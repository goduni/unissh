//! Syslog sink: one RFC 5424 message per audit entry, over UDP or TCP.
//!
//! ```text
//! <PRI>1 <recorded_at, RFC 3339 UTC> <host> <app-name> - <event|->
//!     [unissh@32473 seq="…" event="…" space_id="…" vault_id="…"] <entry>
//! ```
//!
//! - PRI = facility · 8 + severity 5 (notice), for every entry.
//! - HOSTNAME is the host of `server.public_url`, or `-` when it is unset.
//! - MSGID is the event kind of a server-observed entry when it fits RFC 5424
//!   (1-32 printable ASCII), otherwise `-`.
//! - The SD-ID is `unissh@32473`. UniSSH has no IANA Private Enterprise Number;
//!   32473 is the PEN that RFC 5612 reserves for documentation and examples.
//!   `space_id`/`vault_id` are base64, empty when the entry has none; `event`
//!   is empty for a client-signed entry (its contents are opaque to the server).
//! - The body is the entry as in the JSON Lines export: compact JSON for a
//!   server-observed entry, the bare base64 of the blob for a client-signed one.
//!
//! Transport contract:
//! - **UDP** sends each message as one datagram and acknowledges the batch once
//!   every send returned. Nothing confirms receipt, so a datagram lost on the
//!   way is lost for good; a local send error (including an ICMP "port
//!   unreachable" reported on the connected socket) fails the batch.
//! - **TCP** frames each message with octet counting (RFC 6587 `<len> <msg>`) on
//!   one persistent connection, re-established after any error. The batch is
//!   acknowledged only after every frame is written and flushed.

use super::{Batch, Sink, SinkError};
use crate::config::SyslogConfig;
use crate::ids;
use crate::modules::audit::entry_value;
use crate::store::models::AuditExportRow;
use futures_util::future::BoxFuture;
use std::fmt::Write as _;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;

/// The structured-data element carried by every message.
pub const SD_ID: &str = "unissh@32473";
/// RFC 5424 severity 5 (notice): normal but significant.
const SEVERITY_NOTICE: u8 = 5;
/// Entries per batch read from the log.
pub const BATCH_SIZE: u32 = 100;
/// Bound on a connect or on writing one batch.
const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// The per-server parts of the header.
#[derive(Debug, Clone)]
pub struct Header {
    /// 0..=23.
    pub facility: u8,
    pub hostname: String,
    pub app_name: String,
}

/// One RFC 5424 message (no framing) for `row`.
pub fn format_message(h: &Header, row: &AuditExportRow) -> String {
    let entry = entry_value(row);
    let event = match (&entry, row.source.as_str()) {
        (serde_json::Value::Object(o), "server-observed") => {
            o.get("event").and_then(|e| e.as_str()).unwrap_or("")
        }
        _ => "",
    };
    let msgid = if (1..=32).contains(&event.len()) && event.bytes().all(|b| (33..=126).contains(&b))
    {
        event
    } else {
        "-"
    };
    let b64 = |v: &Option<Vec<u8>>| v.as_deref().map(ids::b64).unwrap_or_default();
    let mut m = format!(
        "<{}>1 {} {} {} - {} [{SD_ID}",
        u16::from(h.facility) * 8 + u16::from(SEVERITY_NOTICE),
        rfc3339(row.recorded_at),
        h.hostname,
        h.app_name,
        msgid,
    );
    for (name, value) in [
        ("seq", row.seq.to_string()),
        ("event", event.to_string()),
        ("space_id", b64(&row.space_id)),
        ("vault_id", b64(&row.vault_id)),
    ] {
        let _ = write!(m, " {name}=\"{}\"", sd_escape(&value));
    }
    m.push_str("] ");
    match entry {
        serde_json::Value::String(s) => m.push_str(&s),
        other => m.push_str(&other.to_string()),
    }
    m
}

/// RFC 5424 §6.3.3: `"`, `\` and `]` inside a PARAM-VALUE are backslash-escaped.
fn sd_escape(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for c in v.chars() {
        if matches!(c, '"' | '\\' | ']') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Unix seconds as `YYYY-MM-DDTHH:MM:SSZ`; `-` (NILVALUE) outside years 0..=9999.
fn rfc3339(secs: i64) -> String {
    // Days to civil date (H. Hinnant's algorithm), proleptic Gregorian.
    let (days, sod) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    if !(0..=9999).contains(&y) {
        return "-".into();
    }
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        sod / 3600,
        sod % 3600 / 60,
        sod % 60
    )
}

enum Transport {
    Udp(Mutex<Option<UdpSocket>>),
    Tcp(Mutex<Option<TcpStream>>),
}

/// Holds the collector address and at most one open socket.
pub struct SyslogSink {
    address: String,
    header: Header,
    transport: Transport,
}

impl SyslogSink {
    /// `tcp`: octet-counted frames on one persistent connection; anything else
    /// is UDP (`SyslogConfig::validate` admits only `udp`/`tcp`).
    pub fn new(address: String, tcp: bool, header: Header) -> Self {
        let transport = if tcp {
            Transport::Tcp(Mutex::new(None))
        } else {
            Transport::Udp(Mutex::new(None))
        };
        Self {
            address,
            header,
            transport,
        }
    }

    /// `public_url` supplies HOSTNAME (`-` when empty or unparsable).
    pub fn from_config(cfg: &SyslogConfig, public_url: &str) -> Result<Self, String> {
        let facility = cfg
            .facility_code()
            .ok_or_else(|| "audit.syslog.facility is not a syslog facility".to_string())?;
        let hostname = reqwest::Url::parse(public_url)
            .ok()
            .and_then(|u| u.host_str().map(str::to_string))
            .filter(|h| (1..=255).contains(&h.len()) && h.bytes().all(|b| (33..=126).contains(&b)))
            .unwrap_or_else(|| "-".into());
        Ok(Self::new(
            cfg.address.clone(),
            cfg.protocol == "tcp",
            Header {
                facility,
                hostname,
                app_name: cfg.app_name.clone(),
            },
        ))
    }

    /// The collector is `localhost` or a loopback IP (syslog has no TLS here).
    pub fn is_loopback(&self) -> bool {
        self.address.rsplit_once(':').is_some_and(|(h, _)| {
            h.eq_ignore_ascii_case("localhost")
                || h.trim_start_matches('[')
                    .trim_end_matches(']')
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        })
    }

    async fn send_udp(
        &self,
        slot: &Mutex<Option<UdpSocket>>,
        batch: &Batch,
    ) -> Result<(), SinkError> {
        let mut slot = slot.lock().await;
        if slot.is_none() {
            *slot = Some(udp_connect(&self.address).await?);
        }
        let sock = slot.as_ref().expect("set above");
        for row in batch.rows() {
            let msg = format_message(&self.header, row);
            if sock.send(msg.as_bytes()).await.is_err() {
                // A fresh socket next time (the error may be sticky on this one).
                *slot = None;
                return Err(SinkError("udp_send".into()));
            }
        }
        Ok(())
    }

    async fn send_tcp(
        &self,
        slot: &Mutex<Option<TcpStream>>,
        batch: &Batch,
    ) -> Result<(), SinkError> {
        let mut frames = Vec::new();
        for row in batch.rows() {
            let msg = format_message(&self.header, row);
            frames.extend_from_slice(format!("{} ", msg.len()).as_bytes());
            frames.extend_from_slice(msg.as_bytes());
        }
        let mut slot = slot.lock().await;
        if slot.as_ref().is_some_and(|s| !tcp_alive(s)) {
            *slot = None;
        }
        if slot.is_none() {
            let conn = tokio::time::timeout(IO_TIMEOUT, TcpStream::connect(self.address.as_str()))
                .await
                .map_err(|_| SinkError("timeout".into()))?
                .map_err(|_| SinkError("connect".into()))?;
            *slot = Some(conn);
        }
        let stream = slot.as_mut().expect("set above");
        let written = tokio::time::timeout(IO_TIMEOUT, async {
            stream.write_all(&frames).await?;
            stream.flush().await
        })
        .await;
        match written {
            Ok(Ok(())) => Ok(()),
            // A half-written frame would corrupt the stream: always reconnect.
            Ok(Err(_)) => {
                *slot = None;
                Err(SinkError("write".into()))
            }
            Err(_) => {
                *slot = None;
                Err(SinkError("timeout".into()))
            }
        }
    }
}

/// A connected UDP socket of the collector's address family. Connecting lets the
/// kernel report "port unreachable" as a send error.
async fn udp_connect(address: &str) -> Result<UdpSocket, SinkError> {
    let target = tokio::net::lookup_host(address)
        .await
        .ok()
        .and_then(|mut a| a.next())
        .ok_or_else(|| SinkError("resolve".into()))?;
    let local = if target.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let sock = UdpSocket::bind(local)
        .await
        .map_err(|_| SinkError("udp_bind".into()))?;
    sock.connect(target)
        .await
        .map_err(|_| SinkError("connect".into()))?;
    Ok(sock)
}

/// False when the collector closed or reset the connection. A write to such a
/// socket can still "succeed" into the kernel buffer and be lost, so this is
/// checked before each batch. A collector never sends on a syslog stream, so
/// readable data is unexpected but harmless.
fn tcp_alive(s: &TcpStream) -> bool {
    let mut buf = [0u8; 64];
    match s.try_read(&mut buf) {
        Ok(0) => false,
        Ok(_) => true,
        Err(e) => e.kind() == std::io::ErrorKind::WouldBlock,
    }
}

impl Sink for SyslogSink {
    fn name(&self) -> &str {
        "syslog"
    }

    fn deliver<'a>(&'a self, batch: &'a Batch) -> BoxFuture<'a, Result<(), SinkError>> {
        Box::pin(async move {
            match &self.transport {
                Transport::Udp(slot) => self.send_udp(slot, batch).await,
                Transport::Tcp(slot) => self.send_tcp(slot, batch).await,
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_pri_timestamp_escaped_sd_and_body() {
        let h = Header {
            facility: 4, // auth
            hostname: "unissh.example.com".into(),
            app_name: "unissh".into(),
        };
        let blob = br#"{"event":"lo\"g]in\\","n":1}"#.to_vec();
        let row = AuditExportRow {
            seq: 7,
            source: "server-observed".into(),
            entry_blob: blob,
            signature: None,
            author_pubkey: None,
            vault_id: Some(vec![0xfb; 3]),
            space_id: None,
            recorded_at: 1_790_000_000,
            server_seq: None,
            prev_hash: None,
        };
        assert_eq!(
            format_message(&h, &row),
            "<37>1 2026-09-21T14:13:20Z unissh.example.com unissh - lo\"g]in\\ \
             [unissh@32473 seq=\"7\" event=\"lo\\\"g\\]in\\\\\" space_id=\"\" vault_id=\"+/v7\"] \
             {\"event\":\"lo\\\"g]in\\\\\",\"n\":1}"
        );
    }
}
