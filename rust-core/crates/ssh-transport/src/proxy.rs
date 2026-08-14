//! Outbound proxy support: reach the first TCP hop of a connection through an
//! HTTP CONNECT, SOCKS4/4a or SOCKS5 proxy.
//!
//! Only the *first* hop of a connection can be proxied: every later hop of a
//! ProxyJump chain arrives through a `direct-tcpip` channel inside the previous
//! SSH session, where no TCP dial exists to wrap. [`dial`] produces a plain
//! [`TcpStream`] whose far end is the SSH server, ready for
//! `russh::client::connect_stream`.
//!
//! The handshakes are hand-rolled (as the dynamic-forward SOCKS5 server side
//! already is) rather than pulled in as a dependency: each is a few dozen bytes
//! of fixed protocol, and keeping them here keeps the byte-level behaviour
//! auditable next to the SSH transport it feeds.

use std::net::{Ipv4Addr, Ipv6Addr};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use zeroize::Zeroizing;

use crate::error::TransportError;

/// A hard deadline on the proxy phase (TCP dial + proxy handshake). Separate
/// from the SSH `HANDSHAKE_TIMEOUT`, which starts only once the proxy has
/// produced a stream — otherwise a slow proxy would eat the SSH budget.
const PROXY_TIMEOUT: Duration = Duration::from_secs(30);

/// Longest HTTP CONNECT response (status line + headers) we are willing to
/// read before deciding the peer is not an HTTP proxy.
const HTTP_REPLY_LIMIT: usize = 8 * 1024;

/// The proxy protocol to speak.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProxyKind {
    /// HTTP CONNECT (optionally with Basic authentication).
    Http,
    /// SOCKS4; SOCKS4a when the destination is a hostname. The username, if
    /// any, is sent as the SOCKS4 `USERID`; there is no password in SOCKS4.
    Socks4,
    /// SOCKS5 (RFC 1928), anonymous or with username/password (RFC 1929).
    Socks5,
}

/// How to reach the first TCP hop through a proxy.
#[derive(Clone)]
pub struct ProxyOptions {
    /// Protocol.
    pub kind: ProxyKind,
    /// Proxy host (name or IP).
    pub host: String,
    /// Proxy port.
    pub port: u16,
    /// Username, when the proxy wants one (SOCKS4 `USERID` / SOCKS5 RFC 1929 /
    /// HTTP Basic).
    pub username: Option<String>,
    /// Password (zeroized on drop). Ignored by SOCKS4, which has no password.
    pub password: Option<Zeroizing<String>>,
}

impl core::fmt::Debug for ProxyOptions {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ProxyOptions")
            .field("kind", &self.kind)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            // Do not print the password.
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// Connects to the proxy and asks it for a tunnel to `dest_host:dest_port`.
/// The returned stream carries the destination's bytes (for us: the SSH
/// banner) from the first read.
pub async fn dial(
    proxy: &ProxyOptions,
    dest_host: &str,
    dest_port: u16,
) -> Result<TcpStream, TransportError> {
    timeout(PROXY_TIMEOUT, dial_inner(proxy, dest_host, dest_port))
        .await
        .map_err(|_| proxy_err("proxy handshake timed out"))?
}

async fn dial_inner(
    proxy: &ProxyOptions,
    dest_host: &str,
    dest_port: u16,
) -> Result<TcpStream, TransportError> {
    log::info!(
        "proxy dial {:?} {}:{} for {}:{}",
        proxy.kind,
        proxy.host,
        proxy.port,
        dest_host,
        dest_port
    );
    // Every failure from here on names the proxy. Without this the io error of
    // an unreachable proxy is indistinguishable from one on the destination
    // host, and whoever reads it goes to debug the wrong machine's sshd —
    // which is the entire reason `TransportError::Proxy` exists.
    let mut stream = TcpStream::connect((proxy.host.as_str(), proxy.port))
        .await
        .map_err(|e| {
            proxy_err(format!(
                "cannot reach proxy {}:{}: {e}",
                proxy.host, proxy.port
            ))
        })?;
    // russh sets nodelay itself when it owns the dial; for a handed-in stream
    // (connect_stream) nobody else will.
    stream.set_nodelay(true)?;
    let handshake = match proxy.kind {
        ProxyKind::Http => http_handshake(&mut stream, proxy, dest_host, dest_port).await,
        ProxyKind::Socks4 => socks4_handshake(&mut stream, proxy, dest_host, dest_port).await,
        ProxyKind::Socks5 => socks5_handshake(&mut stream, proxy, dest_host, dest_port).await,
    };
    // A bare `?` inside a handshake yields an io error that reads like the
    // destination's; relabel it here so every proxy-phase failure says so.
    handshake.map_err(|e| match e {
        TransportError::Io(io) => proxy_err(format!(
            "proxy {}:{} broke off the handshake: {io}",
            proxy.host, proxy.port
        )),
        other => other,
    })?;
    Ok(stream)
}

fn proxy_err(msg: impl Into<String>) -> TransportError {
    TransportError::Proxy(msg.into())
}

// ---------------------------------------------------------------- HTTP CONNECT

async fn http_handshake<S>(
    stream: &mut S,
    proxy: &ProxyOptions,
    dest_host: &str,
    dest_port: u16,
) -> Result<(), TransportError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Either credential alone still means "authenticate": a password-only
    // proxy account is unusual but legal in Basic (empty user-id), and
    // silently dropping the password would read as a proxy rejecting good
    // credentials.
    let auth = (proxy.username.is_some() || proxy.password.is_some()).then(|| {
        (
            proxy.username.as_deref().unwrap_or(""),
            proxy.password.as_deref().map_or("", |p| p.as_str()),
        )
    });
    let request = http_connect_request(dest_host, dest_port, auth);
    stream.write_all(request.as_bytes()).await?;

    // Read status line + headers up to the blank line, and not a byte further:
    // whatever follows belongs to the tunneled SSH connection.
    let mut reply = Vec::new();
    while !reply.ends_with(b"\r\n\r\n") {
        if reply.len() >= HTTP_REPLY_LIMIT {
            return Err(proxy_err("http proxy: oversized response"));
        }
        let byte = stream.read_u8().await.map_err(|_| {
            proxy_err("http proxy: connection closed before a full CONNECT response")
        })?;
        reply.push(byte);
    }
    let status_line = reply
        .split(|&b| b == b'\r')
        .next()
        .map(String::from_utf8_lossy)
        .unwrap_or_default()
        .into_owned();
    match http_status_code(&status_line) {
        Some(200) => Ok(()),
        Some(407) => Err(proxy_err(format!(
            "http proxy requires authentication: {status_line}"
        ))),
        _ => Err(proxy_err(format!(
            "http proxy refused CONNECT: {status_line}"
        ))),
    }
}

/// Builds the CONNECT request. An IPv6 literal destination is bracketed, as the
/// authority form requires.
fn http_connect_request(dest_host: &str, dest_port: u16, auth: Option<(&str, &str)>) -> String {
    let authority = if dest_host.parse::<Ipv6Addr>().is_ok() {
        format!("[{dest_host}]:{dest_port}")
    } else {
        format!("{dest_host}:{dest_port}")
    };
    let mut req = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if let Some((user, pass)) = auth {
        let creds = base64_encode(format!("{user}:{pass}").as_bytes());
        req.push_str(&format!("Proxy-Authorization: Basic {creds}\r\n"));
    }
    req.push_str("\r\n");
    req
}

/// Extracts the status code from an HTTP status line (`HTTP/1.1 200 ...`).
fn http_status_code(status_line: &str) -> Option<u16> {
    let mut parts = status_line.split_ascii_whitespace();
    let version = parts.next()?;
    if !version.starts_with("HTTP/") {
        return None;
    }
    parts.next()?.parse().ok()
}

/// Standard base64 (with padding). Hand-rolled for the one Basic-auth header
/// rather than pulling a crate into the transport for it.
fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = u32::from_be_bytes([0, b[0], b[1], b[2]]);
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

// --------------------------------------------------------------------- SOCKS4

async fn socks4_handshake<S>(
    stream: &mut S,
    proxy: &ProxyOptions,
    dest_host: &str,
    dest_port: u16,
) -> Result<(), TransportError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = socks4_request(
        dest_host,
        dest_port,
        proxy.username.as_deref().unwrap_or(""),
    )?;
    stream.write_all(&request).await?;

    // Reply: VN(0) CD DSTPORT(2) DSTIP(4).
    let mut reply = [0u8; 8];
    stream
        .read_exact(&mut reply)
        .await
        .map_err(|_| proxy_err("socks4 proxy: connection closed during handshake"))?;
    match reply[1] {
        90 => Ok(()),
        91 => Err(proxy_err("socks4 proxy rejected the request")),
        92 | 93 => Err(proxy_err(
            "socks4 proxy rejected the request (identd check failed)",
        )),
        code => Err(proxy_err(format!("socks4 proxy: unexpected reply {code}"))),
    }
}

/// Builds a SOCKS4 CONNECT request; a hostname destination uses the SOCKS4a
/// form (IP 0.0.0.1 + hostname after the userid). SOCKS4 cannot carry an IPv6
/// destination at all.
fn socks4_request(
    dest_host: &str,
    dest_port: u16,
    userid: &str,
) -> Result<Vec<u8>, TransportError> {
    if dest_host.parse::<Ipv6Addr>().is_ok() {
        return Err(proxy_err(
            "socks4 cannot reach an IPv6 destination; use socks5",
        ));
    }
    let mut req = vec![4u8, 1u8];
    req.extend_from_slice(&dest_port.to_be_bytes());
    let hostname = match dest_host.parse::<Ipv4Addr>() {
        Ok(ip) => {
            req.extend_from_slice(&ip.octets());
            None
        }
        Err(_) => {
            // SOCKS4a: an invalid IP 0.0.0.x tells the proxy to resolve the
            // hostname that follows the userid.
            req.extend_from_slice(&[0, 0, 0, 1]);
            Some(dest_host)
        }
    };
    req.extend_from_slice(userid.as_bytes());
    req.push(0);
    if let Some(name) = hostname {
        req.extend_from_slice(name.as_bytes());
        req.push(0);
    }
    Ok(req)
}

// --------------------------------------------------------------------- SOCKS5

async fn socks5_handshake<S>(
    stream: &mut S,
    proxy: &ProxyOptions,
    dest_host: &str,
    dest_port: u16,
) -> Result<(), TransportError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Greeting: offer username/password only when we actually hold credentials,
    // so an anonymous proxy never sees the method and a credentialed one can
    // pick it. Either credential alone counts — RFC 1929 permits a zero-length
    // field, and dropping a configured password because the username box was
    // left empty would read as the proxy rejecting good credentials.
    let have_creds = proxy.username.is_some() || proxy.password.is_some();
    let greeting: &[u8] = if have_creds {
        &[5, 2, 0x00, 0x02]
    } else {
        &[5, 1, 0x00]
    };
    stream.write_all(greeting).await?;

    let mut choice = [0u8; 2];
    stream
        .read_exact(&mut choice)
        .await
        .map_err(|_| proxy_err("socks5 proxy: connection closed during handshake"))?;
    if choice[0] != 5 {
        return Err(proxy_err("socks5 proxy: not a SOCKS5 server"));
    }
    match choice[1] {
        0x00 => {}
        0x02 if have_creds => {
            let user = proxy.username.as_deref().unwrap_or("");
            let pass = proxy.password.as_deref().map_or("", |p| p.as_str());
            let auth = socks5_auth_request(user, pass)?;
            stream.write_all(&auth).await?;
            let mut status = [0u8; 2];
            stream
                .read_exact(&mut status)
                .await
                .map_err(|_| proxy_err("socks5 proxy: connection closed during auth"))?;
            if status[1] != 0 {
                return Err(proxy_err("socks5 proxy rejected the credentials"));
            }
        }
        0xff => {
            return Err(proxy_err(if have_creds {
                "socks5 proxy accepted none of the offered auth methods"
            } else {
                "socks5 proxy requires authentication"
            }))
        }
        m => return Err(proxy_err(format!("socks5 proxy chose unknown method {m}"))),
    }

    stream
        .write_all(&socks5_connect_request(dest_host, dest_port)?)
        .await?;

    // Reply: VER REP RSV ATYP BND.ADDR BND.PORT — the bound address is
    // variable-length and must be consumed so the SSH banner starts the stream.
    let mut head = [0u8; 4];
    stream
        .read_exact(&mut head)
        .await
        .map_err(|_| proxy_err("socks5 proxy: connection closed during connect"))?;
    if head[0] != 5 {
        return Err(proxy_err("socks5 proxy: bad reply version"));
    }
    // REP first, BND after. A refusal is the reply we most need to report
    // faithfully, and some proxies answer one with a truncated or ATYP=0 body
    // — parsing that body first turns "connection refused" into a bogus
    // address-type complaint, or into an io error when the peer hangs up.
    // Nothing is read past a refusal because the stream is dropped anyway.
    if head[1] != 0x00 {
        return Err(proxy_err(format!(
            "socks5 proxy refused the connection: {}",
            socks5_reply_text(head[1])
        )));
    }
    // Success: consume the bound address so the SSH banner starts the stream.
    let addr_len = match head[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            len[0] as usize
        }
        a => return Err(proxy_err(format!("socks5 proxy: bad address type {a}"))),
    };
    let mut rest = vec![0u8; addr_len + 2];
    stream.read_exact(&mut rest).await?;
    Ok(())
}

/// Builds the RFC 1929 username/password auth request. Both fields ride a
/// one-byte length.
fn socks5_auth_request(user: &str, pass: &str) -> Result<Vec<u8>, TransportError> {
    if user.len() > 255 || pass.len() > 255 {
        return Err(proxy_err("socks5 username/password longer than 255 bytes"));
    }
    let mut req = vec![1u8, user.len() as u8];
    req.extend_from_slice(user.as_bytes());
    req.push(pass.len() as u8);
    req.extend_from_slice(pass.as_bytes());
    Ok(req)
}

/// Builds the SOCKS5 CONNECT request; a hostname destination is sent as-is
/// (ATYP 3) for the proxy to resolve.
fn socks5_connect_request(dest_host: &str, dest_port: u16) -> Result<Vec<u8>, TransportError> {
    let mut req = vec![5u8, 1u8, 0u8];
    if let Ok(ip) = dest_host.parse::<Ipv4Addr>() {
        req.push(0x01);
        req.extend_from_slice(&ip.octets());
    } else if let Ok(ip) = dest_host.parse::<Ipv6Addr>() {
        req.push(0x04);
        req.extend_from_slice(&ip.octets());
    } else {
        if dest_host.len() > 255 {
            return Err(proxy_err(
                "socks5 destination hostname longer than 255 bytes",
            ));
        }
        req.push(0x03);
        req.push(dest_host.len() as u8);
        req.extend_from_slice(dest_host.as_bytes());
    }
    req.extend_from_slice(&dest_port.to_be_bytes());
    Ok(req)
}

fn socks5_reply_text(code: u8) -> &'static str {
    match code {
        0x01 => "general failure",
        0x02 => "connection not allowed by ruleset",
        0x03 => "network unreachable",
        0x04 => "host unreachable",
        0x05 => "connection refused",
        0x06 => "TTL expired",
        0x07 => "command not supported",
        0x08 => "address type not supported",
        _ => "unknown error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_vectors() {
        // RFC 4648 test vectors.
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
        // The classic Basic-auth example.
        assert_eq!(
            base64_encode(b"Aladdin:open sesame"),
            "QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
        );
    }

    #[test]
    fn http_request_shapes() {
        let plain = http_connect_request("example.com", 22, None);
        assert_eq!(
            plain,
            "CONNECT example.com:22 HTTP/1.1\r\nHost: example.com:22\r\n\r\n"
        );
        let auth = http_connect_request("10.0.0.1", 2222, Some(("user", "pw")));
        assert!(auth.starts_with("CONNECT 10.0.0.1:2222 HTTP/1.1\r\n"));
        assert!(auth.contains("Proxy-Authorization: Basic dXNlcjpwdw==\r\n"));
        assert!(auth.ends_with("\r\n\r\n"));
        // IPv6 literals are bracketed.
        let v6 = http_connect_request("::1", 22, None);
        assert!(v6.starts_with("CONNECT [::1]:22 HTTP/1.1\r\n"));
    }

    #[test]
    fn http_status_parsing() {
        assert_eq!(
            http_status_code("HTTP/1.1 200 Connection established"),
            Some(200)
        );
        assert_eq!(
            http_status_code("HTTP/1.0 407 Proxy Auth Required"),
            Some(407)
        );
        assert_eq!(http_status_code("SSH-2.0-OpenSSH_9.6"), None);
        assert_eq!(http_status_code(""), None);
    }

    #[test]
    fn socks4_request_shapes() {
        // IPv4 destination: direct form, userid nul-terminated.
        let ip = socks4_request("192.0.2.7", 22, "joe").unwrap();
        assert_eq!(ip, [&[4, 1, 0, 22, 192, 0, 2, 7][..], b"joe\0"].concat());
        // Hostname: SOCKS4a marker IP 0.0.0.1 + trailing hostname.
        let name = socks4_request("example.com", 22, "").unwrap();
        assert_eq!(
            name,
            [&[4, 1, 0, 22, 0, 0, 0, 1, 0][..], b"example.com\0"].concat()
        );
        // IPv6 cannot be expressed in SOCKS4.
        assert!(socks4_request("::1", 22, "").is_err());
    }

    #[test]
    fn socks5_request_shapes() {
        assert_eq!(
            socks5_connect_request("192.0.2.7", 22).unwrap(),
            [5, 1, 0, 1, 192, 0, 2, 7, 0, 22]
        );
        assert_eq!(
            socks5_connect_request("example.com", 2222).unwrap(),
            [
                &[5, 1, 0, 3, 11][..],
                b"example.com",
                &(2222u16).to_be_bytes()
            ]
            .concat()
        );
        let v6 = socks5_connect_request("::1", 22).unwrap();
        assert_eq!(v6[3], 0x04);
        assert_eq!(v6.len(), 4 + 16 + 2);
        assert!(socks5_connect_request(&"x".repeat(256), 22).is_err());

        assert_eq!(
            socks5_auth_request("u", "pw").unwrap(),
            [&[1, 1][..], b"u", &[2][..], b"pw"].concat()
        );
        assert!(socks5_auth_request(&"x".repeat(256), "").is_err());
    }
}
