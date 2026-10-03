//! Webhook sink: `POST` a JSON batch, HMAC-SHA256 signed.
//!
//! Body: `{"instance": <instance id, base64>, "entries": [<ExportLine>...]}` —
//! each entry object is exactly a line of the JSON Lines export, `entry_blob`
//! included. Headers: `X-UniSSH-Signature: sha256=<hex HMAC-SHA256 of the body
//! bytes as sent>` and `X-UniSSH-Delivery: <first seq>-<last seq>`. A 2xx
//! acknowledges; any other status, a redirect, or a timeout fails the batch.

use super::{Batch, Sink, SinkError};
use crate::config::WebhookConfig;
use crate::modules::audit::ExportLine;
use futures_util::future::BoxFuture;
use hmac::{Hmac, KeyInit, Mac};
use serde::Serialize;
use sha2::Sha256;
use std::time::Duration;

pub const SIGNATURE_HEADER: &str = "X-UniSSH-Signature";
pub const DELIVERY_HEADER: &str = "X-UniSSH-Delivery";

/// Deliberately no `Debug`: the struct holds the HMAC secret.
pub struct WebhookSink {
    client: reqwest::Client,
    url: reqwest::Url,
    secret: Vec<u8>,
    instance: String,
}

#[derive(Serialize)]
struct Payload<'a> {
    instance: &'a str,
    entries: Vec<ExportLine>,
}

impl WebhookSink {
    /// `instance` is this server's instance id (base64), echoed in every body.
    pub fn new(
        url: &str,
        secret: Vec<u8>,
        timeout: Duration,
        instance: String,
    ) -> Result<Self, String> {
        let url = reqwest::Url::parse(url)
            .map_err(|_| "audit.webhook.url is not a valid URL".to_string())?;
        let client = reqwest::Client::builder()
            .timeout(timeout)
            // A redirect would re-POST the log somewhere the owner did not configure.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| "audit.webhook: cannot build the HTTP client".to_string())?;
        Ok(Self {
            client,
            url,
            secret,
            instance,
        })
    }

    /// `http://` to anything but a loopback host: batches cross the network in
    /// plaintext.
    pub fn is_plaintext_remote(&self) -> bool {
        let loopback = self.url.host_str().is_some_and(|h| {
            h.eq_ignore_ascii_case("localhost")
                || h.trim_start_matches('[')
                    .trim_end_matches(']')
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        });
        self.url.scheme() == "http" && !loopback
    }

    /// Reads the secret named in the config. `Config::load` already resolved it
    /// once to validate; resolving again here keeps the secret out of `Config`.
    pub fn from_config(cfg: &WebhookConfig, instance: String) -> Result<Self, String> {
        let secret = cfg.resolve_secret()?;
        Self::new(
            &cfg.url,
            secret,
            Duration::from_secs(cfg.timeout_secs),
            instance,
        )
    }
}

/// `sha256=<hex HMAC-SHA256(secret, body)>`, the `X-UniSSH-Signature` value.
pub fn signature(secret: &[u8], body: &[u8]) -> String {
    let mut mac = <Hmac<Sha256>>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(body);
    format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
}

fn classify(e: &reqwest::Error) -> SinkError {
    // reqwest's Display includes the URL, which may carry a token: codes only.
    let code = if e.is_timeout() {
        "timeout"
    } else if e.is_connect() {
        "connect"
    } else {
        "request"
    };
    SinkError(code.into())
}

impl Sink for WebhookSink {
    fn name(&self) -> &str {
        "webhook"
    }

    fn deliver<'a>(&'a self, batch: &'a Batch) -> BoxFuture<'a, Result<(), SinkError>> {
        Box::pin(async move {
            let payload = Payload {
                instance: &self.instance,
                entries: batch.rows().iter().map(ExportLine::from).collect(),
            };
            let body = serde_json::to_vec(&payload).map_err(|_| SinkError("serialise".into()))?;
            // Signed over the exact bytes that go on the wire.
            let sig = signature(&self.secret, &body);
            let resp = self
                .client
                .post(self.url.clone())
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .header(SIGNATURE_HEADER, sig)
                .header(
                    DELIVERY_HEADER,
                    format!("{}-{}", batch.first_seq(), batch.last_seq()),
                )
                .body(body)
                .send()
                .await
                .map_err(|e| classify(&e))?;
            let status = resp.status();
            if status.is_success() {
                Ok(())
            } else {
                Err(SinkError(format!("http_{}", status.as_u16())))
            }
        })
    }
}
