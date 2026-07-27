//! Serving the ssh-agent protocol over a forwarded channel.
//!
//! Agent forwarding lets a program on the remote host ask *your* machine to
//! sign something — which is the only way `git` on a server, or `ssh` from it,
//! can use your key. It is also the reason the feature is off by default: while
//! the session lives, anything able to reach that socket on the remote host can
//! ask for a signature, and that includes every process running as you there,
//! not only root.
//!
//! So this implementation is deliberately narrower than a general agent:
//!
//! * **One key.** Only the key this connection authenticated with is offered.
//!   OpenSSH forwards the whole agent; doing that would hand the remote host
//!   every public key you hold — a map of everywhere you log in — and let it
//!   request a signature with any of them.
//! * **Every signature is confirmed.** A request that is not approved is
//!   refused. Silent use is the actual risk; a prompt is what turns it into
//!   something you can see.
//! * **Read-only.** Adding, removing, locking and unlocking keys are refused
//!   outright. Those requests arrive from the remote machine, and a forwarded
//!   agent has no business honouring them.

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::client::KeySource;

/// Agent protocol message numbers (PROTOCOL.agent).
mod msg {
    pub const FAILURE: u8 = 5;
    pub const REQUEST_IDENTITIES: u8 = 11;
    pub const IDENTITIES_ANSWER: u8 = 12;
    pub const SIGN_REQUEST: u8 = 13;
    pub const SIGN_RESPONSE: u8 = 14;
}

/// A frame longer than this is refused rather than allocated. The remote side
/// declares the length, so without a ceiling it decides how much memory we
/// commit. OpenSSH's own agent uses the same limit.
const MAX_FRAME: usize = 256 * 1024;

/// Asked before every signature the remote host requests.
///
/// Returning `false` refuses it. This is the control that makes forwarding
/// defensible: without it, a compromised build script on the far end signs as
/// you and nothing anywhere shows it happened.
pub trait AgentApproval: Send + Sync {
    /// `host` is where the request came from; `blob` is the data to be signed,
    /// so an implementation may inspect it (an SSH authentication request names
    /// the host it logs into).
    fn approve(&self, host: &str, blob: &[u8]) -> bool;
}

/// The single identity a forwarded agent will offer, and the policy around it.
pub struct ForwardedAgent {
    /// Where signatures come from. The private key never crosses this.
    pub keys: std::sync::Arc<dyn KeySource>,
    /// The one key id in scope — the key this connection authenticated with.
    pub key_id: Vec<u8>,
    /// Its public half, in OpenSSH text form.
    pub public_openssh: String,
    /// Host label, for the confirmation prompt.
    pub host: String,
    /// Who approves each signature.
    pub approval: std::sync::Arc<dyn AgentApproval>,
}

impl ForwardedAgent {
    /// The wire encoding of the public key: the base64 field of the OpenSSH
    /// line. This is what the protocol calls a "key blob", and what a client
    /// compares against when it asks us to sign.
    fn key_blob(&self) -> Option<Vec<u8>> {
        // Through the real parser rather than a base64 decode of the middle
        // field: it validates the key at the same time, and the wire encoding is
        // exactly what a client compares against.
        russh::keys::PublicKey::from_openssh(self.public_openssh.trim())
            .ok()?
            .to_bytes()
            .ok()
    }

    fn comment(&self) -> String {
        self.public_openssh
            .split_whitespace()
            .nth(2)
            .unwrap_or("unissh")
            .to_string()
    }
}

fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s);
}

fn take_string<'a>(input: &mut &'a [u8]) -> Option<&'a [u8]> {
    if input.len() < 4 {
        return None;
    }
    let len = u32::from_be_bytes([input[0], input[1], input[2], input[3]]) as usize;
    if input.len() < 4 + len {
        return None;
    }
    let (s, rest) = input[4..].split_at(len);
    *input = rest;
    Some(s)
}

fn framed(payload: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(&payload);
    out
}

fn failure() -> Vec<u8> {
    framed(vec![msg::FAILURE])
}

/// Answers one agent request. Returns the reply frame.
///
/// Split out from the I/O so it can be tested without a channel: this is where
/// the policy lives, and policy is what has to be right.
pub fn answer(agent: &ForwardedAgent, request: &[u8]) -> Vec<u8> {
    let Some((&kind, mut body)) = request.split_first() else {
        return failure();
    };

    match kind {
        msg::REQUEST_IDENTITIES => {
            let Some(blob) = agent.key_blob() else {
                return failure();
            };
            let comment = agent.comment();
            let mut out = vec![msg::IDENTITIES_ANSWER];
            // Exactly one, always: the key this connection used.
            out.extend_from_slice(&1u32.to_be_bytes());
            put_string(&mut out, &blob);
            put_string(&mut out, comment.as_bytes());
            framed(out)
        }
        msg::SIGN_REQUEST => {
            let (Some(want_blob), Some(data)) = (take_string(&mut body), take_string(&mut body))
            else {
                return failure();
            };
            // Flags follow; we do not honour RSA hash selection (see the note on
            // `sign` below), so they are read only to keep the parse honest.
            let Some(blob) = agent.key_blob() else {
                return failure();
            };
            if want_blob != blob {
                // A key we do not offer. Refused rather than substituted.
                log::warn!("forwarded agent: signature requested for a key we do not offer");
                return failure();
            }
            if !agent.approval.approve(&agent.host, data) {
                log::info!("forwarded agent: signature declined by the user");
                return failure();
            }
            match agent.keys.sign(&agent.key_id, data) {
                Ok((algorithm, signature)) => {
                    let mut inner = Vec::new();
                    put_string(&mut inner, algorithm.as_bytes());
                    put_string(&mut inner, &signature);
                    let mut out = vec![msg::SIGN_RESPONSE];
                    put_string(&mut out, &inner);
                    framed(out)
                }
                Err(e) => {
                    log::warn!("forwarded agent: signing failed: {e}");
                    failure()
                }
            }
        }
        // Everything else — add, remove, lock, unlock, extensions. These arrive
        // from the remote machine, and a forwarded agent honouring them would
        // let the far end reshape what your local agent holds.
        other => {
            log::warn!("forwarded agent: refusing request type {other}");
            failure()
        }
    }
}

/// Serves the protocol on one forwarded channel until it closes.
pub async fn serve<S>(agent: std::sync::Arc<ForwardedAgent>, mut stream: S)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut header = [0u8; 4];
    loop {
        if stream.read_exact(&mut header).await.is_err() {
            return; // the far end closed
        }
        let len = u32::from_be_bytes(header) as usize;
        if len == 0 || len > MAX_FRAME {
            log::warn!("forwarded agent: refusing a {len}-byte frame");
            return;
        }
        let mut body = vec![0u8; len];
        if stream.read_exact(&mut body).await.is_err() {
            return;
        }
        let reply = answer(&agent, &body);
        if stream.write_all(&reply).await.is_err() {
            return;
        }
        let _ = stream.flush().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::TransportError;
    use std::sync::Arc;

    struct FixedKey {
        signed: std::sync::Mutex<Vec<Vec<u8>>>,
    }
    impl KeySource for FixedKey {
        fn public_key_openssh(&self, _id: &[u8]) -> Option<String> {
            None
        }
        fn certificate_openssh(&self, _id: &[u8]) -> Option<String> {
            None
        }
        fn sign(&self, _id: &[u8], data: &[u8]) -> Result<(String, Vec<u8>), TransportError> {
            self.signed.lock().unwrap().push(data.to_vec());
            Ok(("ssh-ed25519".to_string(), vec![0xAA; 64]))
        }
    }

    struct Approval(bool);
    impl AgentApproval for Approval {
        fn approve(&self, _host: &str, _blob: &[u8]) -> bool {
            self.0
        }
    }

    fn agent(approve: bool) -> (Arc<ForwardedAgent>, Arc<FixedKey>) {
        let keys = Arc::new(FixedKey {
            signed: std::sync::Mutex::new(Vec::new()),
        });
        // A real ed25519 line; only its base64 field matters here.
        // A real, parseable ed25519 line — the blob is taken through the same
        // parser the production path uses.
        let public = test_public_key();
        (
            Arc::new(ForwardedAgent {
                keys: keys.clone(),
                key_id: b"k".to_vec(),
                public_openssh: public,
                host: "bastion".to_string(),
                approval: Arc::new(Approval(approve)),
            }),
            keys,
        )
    }

    /// Generates a genuine ed25519 public key line, so `key_blob` exercises the
    /// real parser rather than a hand-written constant that may not decode.
    fn test_public_key() -> String {
        // Through the agent crate's own generator, so the line is exactly the
        // shape production produces.
        let (_private, public) = unissh_ssh_agent::generate_ed25519_openssh().expect("keygen");
        format!("{public} test@host")
    }

    fn sign_request(blob: &[u8], data: &[u8]) -> Vec<u8> {
        let mut req = vec![msg::SIGN_REQUEST];
        put_string(&mut req, blob);
        put_string(&mut req, data);
        req.extend_from_slice(&0u32.to_be_bytes()); // flags
        req
    }

    #[test]
    fn offers_exactly_one_identity() {
        let (a, _) = agent(true);
        let reply = answer(&a, &[msg::REQUEST_IDENTITIES]);
        // frame: len | type | count
        assert_eq!(reply[4], msg::IDENTITIES_ANSWER);
        let count = u32::from_be_bytes([reply[5], reply[6], reply[7], reply[8]]);
        assert_eq!(
            count, 1,
            "a forwarded agent must offer only the key this connection used"
        );
    }

    #[test]
    fn a_declined_signature_is_refused() {
        let (a, keys) = agent(false);
        let blob = a.key_blob().unwrap();
        let reply = answer(&a, &sign_request(&blob, b"to-sign"));
        assert_eq!(reply[4], msg::FAILURE);
        assert!(
            keys.signed.lock().unwrap().is_empty(),
            "declining must happen before signing, not after"
        );
    }

    #[test]
    fn an_approved_signature_is_produced() {
        let (a, keys) = agent(true);
        let blob = a.key_blob().unwrap();
        let reply = answer(&a, &sign_request(&blob, b"to-sign"));
        assert_eq!(reply[4], msg::SIGN_RESPONSE);
        assert_eq!(keys.signed.lock().unwrap().len(), 1);
        assert_eq!(keys.signed.lock().unwrap()[0], b"to-sign");
    }

    #[test]
    fn a_key_we_do_not_offer_is_refused() {
        let (a, keys) = agent(true);
        let reply = answer(&a, &sign_request(b"some other key blob", b"to-sign"));
        assert_eq!(reply[4], msg::FAILURE);
        assert!(
            keys.signed.lock().unwrap().is_empty(),
            "the key check must come before signing"
        );
    }

    /// Add, remove, lock and unlock arrive from the remote machine. Honouring
    /// them would let the far end reshape what the local agent holds.
    #[test]
    fn mutating_requests_are_refused() {
        let (a, _) = agent(true);
        for kind in [17u8, 18, 19, 20, 21, 22, 25, 26, 27] {
            let reply = answer(&a, &[kind]);
            assert_eq!(
                reply[4],
                msg::FAILURE,
                "request type {kind} must be refused outright"
            );
        }
    }

    #[test]
    fn a_truncated_request_does_not_panic() {
        let (a, _) = agent(true);
        for bad in [
            vec![],
            vec![msg::SIGN_REQUEST],
            vec![msg::SIGN_REQUEST, 0, 0],
        ] {
            let reply = answer(&a, &bad);
            assert_eq!(reply[4], msg::FAILURE);
        }
    }
}
