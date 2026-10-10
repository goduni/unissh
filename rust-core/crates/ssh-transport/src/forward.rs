//! Serving the ssh-agent protocol: over a forwarded channel, and to local
//! programs through the system agent's socket.
//!
//! One protocol implementation, two policies. [`answer`] speaks the wire format
//! and the refusal rules; an [`AgentKeys`] decides what is offered and whether a
//! signature is produced.
//!
//! Agent forwarding (opt-in per connection) lets a program on the remote host
//! ask *your* machine to sign something — which is the only way `git` on a
//! server, or `ssh` from it, can use your key. It is also the reason the feature
//! is off by default: while the session lives, anything able to reach that
//! socket on the remote host can ask for a signature, and that includes every
//! process running as you there, not only root.
//!
//! So [`ForwardedAgent`] is deliberately narrower than a general agent:
//!
//! * **One key.** Only the key this connection authenticated with is offered.
//!   OpenSSH forwards the whole agent; doing that would hand the remote host
//!   every public key you hold — a map of everywhere you log in — and let it
//!   request a signature with any of them.
//! * **Every signature is confirmed.** A request that is not approved is
//!   refused. Silent use is the actual risk; a prompt is what turns it into
//!   something you can see.
//!
//! The system agent ([`LocalAgent`]) offers a list of keys to programs on this
//! machine, and confirms every signature the same way, naming the key and the
//! process that asked.
//!
//! For every agent, whatever its policy:
//!
//! * **Read-only.** Adding, removing, locking and unlocking keys are refused
//!   outright. The vault governs what an agent holds, not whoever can reach its
//!   socket.
//! * **A signature only for an offered key.** A request naming any other key is
//!   refused rather than substituted.
//! * **Certificates sign with their key.** A certificate is offered as an
//!   identity of its own, after its key; a request naming the certificate is
//!   signed (and approved) as a request for that key, since the certificate is
//!   only the public half a server checks against its CA. Its validity
//!   (expiry, principals) is not checked here; that is the server's call, as
//!   with OpenSSH's agent.
//! * **RSA hashes as asked.** `SSH_AGENT_RSA_SHA2_256` gives `rsa-sha2-256`,
//!   `SSH_AGENT_RSA_SHA2_512` gives `rsa-sha2-512` (the 256 flag wins if both
//!   are set, as in OpenSSH). An RSA request with neither asks for a SHA-1
//!   `ssh-rsa` signature, which the core never makes: it is refused before
//!   anyone is asked to approve it.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use unissh_ssh_agent::RsaHash;

use crate::client::KeySource;

/// Agent protocol message numbers (PROTOCOL.agent).
mod msg {
    pub const FAILURE: u8 = 5;
    pub const REQUEST_IDENTITIES: u8 = 11;
    pub const IDENTITIES_ANSWER: u8 = 12;
    pub const SIGN_REQUEST: u8 = 13;
    pub const SIGN_RESPONSE: u8 = 14;
}

/// `SIGN_REQUEST` flags (PROTOCOL.agent).
mod flag {
    pub const RSA_SHA2_256: u32 = 2;
    pub const RSA_SHA2_512: u32 = 4;
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

/// One identity an agent offers.
#[derive(Clone, Debug)]
pub struct OfferedKey {
    /// The key id the signer knows it by. Never leaves the process. A key and
    /// its certificate, offered as two identities, share it: both sign with
    /// the same private key.
    pub key_id: Vec<u8>,
    /// The public half, in OpenSSH text form: a public key line, or an OpenSSH
    /// certificate line for a certificate identity.
    pub public_openssh: String,
    /// What `ssh-add -l` shows next to it.
    pub comment: String,
}

impl OfferedKey {
    /// The wire encoding of the public key: the base64 field of the OpenSSH
    /// line. This is what the protocol calls a "key blob", and what a client
    /// compares against when it asks us to sign.
    fn blob(&self) -> Option<Vec<u8>> {
        key_blob(&self.public_openssh)
    }

    /// Whether this is an RSA key or an RSA certificate, whose signature hash
    /// the request's flags choose.
    fn is_rsa(&self) -> bool {
        matches!(
            self.public_openssh.split_whitespace().next(),
            Some("ssh-rsa" | "ssh-rsa-cert-v01@openssh.com")
        )
    }
}

/// The policy half of an agent: which identities it offers, and whether a
/// signature is produced. The protocol half is [`answer`].
pub trait AgentKeys: Send + Sync {
    /// The identities offered right now. Resolved per request, so a policy that
    /// changes (a key shared or unshared, a vault locked) takes effect on the
    /// next request without restarting anything.
    fn offered(&self) -> Vec<OfferedKey>;
    /// Signs `data` with `key`, one of the keys [`Self::offered`] returned, or
    /// refuses with `None`. Approval, if the policy has any, happens here.
    /// `rsa` is the hash an RSA key signs with; other key types ignore it.
    /// Returns `(algorithm, signature)`.
    fn sign(&self, key: &OfferedKey, data: &[u8], rsa: RsaHash) -> Option<(String, Vec<u8>)>;
    /// The client went away while a request was still being answered. A policy
    /// waiting on a person withdraws its prompt here; the answer, whatever it
    /// becomes, is discarded.
    fn hang_up(&self) {}
}

impl<T: AgentKeys + ?Sized> AgentKeys for std::sync::Arc<T> {
    fn offered(&self) -> Vec<OfferedKey> {
        (**self).offered()
    }
    fn sign(&self, key: &OfferedKey, data: &[u8], rsa: RsaHash) -> Option<(String, Vec<u8>)> {
        (**self).sign(key, data, rsa)
    }
    fn hang_up(&self) {
        (**self).hang_up();
    }
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
    fn comment(&self) -> String {
        self.public_openssh
            .split_whitespace()
            .nth(2)
            .unwrap_or("unissh")
            .to_owned()
    }
}

impl AgentKeys for ForwardedAgent {
    fn offered(&self) -> Vec<OfferedKey> {
        // Exactly one, always: the key this connection used.
        vec![OfferedKey {
            key_id: self.key_id.clone(),
            public_openssh: self.public_openssh.clone(),
            comment: self.comment(),
        }]
    }

    fn sign(&self, key: &OfferedKey, data: &[u8], rsa: RsaHash) -> Option<(String, Vec<u8>)> {
        if !self.approval.approve(&self.host, data) {
            log::info!("forwarded agent: signature declined by the user");
            return None;
        }
        match self.keys.sign(&key.key_id, data, rsa) {
            Ok(signed) => Some(signed),
            Err(e) => {
                log::warn!("forwarded agent: signing failed: {e}");
                None
            }
        }
    }
}

/// The program on this machine that opened the agent connection, as far as the
/// OS can tell. Both fields are best effort: `None` means "unknown process".
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AgentCaller {
    /// Its process id.
    pub pid: Option<u32>,
    /// The path of its executable.
    pub executable: Option<String>,
}

/// Asked before every signature a local program requests through the system
/// agent. Returning `false` refuses it.
pub trait LocalApproval: Send + Sync {
    /// `key` is the identity asked for, `caller` the program asking, `blob` the
    /// data to be signed (an SSH authentication request names the user it logs
    /// in as). Called on a blocking thread; it may wait for a person.
    fn approve(&self, key: &OfferedKey, caller: &AgentCaller, blob: &[u8]) -> bool;
    /// The connection this approval belongs to closed: withdraw a pending
    /// prompt (it must then answer `false`) and refuse any later one.
    fn abandon(&self) {}
}

/// The system agent's policy: the identities `keys` offers, and a signature
/// only after `approval` says yes for this caller. `keys` produces the
/// signature; it is never asked unless the request was approved.
pub struct LocalAgent<K> {
    /// What is offered, and the signer behind it.
    pub keys: K,
    /// Who approves each signature.
    pub approval: std::sync::Arc<dyn LocalApproval>,
    /// The program on the other end of this connection.
    pub caller: AgentCaller,
}

impl<K: AgentKeys> AgentKeys for LocalAgent<K> {
    fn offered(&self) -> Vec<OfferedKey> {
        self.keys.offered()
    }

    fn sign(&self, key: &OfferedKey, data: &[u8], rsa: RsaHash) -> Option<(String, Vec<u8>)> {
        if !self.approval.approve(key, &self.caller, data) {
            log::info!("system agent: signature declined by the user");
            return None;
        }
        self.keys.sign(key, data, rsa)
    }

    fn hang_up(&self) {
        self.approval.abandon();
    }
}

/// The key blob of an OpenSSH public key line, or of an OpenSSH certificate
/// line (whose blob is the whole certificate).
///
/// Through the real parser rather than a base64 decode of the middle field: it
/// validates the key at the same time, and the wire encoding is exactly what a
/// client compares against.
fn key_blob(public_openssh: &str) -> Option<Vec<u8>> {
    let line = public_openssh.trim();
    match russh::keys::PublicKey::from_openssh(line) {
        Ok(key) => key.to_bytes().ok(),
        Err(_) => russh::keys::Certificate::from_openssh(line)
            .ok()?
            .to_bytes()
            .ok(),
    }
}

fn take_u32(input: &mut &[u8]) -> Option<u32> {
    let (head, rest) = input.split_first_chunk::<4>()?;
    *input = rest;
    Some(u32::from_be_bytes(*head))
}

/// Appends an SSH `string`. `None` only for a field longer than `u32::MAX`,
/// which the wire format cannot express.
fn put_string(out: &mut Vec<u8>, s: &[u8]) -> Option<()> {
    out.extend_from_slice(&u32::try_from(s.len()).ok()?.to_be_bytes());
    out.extend_from_slice(s);
    Some(())
}

fn take_string<'a>(input: &mut &'a [u8]) -> Option<&'a [u8]> {
    let (head, body) = input.split_first_chunk::<4>()?;
    let len = usize::try_from(u32::from_be_bytes(*head)).ok()?;
    let (s, rest) = body.split_at_checked(len)?;
    *input = rest;
    Some(s)
}

fn framed(payload: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(payload.len().saturating_add(4));
    put_string(&mut out, payload)?;
    Some(out)
}

fn failure() -> Vec<u8> {
    // `framed(&[msg::FAILURE])`, spelled out so it cannot fail.
    vec![0, 0, 0, 1, msg::FAILURE]
}

/// Answers one agent request. Returns the reply frame.
///
/// Split out from the I/O so it can be tested without a channel: this is where
/// the protocol rules live, and they are what has to be right.
pub fn answer<A: AgentKeys + ?Sized>(agent: &A, request: &[u8]) -> Vec<u8> {
    reply(agent, request).unwrap_or_else(failure)
}

/// The reply frame for one request, or `None` for every refusal and every
/// malformed request — [`answer`] turns all of those into `SSH_AGENT_FAILURE`.
fn reply<A: AgentKeys + ?Sized>(agent: &A, request: &[u8]) -> Option<Vec<u8>> {
    let (&kind, mut body) = request.split_first()?;

    match kind {
        msg::REQUEST_IDENTITIES => {
            // A key that does not parse is left out rather than failing the
            // whole list: one bad entry must not hide the others.
            let identities: Vec<(Vec<u8>, String)> = agent
                .offered()
                .into_iter()
                .filter_map(|key| Some((key.blob()?, key.comment)))
                .collect();
            let mut out = vec![msg::IDENTITIES_ANSWER];
            out.extend_from_slice(&u32::try_from(identities.len()).ok()?.to_be_bytes());
            for (blob, comment) in &identities {
                put_string(&mut out, blob)?;
                put_string(&mut out, comment.as_bytes())?;
            }
            framed(&out)
        }
        msg::SIGN_REQUEST => {
            let (Some(want_blob), Some(data)) = (take_string(&mut body), take_string(&mut body))
            else {
                return None;
            };
            // A client that leaves the flags out asked for none.
            let flags = take_u32(&mut body).unwrap_or(0);
            let Some(key) = agent
                .offered()
                .into_iter()
                .find(|key| key.blob().as_deref() == Some(want_blob))
            else {
                // A key we do not offer. Refused rather than substituted.
                log::warn!("agent: signature requested for a key we do not offer");
                return None;
            };
            let rsa = if flags & flag::RSA_SHA2_256 != 0 {
                RsaHash::Sha256
            } else if flags & flag::RSA_SHA2_512 != 0 {
                RsaHash::Sha512
            } else if key.is_rsa() {
                // A SHA-1 `ssh-rsa` signature. The core never makes one, and
                // answering with another hash would hand the client a signature
                // of a type it did not ask for. Refused before any prompt.
                log::info!("agent: refusing an ssh-rsa (SHA-1) signature request");
                return None;
            } else {
                RsaHash::default() // not an RSA key: no hash to choose
            };
            let (algorithm, signature) = agent.sign(&key, data, rsa)?;
            let mut inner = Vec::new();
            put_string(&mut inner, algorithm.as_bytes())?;
            put_string(&mut inner, &signature)?;
            let mut out = vec![msg::SIGN_RESPONSE];
            put_string(&mut out, &inner)?;
            framed(&out)
        }
        // Everything else — add, remove, lock, unlock, extensions. Whoever can
        // reach the socket does not get to reshape what the agent holds.
        other => {
            log::warn!("agent: refusing request type {other}");
            None
        }
    }
}

/// Serves the protocol on one stream (a forwarded channel, or a local socket
/// connection) until it closes.
///
/// Each request is answered on a blocking thread: the policy may take the
/// core's lock, read the vault, or wait up to a minute for a person to approve
/// a signature, and none of that may stall the runtime's async workers. While
/// it runs the stream is still read, so a client that hangs up is noticed at
/// once ([`AgentKeys::hang_up`]) rather than after the prompt times out. Bytes
/// a client sends ahead are kept for the next request.
pub async fn serve<A, S>(agent: std::sync::Arc<A>, mut stream: S)
where
    A: AgentKeys + ?Sized + 'static,
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut inbox: Vec<u8> = Vec::new();
    loop {
        if fill(&mut stream, &mut inbox, 4).await.is_err() {
            return; // the far end closed
        }
        // `fill` returned Ok, so the 4-byte length prefix is there.
        let Some(&head) = inbox.first_chunk::<4>() else {
            return;
        };
        let len = u32::from_be_bytes(head) as usize;
        if len == 0 || len > MAX_FRAME {
            log::warn!("agent: refusing a {len}-byte frame");
            return;
        }
        #[expect(
            clippy::arithmetic_side_effects,
            reason = "len <= MAX_FRAME (256 KiB) is checked just above, so 4 + len cannot overflow"
        )]
        let frame_len = 4 + len;
        if fill(&mut stream, &mut inbox, frame_len).await.is_err() {
            return;
        }
        let body: Vec<u8> = inbox.drain(..frame_len).skip(4).collect();
        let policy = agent.clone();
        let mut job = tokio::task::spawn_blocking(move || answer(&*policy, &body));
        let reply = loop {
            let mut chunk = [0_u8; 4096];
            tokio::select! {
                done = &mut job => break done,
                read = stream.read(&mut chunk), if inbox.len() <= 4 + MAX_FRAME => match read {
                    Ok(0) | Err(_) => {
                        agent.hang_up();
                        return;
                    }
                    Ok(n) => {
                        // `read` never reports more than the buffer it was given;
                        // if it ever did, hang up rather than drop bytes silently.
                        let Some(got) = chunk.get(..n) else {
                            agent.hang_up();
                            return;
                        };
                        inbox.extend_from_slice(got);
                    }
                },
            }
        };
        let Ok(reply) = reply else {
            return;
        };
        if stream.write_all(&reply).await.is_err() {
            return;
        }
        if stream.flush().await.is_err() {
            // A dead stream ends the loop at the next read.
        }
    }
}

/// Reads from `stream` until `inbox` holds at least `want` bytes.
async fn fill<S: tokio::io::AsyncRead + Unpin>(
    stream: &mut S,
    inbox: &mut Vec<u8>,
    want: usize,
) -> std::io::Result<()> {
    let mut chunk = [0_u8; 4096];
    while inbox.len() < want {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        // `read` never reports more than the buffer it was given; refuse rather
        // than drop bytes silently if it ever did.
        let got = chunk.get(..n).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "read reported more bytes than the buffer holds",
            )
        })?;
        inbox.extend_from_slice(got);
    }
    Ok(())
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
        fn sign(
            &self,
            _id: &[u8],
            data: &[u8],
            _rsa: RsaHash,
        ) -> Result<(String, Vec<u8>), TransportError> {
            self.signed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(data.to_vec());
            Ok(("ssh-ed25519".to_owned(), vec![0xAA; 64]))
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
                host: "bastion".to_owned(),
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
        sign_request_flagged(blob, data, 0)
    }

    fn sign_request_flagged(blob: &[u8], data: &[u8], flags: u32) -> Vec<u8> {
        let mut req = vec![msg::SIGN_REQUEST];
        put_string(&mut req, blob).unwrap();
        put_string(&mut req, data).unwrap();
        req.extend_from_slice(&flags.to_be_bytes());
        req
    }

    #[test]
    fn truncated_sign_request_is_refused() {
        let (a, keys) = agent(true);
        let blob = key_blob(&a.public_openssh).unwrap();
        let full = sign_request(&blob, b"to-sign");
        // Every cut inside the two strings (the flags are optional, so cuts in
        // them still parse) must come back as a plain FAILURE frame.
        let strings_end = 1 + 4 + blob.len() + 4 + b"to-sign".len();
        for cut in 0..strings_end {
            let reply = answer(&a, &full[..cut]);
            assert_eq!(reply, failure(), "cut at {cut}");
        }
        assert!(
            keys.signed.lock().unwrap().is_empty(),
            "a truncated request must never reach the signer"
        );
    }

    #[test]
    fn failure_frame_matches_the_framed_encoding() {
        assert_eq!(Some(failure()), framed(&[msg::FAILURE]));
    }

    /// The `(algorithm, signature)` of a SIGN_RESPONSE frame, checked against
    /// `public` (an OpenSSH public key line) the way a server would.
    fn verified(reply: &[u8], public: &str, data: &[u8]) -> String {
        use russh::keys::signature::Verifier;

        assert_eq!(reply[4], msg::SIGN_RESPONSE);
        let mut body = &reply[5..];
        let mut inner = take_string(&mut body).unwrap();
        let algorithm = std::str::from_utf8(take_string(&mut inner).unwrap()).unwrap();
        let signature = russh::keys::ssh_key::Signature::new(
            russh::keys::Algorithm::new(algorithm).unwrap(),
            take_string(&mut inner).unwrap().to_vec(),
        )
        .unwrap();
        let public = russh::keys::PublicKey::from_openssh(public).unwrap();
        // Through the trait: `PublicKey` also has an inherent SSHSIG `verify`.
        Verifier::verify(&public, data, &signature).expect("the signature verifies");
        algorithm.to_owned()
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
        let blob = key_blob(&a.public_openssh).unwrap();
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
        let blob = key_blob(&a.public_openssh).unwrap();
        let reply = answer(&a, &sign_request(&blob, b"to-sign"));
        assert_eq!(reply[4], msg::SIGN_RESPONSE);
        assert_eq!(keys.signed.lock().unwrap().len(), 1);
        assert_eq!(keys.signed.lock().unwrap()[0], b"to-sign");
    }

    /// Add, remove, lock and unlock arrive from the remote machine. Honouring
    /// them would let the far end reshape what the local agent holds.
    #[test]
    fn mutating_requests_are_refused() {
        let (a, _) = agent(true);
        for kind in [17_u8, 18, 19, 20, 21, 22, 25, 26, 27] {
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

    /// An agent offering several keys, as the system agent does. It signs for
    /// real with whichever key it is handed and records which one that was.
    struct Listed {
        keys: Vec<OfferedKey>,
        signer: std::sync::Mutex<unissh_ssh_agent::InMemoryAgent>,
        signed_with: std::sync::Mutex<Vec<Vec<u8>>>,
    }
    impl AgentKeys for Listed {
        fn offered(&self) -> Vec<OfferedKey> {
            self.keys.clone()
        }
        fn sign(&self, key: &OfferedKey, data: &[u8], rsa: RsaHash) -> Option<(String, Vec<u8>)> {
            self.signed_with.lock().unwrap().push(key.key_id.clone());
            let signature = self
                .signer
                .lock()
                .unwrap()
                .sign_with(&key.key_id, data, rsa)
                .ok()?;
            Some((signature.algorithm, signature.signature))
        }
    }

    fn listed(comments: &[&str]) -> Listed {
        let mut signer = unissh_ssh_agent::InMemoryAgent::new();
        let keys = comments
            .iter()
            .map(|comment| {
                let (private, public) =
                    unissh_ssh_agent::generate_ed25519_openssh().expect("keygen");
                signer
                    .add_from_openssh(comment.as_bytes().to_vec(), private.as_bytes())
                    .expect("load key");
                OfferedKey {
                    key_id: comment.as_bytes().to_vec(),
                    public_openssh: format!("{public} {comment}"),
                    comment: comment.to_string(),
                }
            })
            .collect();
        Listed {
            keys,
            signer: std::sync::Mutex::new(signer),
            signed_with: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Answers like the person at the prompt, and records what each prompt
    /// named: the key's comment and the calling program.
    struct Prompt {
        answer: bool,
        asked: std::sync::Mutex<Vec<(String, AgentCaller)>>,
    }
    impl LocalApproval for Prompt {
        fn approve(&self, key: &OfferedKey, caller: &AgentCaller, _blob: &[u8]) -> bool {
            self.asked
                .lock()
                .unwrap()
                .push((key.comment.clone(), caller.clone()));
            self.answer
        }
    }

    fn caller() -> AgentCaller {
        AgentCaller {
            pid: Some(4242),
            executable: Some("/usr/bin/ssh".to_owned()),
        }
    }

    /// The system agent's policy over two offered keys, `work` and `deploy`.
    fn local(answer: bool) -> (LocalAgent<Arc<Listed>>, Arc<Listed>, Arc<Prompt>) {
        let keys = Arc::new(listed(&["work", "deploy"]));
        let prompt = Arc::new(Prompt {
            answer,
            asked: std::sync::Mutex::new(Vec::new()),
        });
        let agent = LocalAgent {
            keys: keys.clone(),
            approval: prompt.clone(),
            caller: caller(),
        };
        (agent, keys, prompt)
    }

    /// Reads an IDENTITIES_ANSWER frame the way `ssh-add -l` does.
    fn identities(reply: &[u8]) -> Vec<(Vec<u8>, String)> {
        assert_eq!(reply[4], msg::IDENTITIES_ANSWER);
        let mut body = &reply[9..];
        let count = u32::from_be_bytes([reply[5], reply[6], reply[7], reply[8]]);
        std::iter::repeat_with(|| {
            let blob = take_string(&mut body).unwrap().to_vec();
            let comment = String::from_utf8(take_string(&mut body).unwrap().to_vec()).unwrap();
            (blob, comment)
        })
        .take(usize::try_from(count).unwrap())
        .collect()
    }

    #[test]
    fn identities_list_every_offered_key_with_its_comment() {
        let agent = listed(&["work", "deploy"]);
        let listed = identities(&answer(&agent, &[msg::REQUEST_IDENTITIES]));
        let expected: Vec<(Vec<u8>, String)> = agent
            .keys
            .iter()
            .map(|k| (k.blob().unwrap(), k.comment.clone()))
            .collect();
        assert_eq!(listed, expected);
    }

    #[test]
    fn a_declined_local_signature_is_refused() {
        let (agent, keys, _) = local(false);
        let blob = keys.keys[0].blob().unwrap();
        let reply = answer(&agent, &sign_request(&blob, b"to-sign"));
        assert_eq!(reply[4], msg::FAILURE);
        assert!(
            keys.signed_with.lock().unwrap().is_empty(),
            "declining must happen before signing, not after"
        );
    }

    /// The prompt names the key asked for and the program asking, and the
    /// signature that comes back is one a server holding that public key accepts.
    #[test]
    fn an_approved_signature_verifies_against_the_key_it_names() {
        let (agent, keys, prompt) = local(true);
        let deploy = &keys.keys[1];
        let reply = answer(&agent, &sign_request(&deploy.blob().unwrap(), b"to-sign"));
        assert_eq!(
            *prompt.asked.lock().unwrap(),
            vec![("deploy".to_owned(), caller())]
        );
        verified(&reply, &deploy.public_openssh, b"to-sign");
    }

    /// A key with a certificate is listed twice, key first, and a request
    /// naming the certificate is approved as that key and signed with it.
    #[test]
    fn a_certificate_is_offered_after_its_key_and_signs_with_it() {
        use russh::keys::ssh_key::{certificate, private::Ed25519Keypair, PrivateKey};

        let keys = listed(&["work"]);
        let work = keys.keys[0].clone();
        let public = russh::keys::PublicKey::from_openssh(&work.public_openssh).unwrap();
        let ca = PrivateKey::from(Ed25519Keypair::from_seed(&[8; 32]));
        let mut builder =
            certificate::Builder::new(vec![9; 32], public.key_data().clone(), 0, u64::MAX).unwrap();
        builder.cert_type(certificate::CertType::User).unwrap();
        builder.valid_principal("alice").unwrap();
        let cert = builder.sign(&ca).unwrap();
        let cert_identity = OfferedKey {
            public_openssh: cert.to_openssh().unwrap(),
            ..work.clone()
        };
        let keys = Arc::new(Listed {
            keys: vec![work.clone(), cert_identity],
            ..keys
        });
        let prompt = Arc::new(Prompt {
            answer: true,
            asked: std::sync::Mutex::default(),
        });
        let agent = LocalAgent {
            keys: keys.clone(),
            approval: prompt.clone(),
            caller: caller(),
        };

        let listed = identities(&answer(&agent, &[msg::REQUEST_IDENTITIES]));
        assert_eq!(
            listed,
            vec![
                (work.blob().unwrap(), "work".to_owned()),
                (cert.to_bytes().unwrap(), "work".to_owned()),
            ]
        );

        let reply = answer(&agent, &sign_request(&cert.to_bytes().unwrap(), b"to-sign"));
        assert_eq!(
            *prompt.asked.lock().unwrap(),
            vec![("work".to_owned(), caller())]
        );
        assert_eq!(*keys.signed_with.lock().unwrap(), vec![b"work".to_vec()]);
        verified(&reply, &work.public_openssh, b"to-sign");
    }

    /// `SSH_AGENT_RSA_SHA2_256` and `_512` choose the hash; an RSA request with
    /// neither (a SHA-1 `ssh-rsa` signature) is refused before any prompt.
    #[test]
    fn rsa_flags_choose_the_hash_and_sha1_is_refused() {
        let mut signer = unissh_ssh_agent::InMemoryAgent::new();
        let pem = unissh_ssh_agent::normalize_private_key_to_openssh(RSA_PKCS1).unwrap();
        signer
            .add_from_openssh(b"rsa".to_vec(), pem.as_bytes())
            .unwrap();
        let rsa = OfferedKey {
            key_id: b"rsa".to_vec(),
            public_openssh: RSA_PUB.to_owned(),
            comment: "rsa".to_owned(),
        };
        let prompt = Arc::new(Prompt {
            answer: true,
            asked: std::sync::Mutex::new(Vec::new()),
        });
        let agent = LocalAgent {
            keys: Listed {
                keys: vec![rsa.clone()],
                signer: signer.into(),
                signed_with: std::sync::Mutex::default(),
            },
            approval: prompt.clone(),
            caller: caller(),
        };
        let blob = rsa.blob().unwrap();

        for (flags, algorithm) in [
            (2, "rsa-sha2-256"),
            (4, "rsa-sha2-512"),
            (6, "rsa-sha2-256"),
        ] {
            let reply = answer(&agent, &sign_request_flagged(&blob, b"to-sign", flags));
            assert_eq!(
                verified(&reply, RSA_PUB, b"to-sign"),
                algorithm,
                "flags {flags}"
            );
        }
        prompt.asked.lock().unwrap().clear();
        let reply = answer(&agent, &sign_request_flagged(&blob, b"to-sign", 0));
        assert_eq!(reply[4], msg::FAILURE);
        assert!(
            prompt.asked.lock().unwrap().is_empty(),
            "refused before the prompt"
        );
    }

    /// A classic RSA-2048 (PKCS#1) and its public key: generating one at test
    /// time is slow in a debug build.
    const RSA_PKCS1: &str = "\
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Nz6qk+yFoEL3gBixnDidk4jLEIvDk25O5yTpEMmmIHa/o8x
MVd1pYkXbh2IZwy/SrTyUqWDvAif5Monzuti7kT/0/VMldm4X/JNhfr6K+p5Y+oJ
61cHMNzW+PVe/SFCdqYeFZaa4v0feSKfc3pdTawrVyopGQ9Onj/W2QS5OGdwFblq
zqzaJKZWA9qvFy90qmTpliSxxr7mY5C/RMwqiXt9+4DtPeJBRK9BNZ8AkMGbwgP8
/WW6yqYDd1L62AxLA+uNymQWf6t9nWaSf03mREe1zVXS/HFIVeSPBDej80gULfJt
3ftjQNTem6PxSqAOdHWBS2PCtrRVClMSnLcvPwIDAQABAoIBAACnSj+Uc33n3dZO
K1ZHm5DUJS90pSyp/x0hfYUlkosmqEmbamshAeAtGAK4eVCvUc+c+qcEsAeW3Wn3
dUlhHaI4QpH7rXIkGm+rjoBxGQ8XQlWW7ojSob2zA/KxvsrQVmXBNTRpnE/47T88
EGbjnbE2VJgxgdyNu/4X5yKQZ2jnYaONCPPozU9/P94oXj+huOl8LQQ3P+dukcMu
13X/Bdbo7FjmHL0Fci7Ii33PZm350lcfeIuOIYltglZNSTUPrJy9FIrQ8H8BY6yM
GKrI6UMbMWSopJdwEi99pCoPGr7O7frz9Ly7Cpl1axj9WfsA/G6MZMjnFLAyvYKv
43AdHPECgYEA9+pbS3o9LwMok/cqPHzrYnK1Vn0BHH10HqeXpuwJE4lsps2Fo2LH
Xz1Wi9+/JY1jObnadWMkkAvx1ZUsp4FkcLOr/HDZOYF+uaEw+gKRVpOlWCLICjlm
GjeP5X72aoHUJ8PNBvjqAVp8ylKBFE9ukLzZsVb4FBPS+bMu63pJ8YsCgYEA16yb
cUO9N2uzlQMAUckIDyoUnHptRdcHapXDneZd/SnKzcU/hD/S/RcVqQB1YANpZyeM
/bNzSfkWcxVkaWC7Z2maHn/DXm3ZhFT15I5ELAbdq37e+vUbdvWGcBuCzmtwFdIl
yeqx6BzHoUWaVuPAZ5Z5VJQoTH1OhHuQFJUxx50CgYEAlLu/JdsiVdAZShwg9MUl
Gp0i+c5pGkSRo8p8CyLUlyn9S11F7a3XWuYbxDLqJIdcnkdILuDaEKl53t9uONhB
//NrHTo+uGdeNdPk5DkiJMTTj7reNHQXM2deJxsyjtdxBqJLoQE4srMs5tz0n9C/
zoneOKyqjLEQA8piPdfSAN0CgYASvq3D6l9HsdSp3tjoQtCwgLfJ4dodd9LtMJcP
4jXJCxjVSY97rxBnbtozFhcdgS5oCMf4ROCATWXmGrXfcsjW9BaxD+mrC2EcX0X/
112VdgNOJHi81xDMBgrpM3rq9euH+fvO0NcllVrEaYhAhQrz9eAVucrG2x035oVf
RJhPAQKBgQCcjnPyuFuq3zIIAVSA1ryvtFW5n95eij/AABeBhKjcsKKC9TyPy145
5mXOxoXcTAT4qbLxLc34BVjC49DoquOVble2OBVWWNng+x+AKyJXVaih7o+mTt6Y
otqRUgfM3Hf3sdwr66X6ltp1sQlzggaVlhH3pBsCWTPQ6nBzWEgiPA==
-----END RSA PRIVATE KEY-----";

    const RSA_PUB: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDQ3PqqT7IWgQveAGLGcOJ2TiMsQi8OTbk7nJOkQyaYgdr+jzExV3WliRduHYhnDL9KtPJSpYO8CJ/kyifO62LuRP/T9UyV2bhf8k2F+vor6nlj6gnrVwcw3Nb49V79IUJ2ph4Vlpri/R95Ip9zel1NrCtXKikZD06eP9bZBLk4Z3AVuWrOrNokplYD2q8XL3SqZOmWJLHGvuZjkL9EzCqJe337gO094kFEr0E1nwCQwZvCA/z9ZbrKpgN3UvrYDEsD643KZBZ/q32dZpJ/TeZER7XNVdL8cUhV5I8EN6PzSBQt8m3d+2NA1N6bo/FKoA50dYFLY8K2tFUKUxKcty8/ rsa";

    #[test]
    fn a_key_we_do_not_offer_is_refused() {
        let (agent, keys, prompt) = local(true);
        let other = listed(&["elsewhere"]).keys[0].blob().unwrap();
        let reply = answer(&agent, &sign_request(&other, b"to-sign"));
        assert_eq!(reply[4], msg::FAILURE);
        assert!(
            prompt.asked.lock().unwrap().is_empty() && keys.signed_with.lock().unwrap().is_empty(),
            "the key check must come before the prompt and the signature"
        );
    }

    /// Keeps the prompt open until the connection is abandoned, then refuses.
    #[derive(Default)]
    struct HeldOpen {
        asked: std::sync::atomic::AtomicBool,
        abandoned: std::sync::Mutex<bool>,
        wake: std::sync::Condvar,
    }
    impl LocalApproval for HeldOpen {
        fn approve(&self, _key: &OfferedKey, _caller: &AgentCaller, _blob: &[u8]) -> bool {
            self.asked.store(true, std::sync::atomic::Ordering::SeqCst);
            let abandoned = self.abandoned.lock().unwrap();
            // Bounded, so a regression fails the test instead of hanging it.
            // Released right away: the answer is `false` whether abandoned or timed out.
            drop(
                self.wake
                    .wait_timeout_while(abandoned, std::time::Duration::from_secs(10), |a| !*a)
                    .unwrap(),
            );
            false
        }
        fn abandon(&self) {
            *self.abandoned.lock().unwrap() = true;
            self.wake.notify_all();
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_client_that_hangs_up_withdraws_its_pending_prompt() {
        use tokio::io::AsyncWriteExt;

        let keys = Arc::new(listed(&["work"]));
        let prompt = Arc::new(HeldOpen::default());
        let agent = Arc::new(LocalAgent {
            keys: keys.clone(),
            approval: prompt.clone(),
            caller: caller(),
        });
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let served = tokio::spawn(serve(agent, server));
        let request = sign_request(&keys.keys[0].blob().unwrap(), b"to-sign");
        client.write_all(&framed(&request).unwrap()).await.unwrap();
        while !prompt.asked.load(std::sync::atomic::Ordering::SeqCst) {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        drop(client);
        tokio::time::timeout(std::time::Duration::from_secs(5), served)
            .await
            .expect("serving ends as soon as the client is gone")
            .unwrap();
        assert!(
            *prompt.abandoned.lock().unwrap(),
            "the prompt was withdrawn"
        );
    }
}
