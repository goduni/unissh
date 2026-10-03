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

/// One identity an agent offers.
#[derive(Clone, Debug)]
pub struct OfferedKey {
    /// The key id the signer knows it by. Never leaves the process.
    pub key_id: Vec<u8>,
    /// The public half, in OpenSSH text form.
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
    /// Returns `(algorithm, signature)`.
    fn sign(&self, key: &OfferedKey, data: &[u8]) -> Option<(String, Vec<u8>)>;
    /// The client went away while a request was still being answered. A policy
    /// waiting on a person withdraws its prompt here; the answer, whatever it
    /// becomes, is discarded.
    fn hang_up(&self) {}
}

impl<T: AgentKeys + ?Sized> AgentKeys for std::sync::Arc<T> {
    fn offered(&self) -> Vec<OfferedKey> {
        (**self).offered()
    }
    fn sign(&self, key: &OfferedKey, data: &[u8]) -> Option<(String, Vec<u8>)> {
        (**self).sign(key, data)
    }
    fn hang_up(&self) {
        (**self).hang_up()
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
            .to_string()
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

    fn sign(&self, key: &OfferedKey, data: &[u8]) -> Option<(String, Vec<u8>)> {
        if !self.approval.approve(&self.host, data) {
            log::info!("forwarded agent: signature declined by the user");
            return None;
        }
        match self.keys.sign(&key.key_id, data) {
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

    fn sign(&self, key: &OfferedKey, data: &[u8]) -> Option<(String, Vec<u8>)> {
        if !self.approval.approve(key, &self.caller, data) {
            log::info!("system agent: signature declined by the user");
            return None;
        }
        self.keys.sign(key, data)
    }

    fn hang_up(&self) {
        self.approval.abandon();
    }
}

/// The key blob of an OpenSSH public key line.
///
/// Through the real parser rather than a base64 decode of the middle field: it
/// validates the key at the same time, and the wire encoding is exactly what a
/// client compares against.
fn key_blob(public_openssh: &str) -> Option<Vec<u8>> {
    russh::keys::PublicKey::from_openssh(public_openssh.trim())
        .ok()?
        .to_bytes()
        .ok()
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
/// the protocol rules live, and they are what has to be right.
pub fn answer<A: AgentKeys + ?Sized>(agent: &A, request: &[u8]) -> Vec<u8> {
    let Some((&kind, mut body)) = request.split_first() else {
        return failure();
    };

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
            out.extend_from_slice(&(identities.len() as u32).to_be_bytes());
            for (blob, comment) in &identities {
                put_string(&mut out, blob);
                put_string(&mut out, comment.as_bytes());
            }
            framed(out)
        }
        msg::SIGN_REQUEST => {
            let (Some(want_blob), Some(data)) = (take_string(&mut body), take_string(&mut body))
            else {
                return failure();
            };
            // Flags follow; RSA hash selection is not honoured yet, so they are
            // not read.
            let Some(key) = agent
                .offered()
                .into_iter()
                .find(|key| key.blob().as_deref() == Some(want_blob))
            else {
                // A key we do not offer. Refused rather than substituted.
                log::warn!("agent: signature requested for a key we do not offer");
                return failure();
            };
            match agent.sign(&key, data) {
                Some((algorithm, signature)) => {
                    let mut inner = Vec::new();
                    put_string(&mut inner, algorithm.as_bytes());
                    put_string(&mut inner, &signature);
                    let mut out = vec![msg::SIGN_RESPONSE];
                    put_string(&mut out, &inner);
                    framed(out)
                }
                None => failure(),
            }
        }
        // Everything else — add, remove, lock, unlock, extensions. Whoever can
        // reach the socket does not get to reshape what the agent holds.
        other => {
            log::warn!("agent: refusing request type {other}");
            failure()
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
        let len = u32::from_be_bytes([inbox[0], inbox[1], inbox[2], inbox[3]]) as usize;
        if len == 0 || len > MAX_FRAME {
            log::warn!("agent: refusing a {len}-byte frame");
            return;
        }
        if fill(&mut stream, &mut inbox, 4 + len).await.is_err() {
            return;
        }
        let body: Vec<u8> = inbox.drain(..4 + len).skip(4).collect();
        let policy = agent.clone();
        let mut job = tokio::task::spawn_blocking(move || answer(&*policy, &body));
        let reply = loop {
            let mut chunk = [0u8; 4096];
            tokio::select! {
                done = &mut job => break done,
                read = stream.read(&mut chunk), if inbox.len() <= 4 + MAX_FRAME => match read {
                    Ok(0) | Err(_) => {
                        agent.hang_up();
                        return;
                    }
                    Ok(n) => inbox.extend_from_slice(&chunk[..n]),
                },
            }
        };
        let Ok(reply) = reply else {
            return;
        };
        if stream.write_all(&reply).await.is_err() {
            return;
        }
        let _ = stream.flush().await;
    }
}

/// Reads from `stream` until `inbox` holds at least `want` bytes.
async fn fill<S: tokio::io::AsyncRead + Unpin>(
    stream: &mut S,
    inbox: &mut Vec<u8>,
    want: usize,
) -> std::io::Result<()> {
    let mut chunk = [0u8; 4096];
    while inbox.len() < want {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        inbox.extend_from_slice(&chunk[..n]);
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
        fn sign(&self, key: &OfferedKey, data: &[u8]) -> Option<(String, Vec<u8>)> {
            self.signed_with.lock().unwrap().push(key.key_id.clone());
            let signature = self.signer.lock().unwrap().sign(&key.key_id, data).ok()?;
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
            executable: Some("/usr/bin/ssh".to_string()),
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
        (0..count)
            .map(|_| {
                let blob = take_string(&mut body).unwrap().to_vec();
                let comment = String::from_utf8(take_string(&mut body).unwrap().to_vec()).unwrap();
                (blob, comment)
            })
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
        use russh::keys::signature::Verifier;

        let (agent, keys, prompt) = local(true);
        let deploy = &keys.keys[1];
        let reply = answer(&agent, &sign_request(&deploy.blob().unwrap(), b"to-sign"));
        assert_eq!(reply[4], msg::SIGN_RESPONSE);
        assert_eq!(
            *prompt.asked.lock().unwrap(),
            vec![("deploy".to_string(), caller())]
        );

        let mut body = &reply[5..];
        let mut inner = take_string(&mut body).unwrap();
        let algorithm = std::str::from_utf8(take_string(&mut inner).unwrap()).unwrap();
        let signature = russh::keys::ssh_key::Signature::new(
            russh::keys::Algorithm::new(algorithm).unwrap(),
            take_string(&mut inner).unwrap().to_vec(),
        )
        .unwrap();
        let public = russh::keys::PublicKey::from_openssh(&deploy.public_openssh).unwrap();
        // Through the trait: `PublicKey` also has an inherent SSHSIG `verify`.
        Verifier::verify(&public, b"to-sign", &signature)
            .expect("the signature verifies against the named key");
    }

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
            let _ = self
                .wake
                .wait_timeout_while(abandoned, std::time::Duration::from_secs(10), |a| !*a)
                .unwrap();
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
        client.write_all(&framed(request)).await.unwrap();
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
