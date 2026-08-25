//! Platform TLS trust-store initialisation.
//!
//! `reqwest`'s `rustls` feature does not pick a bundled root store: it pulls in
//! `rustls-platform-verifier` and verifies against whatever the OS trusts. That
//! is the behaviour we want — self-hosting behind a private CA is supported, and
//! the certificate error text tells the user to install their CA root into the
//! machine's own trust store, which is only true if we read that store.
//!
//! On every desktop the verifier finds the store by itself. **Android is the
//! exception**: there the trust store is only reachable over JNI, so the crate
//! has to be handed the JVM and the application `Context` before it verifies
//! anything, and it panics if it was not (`Expect rustls-platform-verifier to be
//! initialized`).
//!
//! That panic is why #34 looked like a Tauri bug. It fires on reqwest's own
//! internal thread, which is building the async client there; unwinding past the
//! startup channel leaves the caller with a cancelled oneshot, and reqwest turns
//! that into a *second* panic — `event loop thread panicked` — deliberately,
//! because at that point the client is unusable. The original message is lost,
//! so every cloud operation on Android died with a string that names reqwest's
//! thread and says nothing about certificates.
//!
//! Call [`init`] before the first HTTPS request. It is idempotent.
//!
//! Android is the exception twice over, and [`configure`] is the second half.
//! Its platform verifier reports "certificate revoked" when what actually
//! happened is that it had no responder to ask — which is now the normal case
//! for Let's Encrypt and Google Trust Services, and made every cloud request on
//! Android fail. The wrapper that tells those two apart lives in
//! `platform_tls/android.rs`; everything else compiles it away.

#[cfg(target_os = "android")]
mod android;

use std::sync::OnceLock;

/// Set once the verifier is ready. Deliberately caches only SUCCESS: the one way
/// this fails is being called before the Android activity exists, which is
/// transient, and a `OnceLock<Result<..>>` would freeze that transient miss in
/// for the life of the process. Retrying is cheap — after the first success this
/// is a single atomic load, and the underlying crate's own init is idempotent.
static DONE: OnceLock<()> = OnceLock::new();

/// Prepare the platform certificate verifier. `Ok(())` on every platform that
/// needs no preparation. Idempotent; call it before each HTTPS request.
pub fn init() -> Result<(), String> {
    if DONE.get().is_some() {
        return Ok(());
    }
    init_once()?;
    let _ = DONE.set(());
    Ok(())
}

#[cfg(not(target_os = "android"))]
fn init_once() -> Result<(), String> {
    Ok(())
}

/// Hand `rustls-platform-verifier` the JVM and the app `Context`.
///
/// The pointers come from tao, which owns the activity — `tauri::tao` is Tauri's
/// own re-export, so this does not add a dependency on tao's release cadence.
/// `main_android_context()` is `None` until the activity exists, which is why
/// this is called lazily on first use rather than from `setup()`.
///
/// NOTE: the direct `rustls-platform-verifier` dependency MUST stay
/// semver-compatible with the one `reqwest` resolves. The crate stores the JNI
/// handles in a private process-global `OnceCell`; two incompatible versions
/// would each get their own, and this call would initialise one while reqwest
/// verified against the other — a silent no-op that looks exactly like the bug
/// it is here to fix.
#[cfg(target_os = "android")]
fn init_once() -> Result<(), String> {
    use jni::objects::JObject;
    use jni::{Env, JavaVM};
    use tauri::tao::platform::android::prelude::main_android_context;

    let ctx = main_android_context()
        .ok_or_else(|| "the Android activity is not available yet".to_string())?;

    // SAFETY: both pointers come straight from tao's live activity context; they
    // are the JavaVM and the MainActivity jobject for this process.
    let vm = unsafe { JavaVM::from_raw(ctx.java_vm.cast()) };
    vm.attach_current_thread(|env: &mut Env| -> Result<(), jni::errors::Error> {
        let context = unsafe { JObject::from_raw(env, ctx.context_jobject.cast()) };
        rustls_platform_verifier::android::init_with_env(env, context)
    })
    .map_err(|e| format!("could not reach the Android trust store over JNI: {e}"))
}

/// Apply any platform-specific TLS configuration to the blocking HTTP client
/// builder. Everywhere but Android this hands the builder straight back — no
/// branch, no allocation, no behaviour to review; the desktop and iOS clients
/// are the ones `reqwest` builds for itself, byte for byte.
#[cfg(not(target_os = "android"))]
pub fn configure(builder: reqwest::blocking::ClientBuilder) -> reqwest::blocking::ClientBuilder {
    builder
}

/// Wrap Android's platform verifier so that "I could not ask about revocation"
/// stops being reported as "revoked". See `platform_tls/android.rs` — the whole
/// argument for why that is safe is written there.
#[cfg(target_os = "android")]
pub fn configure(builder: reqwest::blocking::ClientBuilder) -> reqwest::blocking::ClientBuilder {
    android::configure(builder)
}

/// Did Android's revocation check come back empty-handed, rather than come back
/// with an answer?
///
/// This is the whole of the project-authored decision in one place: the two data
/// conditions that, together with a `Revoked` verdict from the platform, mean
/// nobody was ever in a position to answer. It lives here rather than inside the
/// `cfg(target_os = "android")` module for one reason — it is pure bytes with no
/// JNI in it, and out here it can be exercised without a phone.
///
/// * **Nothing stapled.** `ocsp_response` is empty exactly when the server sent
///   no OCSP response in the handshake; that is the same normalisation upstream
///   applies before its JNI call. A staple that says "revoked" is a real answer
///   from a real responder and must still be refused.
/// * **Nowhere to ask.** The certificate names no OCSP responder of its own.
///
/// The third condition — that the platform actually said *revoked* — is the
/// caller's, and is checked in `platform_tls/android.rs`.
#[cfg(any(target_os = "android", test))]
pub(crate) fn revocation_was_unanswered(ocsp_response: &[u8], end_entity: &[u8]) -> bool {
    ocsp_response.is_empty() && !has_ocsp_responder(end_entity)
}

/// Does this DER certificate name an OCSP responder to ask about its own
/// revocation?
///
/// The needle is the `accessMethod` OID `id-ad-ocsp` (1.3.6.1.5.5.7.48.1) as it
/// appears inside an `AccessDescription` of the Authority Information Access
/// extension (RFC 5280 §4.2.2.1), tag and length included:
///
/// ```text
/// 06 08 2B 06 01 05 05 07 30 01
/// ^^ ^^ OBJECT IDENTIFIER, 8 content octets
///       ^^ 1.3 packs into one octet (40*1 + 3 = 0x2B), then 6 1 5 5 7 48 1
/// ```
///
/// A byte scan rather than a parse, and deliberately so: the alternative is a
/// new ASN.1 dependency in the one code path that decides whether to accept a
/// certificate, which is a poor trade for locating a fixed ten-byte string.
///
/// **The asymmetry is the point.** A false positive — deciding a responder
/// exists because those ten bytes happen to fall inside a signature, an SCT or a
/// public key — only makes us hand back the platform's `Revoked` verdict
/// unchanged, i.e. refuse the connection. That is the safe direction. A false
/// negative is the dangerous one, because it is what would let a genuinely
/// revoked certificate through, so it is worth saying why it cannot happen in
/// practice: X.690 §8.19.1 requires an object identifier to be encoded
/// *primitively*, so the OID is always one contiguous run of octets no matter
/// how its enclosing SEQUENCEs are wrapped — indefinite lengths and BER included
/// — and TLS puts DER on the wire (RFC 8446 §4.4.2), which rustls hands us
/// untouched. So we scan exactly the bytes the CA emitted and exactly the bytes
/// Android parsed. A non-minimal encoding that slipped past our scan would have
/// had to slip past Android's parser too, in which case Android learned nothing
/// either and accepting is still the right answer.
///
/// Only the end-entity certificate is scanned, and it is upstream's own
/// configuration that makes that the correct scope rather than a compromise: its
/// Kotlin half sets `PKIXRevocationChecker.Option.ONLY_END_ENTITY`, so Android
/// never asks a revocation question about an intermediate or an anchor in the
/// first place. A `Revoked` verdict is therefore always *about the leaf*, and the
/// leaf is what we scan. Widening the scan to `intermediates` could only cost the
/// fix and never buy safety: that slice is "everything else the server sent",
/// routinely including the root, and roots very often *do* publish a responder
/// while the leaf below them does not (GTS Root R1 is the everyday example,
/// shipped in Google's own chains) — so counting those bytes would refuse the
/// accept path for most real chains and leave Android exactly as broken as
/// before.
#[cfg(any(target_os = "android", test))]
pub(crate) fn has_ocsp_responder(der: &[u8]) -> bool {
    const ID_AD_OCSP: [u8; 10] = [0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01];
    // `windows` yields nothing when the slice is shorter than the needle, so an
    // empty or truncated certificate answers "no responder" without a bounds check.
    der.windows(ID_AD_OCSP.len()).any(|w| w == ID_AD_OCSP)
}

/// The scanner and the decision it feeds are pure bytes with no Android in them,
/// which is why both are compiled into every test build rather than gated away
/// with the rest: the scan is the only hand-written parsing in this change, and
/// its false negative would be the security bug.
///
/// **Nothing in CI evaluates these assertions today**, and that is worth writing
/// down rather than assuming otherwise. The root workspace excludes
/// `client/src-tauri`, so `cargo test --workspace` in `ci.yml` never reaches this
/// crate, and the one step that does — `Lint (Tauri crate)` in `client.yml` —
/// runs `cargo fmt --all --check` and `cargo clippy --all-targets`, which
/// type-check this module and execute none of it. A scanner broken to always
/// answer `true` would ship green. Appending `cargo test --lib` to that step is a
/// one-line change and this is the reason for it; until then, run it by hand in
/// `client/src-tauri` before touching anything below.
///
/// The fixtures are hand-built byte for byte rather than committed as `.der`
/// blobs, which keeps the encoding legible — the discriminating byte is visible
/// in the source. The negative one is not invented: it is the live server's own
/// Authority Information Access extension, copied out of its certificate. The
/// positive one carries both access methods, which is what every CA that still
/// runs a responder (DigiCert, Sectigo, GlobalSign, Microsoft) emits today.
#[cfg(test)]
mod ocsp_scan_tests {
    use super::{has_ocsp_responder, revocation_was_unanswered};

    /// `AuthorityInfoAccessSyntax` with an OCSP `AccessDescription` first and a
    /// `caIssuers` one after it — the shape of the positive test vector:
    ///
    /// ```text
    /// 30 4F                            SEQUENCE (79)  AuthorityInfoAccessSyntax
    ///   30 23                          SEQUENCE (35)  AccessDescription
    ///     06 08 2B..30 01              id-ad-ocsp
    ///     86 17 "http://ocsp.example.com"   [6] IMPLICIT IA5String (23)
    ///   30 28                          SEQUENCE (40)  AccessDescription
    ///     06 08 2B..30 02              id-ad-caIssuers
    ///     86 1C "http://ca.example.com/ca.crt"        (28)
    /// ```
    fn aia_with_ocsp() -> Vec<u8> {
        let mut v = vec![0x30, 0x4F, 0x30, 0x23];
        v.extend_from_slice(&[0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01]);
        v.extend_from_slice(&[0x86, 0x17]);
        v.extend_from_slice(b"http://ocsp.example.com");
        v.extend_from_slice(&[0x30, 0x28]);
        v.extend_from_slice(&[0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02]);
        v.extend_from_slice(&[0x86, 0x1C]);
        v.extend_from_slice(b"http://ca.example.com/ca.crt");
        v
    }

    /// The real thing that broke Android: an AIA extension that *exists* and
    /// carries only `caIssuers`. Not a plausible shape — these 39 bytes appear
    /// verbatim in the live server's own leaf (`unissh.dev`, issued by Let's
    /// Encrypt YR2), and the same shape with a different URL is what Google Trust
    /// Services emits.
    ///
    /// ```text
    /// 30 25                            SEQUENCE (37)  AuthorityInfoAccessSyntax
    ///   30 23                          SEQUENCE (35)  AccessDescription
    ///     06 08 2B..30 02              id-ad-caIssuers   <- last byte 02, not 01
    ///     86 17 "http://yr2.i.lencr.org/"               (23)
    /// ```
    fn aia_without_ocsp() -> Vec<u8> {
        let mut v = vec![0x30, 0x25, 0x30, 0x23];
        v.extend_from_slice(&[0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02]);
        v.extend_from_slice(&[0x86, 0x17]);
        v.extend_from_slice(b"http://yr2.i.lencr.org/");
        v
    }

    /// A certificate that says where to ask is found, wherever in the DER the
    /// extension happens to sit — the scan is not anchored to an offset.
    #[test]
    fn a_published_responder_is_found() {
        assert!(has_ocsp_responder(&aia_with_ocsp()));

        let mut buried = vec![0xAA; 300];
        buried.extend_from_slice(&aia_with_ocsp());
        buried.extend_from_slice(&[0xBB; 256]);
        assert!(has_ocsp_responder(&buried));
    }

    /// The case the whole fix turns on. `id-ad-caIssuers` differs from
    /// `id-ad-ocsp` in exactly one byte, and "has an AIA extension" is a
    /// different question from "publishes a responder" — mainstream CAs now
    /// answer yes to the first and no to the second.
    #[test]
    fn an_aia_with_only_ca_issuers_is_not_a_responder() {
        assert!(!has_ocsp_responder(&aia_without_ocsp()));

        let mut buried = vec![0xAA; 300];
        buried.extend_from_slice(&aia_without_ocsp());
        assert!(!has_ocsp_responder(&buried));
    }

    /// Nothing to scan must answer "no responder" rather than panic — the caller
    /// reaches this with whatever bytes were on the wire, unparsed.
    #[test]
    fn an_empty_slice_is_not_a_responder() {
        assert!(!has_ocsp_responder(&[]));
        assert!(!has_ocsp_responder(&[0x06]));
    }

    /// A truncated OID must not count. Both halves matter: a needle cut short at
    /// the end of the buffer, and the same prefix followed by the wrong final
    /// byte — which is how `caIssuers` would score a hit if the scan compared
    /// only a prefix.
    #[test]
    fn a_truncated_oid_is_not_a_responder() {
        // Nine of the ten bytes, and the buffer simply ends.
        assert!(!has_ocsp_responder(&[
            0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30
        ]));
        // The full ten bytes, but the last one belongs to a different OID.
        assert!(!has_ocsp_responder(&[
            0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02
        ]));
        // Right bytes, wrong length octet: this is not an eight-octet OID.
        assert!(!has_ocsp_responder(&[
            0x06, 0x07, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01
        ]));
    }

    /// The only shape that may override the platform: nothing came down in the
    /// handshake and the certificate names nowhere to go and ask.
    #[test]
    fn nothing_stapled_and_nowhere_to_ask_is_unanswered() {
        assert!(revocation_was_unanswered(&[], &aia_without_ocsp()));
    }

    /// A staple is an answer, and it blocks the override on its own — including
    /// for the very certificate shape the fix exists for. This is the case the
    /// scanner tests cannot express: if the server handed us an OCSP response
    /// then somebody *was* asked, so a `Revoked` verdict is what that answer
    /// said. The bytes here need not be a well-formed response; the caller only
    /// ever asks whether any arrived.
    #[test]
    fn a_staple_is_an_answer() {
        assert!(!revocation_was_unanswered(
            &[0x30, 0x03],
            &aia_without_ocsp()
        ));
        assert!(!revocation_was_unanswered(&[0x30, 0x03], &aia_with_ocsp()));
    }

    /// ...and so does a published responder, staple or no staple: a certificate
    /// that says where to ask is one Android could have asked about, so its
    /// `Revoked` is a real revocation and stays refused.
    #[test]
    fn a_published_responder_blocks_the_override() {
        assert!(!revocation_was_unanswered(&[], &aia_with_ocsp()));
    }
}
