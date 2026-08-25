//! Android answers "revoked" when what it means is "I was never able to ask".
//!
//! `rustls-platform-verifier` verifies a chain on Android in two separate steps.
//! First it hands the chain to the system `X509TrustManager`, which is what
//! consults the trust store and applies pinning and Certificate Transparency.
//! Only then, as a second pass, does it run a `CertPathValidator` carrying a
//! `PKIXRevocationChecker` over the chain the first step built. That checker
//! asks OCSP, and both Let's Encrypt and Google Trust Services have stopped
//! putting an OCSP responder into the certificates they issue. With no responder
//! to ask and no stapled answer to read, the second pass throws
//! `CertPathValidatorException: Certificate does not specify OCSP responder` —
//! and the crate's Kotlin half maps *every* `CertPathValidatorException` onto
//! `StatusCode.Revoked`, which becomes `CertificateError::Revoked` on this side.
//!
//! So on Android every cloud request to a server behind a mainstream public CA
//! died with `invalid peer certificate: Revoked`, and the certificate was not
//! revoked at all — nobody had been asked. Upstream knows (its own comment
//! points at its PR #179) and ships an escape hatch gated on `BuildConfig.TEST`,
//! which a shipped app can never reach. 0.7.0 is current, there is no feature
//! flag and no API knob, and the behaviour dates to 2023, so there is nothing to
//! downgrade to either.
//!
//! What this module does is narrow on purpose. It wraps the platform verifier
//! and second-guesses it in exactly one situation: the platform said *revoked*,
//! **and** the server stapled no OCSP response, **and** the certificate itself
//! names no OCSP responder. Every other verdict — including a *revoked* on a
//! certificate that does publish a responder, which is a real answer from a real
//! responder — is returned untouched. There is no "accept anything" path here
//! and nothing is disabled.
//!
//! ## Why that is safe
//!
//! Three facts out of upstream's own Android verifier, all of which the design
//! rests on:
//!
//! 1. **A `Revoked` verdict guarantees the chain already validated against the
//!    system trust store.** A chain Android does not trust comes back as
//!    `UnknownCert` → `UnknownIssuer`, on a different arm entirely, and the
//!    validity dates and EKU are checked before the trust manager is even
//!    called. Narrower still: with nothing stapled, upstream returns `Ok`
//!    immediately unless the anchor is an OS-shipped root — its `isKnownRoot`
//!    check, which a user- or enterprise-installed CA does not satisfy — so the
//!    arm below is only ever reached for a chain ending in a public root Android
//!    itself ships.
//! 2. **Android never checks the hostname.** Upstream's comment says so plainly
//!    ("This does not validate serverName ... That is handled in Rust"), and the
//!    crate calls `rustls::client::verify_server_name` only on its `Ok` arm.
//!    Accepting on the `Revoked` arm without repeating that check would accept a
//!    perfectly valid, perfectly unrevoked certificate issued for *someone
//!    else's* host. That is why the check below is not optional decoration; it
//!    is the single load-bearing line in this file.
//! 3. **Only the end-entity is ever revocation-checked.** Upstream sets
//!    `PKIXRevocationChecker.Option.ONLY_END_ENTITY`, so a `Revoked` verdict is
//!    always about the leaf — which is why the OID scan in the parent module
//!    looks at the leaf and at nothing else.
//!
//! Nothing here reimplements a cryptographic primitive: chain building, trust
//! store lookup, signature verification and name matching are all still upstream
//! calls. The only project-authored logic is the ten-byte OID scan in the parent
//! module and the three-way AND below — a decision, not a re-implementation.
//!
//! ## What the override costs, stated plainly
//!
//! Two narrowings. Neither is a bypass, both are real, and a reader deciding
//! whether to keep this file needs them in front of them:
//!
//! * **`Revoked` is a wider bucket than its name.** The Kotlin catches
//!   `CertPathValidatorException` around the *whole* second-pass
//!   `CertPathValidator.validate(...)`, not merely the revocation checker, and
//!   only the exception's text crosses JNI — the reason code is discarded. So a
//!   second-stage PKIX failure that has nothing to do with revocation (a
//!   disabled signature algorithm, an unhandled critical extension, a name or
//!   policy constraint) also arrives here as `Revoked`, and on a chain with no
//!   staple and no responder this file now accepts it. What is *not* lost is the
//!   first pass: the system `X509TrustManager` — chain building, the trust
//!   store, validity, pinning, CT — has already said yes. The residue is the
//!   delta between conscrypt's checks and the JDK validator's, which is the
//!   reason the override is kept this narrow rather than widened to taste.
//! * **OCSP is not the only revocation channel a certificate can name.**
//!   Upstream sets `SOFT_FAIL` and `ONLY_END_ENTITY` but *not* `NO_FALLBACK`, so
//!   Java is entitled to fall back from OCSP to CRLs — and the very certificates
//!   this fix targets do carry a `cRLDistributionPoints` (a live Let's Encrypt
//!   leaf has no OCSP responder in its AIA and a `.crl` URL beside it). Android
//!   does not fetch distribution points unless `com.sun.security.enableCRLDP` is
//!   set, which is off by default; that is precisely why the exception we
//!   actually see is the missing-responder one rather than a CRL verdict. **The
//!   accepted risk in one sentence: a certificate that is genuinely revoked, and
//!   whose revocation is discoverable only through its CRL distribution point,
//!   is accepted on this path.** Gating on the distribution point instead would
//!   refuse every Let's Encrypt certificate and undo the fix, so the scan stays
//!   on OCSP — but if a future Android starts consulting CRL DPs, this override
//!   begins masking real revocations and must go that day.
//!
//! ## Removing this
//!
//! A workaround with an expiry date, not a permanent part of the client. It
//! comes out when `rustls-platform-verifier` ships a release whose Android path
//! either stops mapping a missing-responder `CertPathValidatorException` onto
//! `Revoked`, or exposes a way to soft-fail an unanswerable revocation check
//! from outside `BuildConfig.TEST`. The thread to watch is
//! <https://github.com/rustls/rustls-platform-verifier/pull/179>; **re-read this
//! file on every `rustls-platform-verifier` bump**, and delete all of it
//! together:
//!
//! * this file;
//! * in `platform_tls.rs`: `mod android;`, the Android `configure` arm,
//!   `revocation_was_unanswered`, `has_ocsp_responder` and `mod
//!   ocsp_scan_tests`;
//! * in `cloud/client.rs`: the `crate::platform_tls::configure(...)` call;
//! * in `Cargo.toml`: the direct `rustls` dependency.
//!
//! Desktop and iOS never compile any of this: their verifiers answer revocation
//! properly and are used exactly as `reqwest` ships them.

use std::sync::Arc;

use reqwest::blocking::ClientBuilder;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, DistinguishedName, Error,
    SignatureScheme,
};

use super::revocation_was_unanswered;

/// Install the wrapped verifier on the blocking client builder.
///
/// The error arm is very nearly unreachable — on Android `Verifier::new` returns
/// `Ok` unconditionally, and the only other fallible call is
/// `with_protocol_versions`, which fails on an empty version list — but it is a
/// `Result` and pretending otherwise would be worse than handling it. Handing
/// the builder back unchanged leaves the plain platform verifier `reqwest` would
/// have built for itself: broken for public CAs, exactly as before this file
/// existed, never less safe.
///
/// The failure that *can* really happen is not caught here and is not ours to
/// catch: `tls_backend_preconfigured` takes `impl Any` and downcasts at run
/// time, so a future rustls major that leaves `reqwest` and this crate on
/// different copies of the crate still compiles and fails inside
/// `Client::build()` instead. `cloud/client.rs` logs that one.
///
/// Worth knowing, because it is nowhere else in the tree: the private-CA users
/// this app supports were never hit by the bug at all. With nothing stapled and
/// an anchor that is not an OS-shipped root, upstream returns `Ok` before it
/// ever reaches its revocation pass, so a self-hosted CA never produced a
/// `Revoked` in the first place.
pub(super) fn configure(builder: ClientBuilder) -> ClientBuilder {
    match client_config() {
        Ok(config) => builder.tls_backend_preconfigured(config),
        Err(e) => {
            log::error!(
                "tls: could not install the Android revocation wrapper ({e}) — \
                 falling back to the platform verifier as-is; requests to a server \
                 whose certificate publishes no OCSP responder will fail as \"Revoked\""
            );
            builder
        }
    }
}

/// Build the `ClientConfig` that `reqwest` would have built, with our verifier
/// in place of the bare platform one.
///
/// Handing `reqwest` a finished config means everything it normally applies on
/// its own path is now ours to set, because it consumes a preconfigured backend
/// verbatim. Two of those matter:
///
/// * **The crypto provider.** Nothing in this app installs a process default, so
///   `ClientConfig::builder()` would fall through to
///   `get_default_or_install_from_crate_features()`, which *panics* if the
///   feature set is ambiguous. Resolving the provider the way `reqwest` does and
///   going in through `builder_with_provider` sidesteps that and guarantees we
///   use the very provider `reqwest` would have used — `aws-lc-rs`, which both
///   `reqwest` and this crate's own `rustls` dependency ask for by name.
/// * **ALPN.** On the preconfigured path `reqwest` sets no protocols at all. We
///   build it with `default-features = false` and no `http2`, so the list it
///   would have chosen for itself is `http/1.1` alone, and that is what is set
///   below. **If `reqwest`'s `http2` feature is ever enabled, that list must gain
///   `h2`** — otherwise desktop negotiates HTTP/2 and Android alone quietly does
///   not.
///
/// TLS versions are `ALL_VERSIONS`, matching `reqwest` with no min/max version
/// configured, and SNI stays on by default — the same as `config.tls_sni`.
fn client_config() -> Result<ClientConfig, Error> {
    // Allow a runtime default if something ever installs one; otherwise ship the
    // same provider reqwest ships. Mirrors reqwest's own resolution exactly.
    let provider = CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider()));

    let inner = rustls_platform_verifier::Verifier::new(Arc::clone(&provider))?;

    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(rustls::ALL_VERSIONS)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(UnansweredRevocation { inner }))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

/// The platform verifier, plus one exception for the verdict it cannot express:
/// "I had no way to find out". Named for what it tolerates, so that a reader who
/// meets it in a stack trace knows immediately that it is not a blanket bypass.
#[derive(Debug)]
struct UnansweredRevocation {
    inner: rustls_platform_verifier::Verifier,
}

impl ServerCertVerifier for UnansweredRevocation {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        // The platform always runs first, and its verdict is what we return in
        // every case but one. In particular a *revoked* on a certificate that
        // does publish a responder falls through the `other` arm untouched: that
        // is a real answer from a real responder and it must still be refused.
        match self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Err(Error::InvalidCertificate(CertificateError::Revoked))
                if revocation_was_unanswered(ocsp_response, end_entity) =>
            {
                // Never silent. One line per occurrence, naming the server, so
                // that a "why did this connect?" question has an answer in the
                // log rather than in this file's git history.
                log::warn!(
                    "tls: Android reported \"revoked\" for {} but the server stapled no OCSP \
                     response and the certificate names no OCSP responder, so Android's \
                     revocation checker had nothing it could ask. Treating this as its \
                     missing-responder failure rather than as a revocation; the chain \
                     itself was accepted by the system trust store, and the hostname is \
                     being verified here because the Android verifier never does it.",
                    server_name.to_str()
                );

                // **The load-bearing line** (see the module doc, fact 2).
                // Android validated the chain but not the name, and upstream
                // only checks the name on its `Ok` arm — which we are not on.
                // Without this we would accept a valid certificate issued for
                // another host. Copied verbatim from upstream's own `Ok` arm,
                // including the asymmetric paths: `verify_server_name` is
                // exported from `rustls::client`, `ParsedCertificate` from
                // `rustls::server`. A malformed certificate turns into
                // `BadEncoding` through `?` and is refused, never accepted.
                rustls::client::verify_server_name(
                    &rustls::server::ParsedCertificate::try_from(end_entity)?,
                    server_name,
                )?;
                Ok(ServerCertVerified::assertion())
            }
            other => other,
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }

    // The two defaulted methods. Upstream's Android verifier overrides neither,
    // so forwarding them is a no-op today — but a wrapper that answers for
    // itself is a wrapper that silently diverges the day upstream stops taking
    // the default. Delegate everything; override only what this file is for.
    fn requires_raw_public_keys(&self) -> bool {
        self.inner.requires_raw_public_keys()
    }

    fn root_hint_subjects(&self) -> Option<&[DistinguishedName]> {
        self.inner.root_hint_subjects()
    }
}
