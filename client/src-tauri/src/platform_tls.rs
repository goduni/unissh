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
