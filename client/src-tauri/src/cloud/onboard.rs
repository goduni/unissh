//! Path B device-to-device onboarding: the PAKE choreography over the server relay.
//!
//! The initiator (an existing, authenticated device) and the responder (a new,
//! keyless device) exchange three PAKE messages through the untrusted relay,
//! keyed by a short OOB code carried on a trusted side channel (the pairing
//! payload / QR). The relay only shuttles opaque blobs — the sealed keyset is
//! encrypted under the PAKE-derived channel key, so the server never sees it.
//!
//! ```text
//!   initiator                         relay                      responder
//!   start(code) -> msg1 ---- POST msg1 ----> [msg1] ---- poll ---->
//!                  <---- poll msg2 ---- [msg2] <---- POST msg2 ---- respond(code,msg1) -> msg2
//!   confirm_and_seal(msg2) -> msg3 -- POST msg3 -> [msg3] -- poll -> finish_install(msg3)
//! ```

use std::thread::sleep;
use std::time::Duration;

use unissh_ffi as ffi;
use unissh_ffi::{OnboardInitiatorHandle, OnboardResponderHandle};

use crate::cloud::identity;
use crate::error::{ApiError, ApiResult};

/// Relay poll cadence and budget. The relay channel TTL is ~120s server-side, so
/// the whole exchange must complete inside it.
const POLL_INTERVAL: Duration = Duration::from_millis(700);
const POLL_BUDGET: Duration = Duration::from_secs(110);

/// Poll a relay slot until it is filled or the budget runs out. Propagates real
/// errors (e.g. the channel expiring → `gone`) immediately.
fn poll_until(
    http: &reqwest::blocking::Client,
    base_url: &str,
    channel_id: &str,
    want: &str,
) -> ApiResult<Vec<u8>> {
    let max_iters = (POLL_BUDGET.as_millis() / POLL_INTERVAL.as_millis()).max(1);
    for _ in 0..max_iters {
        if let Some(msg) = identity::relay_poll(http, base_url, channel_id, want)? {
            return Ok(msg);
        }
        sleep(POLL_INTERVAL);
    }
    Err(ApiError::Server {
        code: "timeout".into(),
        message: format!("onboarding: timed out waiting for {want}"),
    })
}

/// Initiator side (existing device): post msg1, await msg2, seal, post msg3.
/// The relay channel must already be open and shared with the responder.
pub fn initiator_complete(
    core: &ffi::Core,
    http: &reqwest::blocking::Client,
    base_url: &str,
    channel_id: &str,
    oob_code: Vec<u8>,
    secret_key_hex: String,
) -> ApiResult<()> {
    let handle = OnboardInitiatorHandle::start(oob_code);
    let msg1 = handle.msg();
    identity::relay_post(http, base_url, channel_id, "msg1", &msg1)?;

    let msg2 = poll_until(http, base_url, channel_id, "msg2")?;
    // Seal the keyset secrets + this device's (shared) Secret Key for the new device.
    let msg3 = core
        .onboard_confirm_and_seal(handle, msg2, secret_key_hex)
        .map_err(ApiError::from)?;
    identity::relay_post(http, base_url, channel_id, "msg3", &msg3)?;
    Ok(())
}

/// Responder side (new device): await msg1, post msg2, await msg3, install the
/// sealed keyset (opens the local instance). Requires no prior local state.
pub fn responder_join(
    core: &ffi::Core,
    http: &reqwest::blocking::Client,
    base_url: &str,
    channel_id: &str,
    oob_code: Vec<u8>,
    password: Option<String>,
) -> ApiResult<()> {
    let msg1 = poll_until(http, base_url, channel_id, "msg1")?;
    let handle = OnboardResponderHandle::respond(oob_code, msg1).map_err(ApiError::from)?;
    let msg2 = handle.msg();
    identity::relay_post(http, base_url, channel_id, "msg2", &msg2)?;

    let msg3 = poll_until(http, base_url, channel_id, "msg3")?;
    let secret_key_hex = core
        .onboard_finish_install(handle, msg3, password)
        .map_err(ApiError::from)?;
    // Persist the SHARED account Secret Key to THIS device's OS keychain so future
    // unlocks (and auto-unlock) work. Stays inside Rust — never returned to JS.
    // Best-effort: a keychain-write failure (or a no-op on mobile) just means the
    // user re-enters their account Secret Key next launch; the join itself stands.
    if let Err(e) = crate::keychain::keychain_save_secret_key(secret_key_hex) {
        log::warn!("onboard: failed to persist shared Secret Key to keychain: {e:?}");
    }
    Ok(())
}
