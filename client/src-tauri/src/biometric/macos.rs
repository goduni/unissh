//! macOS: the device secret in a Touch ID-gated Keychain item.
//!
//! One generic-password item (`me.goduni.unissh` / `biometric-device-secret`) in
//! the **data-protection** Keychain, created with an access-control object of
//! `kSecAccessControlBiometryCurrentSet` and protection
//! `WhenPasscodeSetThisDeviceOnly`:
//!
//! * reading its data requires Touch ID;
//! * enrolling or removing a finger invalidates it for good — that is what
//!   "current set" means, and it is why a re-enrolment asks the user to enable
//!   biometric unlock again rather than letting a newly added finger in;
//! * `ThisDeviceOnly` keeps it out of backups and iCloud Keychain, and removing
//!   the Mac's login password destroys it.
//!
//! **Detecting a re-enrolment deterministically.** An invalidated item is not
//! reliably reported as such: an attribute-only lookup does not evaluate the data
//! ACL, and a read can fail with the same `errSecAuthFailed` a bad finger gives.
//! So two signals are used, neither of which is a guess:
//!
//! 1. The biometric **domain state** — a hash LocalAuthentication changes
//!    whenever the enrolled set changes — is recorded on the item at creation
//!    (`kSecAttrGeneric`; not secret) and compared with the current one: before a
//!    prompt, from `canEvaluatePolicy` (no prompt), and after the match. A
//!    mismatch means the item was made for a different set of fingers.
//!    `LAContext.domainState.biometry.stateHash` is used on macOS 15+, the
//!    deprecated `evaluatedPolicyDomainState` before; the stored value is tagged
//!    with which API produced it, and values from different APIs are never
//!    compared (an OS upgrade across 15 then simply skips this signal). Apple
//!    warns the value may change across major OS versions; then the user is
//!    asked to re-enable once, which is the safe direction.
//! 2. The policy is **evaluated first** (that is the prompt, with the caller's
//!    reason), and the item is then read with that already-authenticated context.
//!    A read that fails authentication after a successful match cannot be a bad
//!    finger: the item is dead.
//!
//! **The presence gate** (Secret-Key-only vaults) is `evaluatePolicy` alone, on
//! a fresh context, with no Keychain item behind it. It therefore needs no
//! entitlement and works on a build the protected Keychain refuses; it proves
//! only that an enrolled finger was there when it was asked.
//!
//! Everything else — a closed lid, a lockout, `errSecMissingEntitlement`, an
//! unmapped status — never wipes (see the module note in `biometric.rs`).
//!
//! The raw `SecItem*` calls are used instead of security-framework's `passwords`
//! helpers because those cannot attach an authentication context or return the
//! attributes alongside the data. `keyring` is untouched and keeps serving the
//! Secret Key item.
//!
//! **Status codes this file turns into meaning** (from `SecBase.h`):
//! `errSecUserCanceled` (-128); `errSecAuthFailed` (-25293); `errSecItemNotFound`
//! (-25300); `errSecInteractionNotAllowed` (-25308, the non-interactive probe's
//! "it exists, and would need Touch ID"); `errSecMissingEntitlement` (-34018, a
//! build that may not use the data-protection Keychain: Apple ties it to a signed
//! app with a keychain-access-group entitlement, which an unsigned or ad-hoc
//! bundle does not have — the feature is then `Unsupported` and not offered).
//!
//! None of this is unit-testable — every path ends in a system prompt or a
//! Keychain the test runner does not have. It is checked by hand on a Mac.

use std::ffi::c_void;
use std::sync::mpsc;

use block2::RcBlock;
use core_foundation::base::{CFType, CFTypeRef, TCFType};
use core_foundation::boolean::CFBoolean;
use core_foundation::data::CFData;
use core_foundation::dictionary::CFDictionary;
use core_foundation::string::{CFString, CFStringRef};
use objc2::rc::Retained;
use objc2::runtime::Bool;
use objc2_foundation::{NSError, NSString};
use objc2_local_authentication::{LAContext, LAPolicy};
use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework::random::SecRandom;
use security_framework_sys::access_control::kSecAccessControlBiometryCurrentSet;
use security_framework_sys::item::{
    kSecAttrAccessControl, kSecAttrAccount, kSecAttrLabel, kSecAttrService, kSecClass,
    kSecClassGenericPassword, kSecReturnAttributes, kSecReturnData, kSecUseAuthenticationContext,
    kSecUseDataProtectionKeychain, kSecValueData,
};
use security_framework_sys::keychain_item::{SecItemAdd, SecItemCopyMatching, SecItemDelete};
use zeroize::Zeroizing;

use super::{DeviceSecretStore, SecretError, SecretState};

// `kSecAttrGeneric` (user-defined data on a generic password) is exported by
// Security.framework but not declared by security-framework-sys 2.17.
#[link(name = "Security", kind = "framework")]
extern "C" {
    static kSecAttrGeneric: CFStringRef;
}

const SERVICE: &str = "me.goduni.unissh";
const ACCOUNT: &str = "biometric-device-secret";
const LABEL: &str = "UniSSH biometric unlock";
const SECRET_LEN: usize = 32;

const ERR_SEC_SUCCESS: i32 = 0;
const ERR_SEC_USER_CANCELED: i32 = -128;
const ERR_SEC_AUTH_FAILED: i32 = -25_293;
const ERR_SEC_ITEM_NOT_FOUND: i32 = -25_300;
const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25_308;
const ERR_SEC_MISSING_ENTITLEMENT: i32 = -34_018;

/// `LAError` codes meaning "this Mac cannot do Touch ID right now": no login
/// password (-5), no sensor reachable — including a closed lid — (-6), nothing
/// enrolled (-7). Never a reason to wipe.
const LA_ERROR_UNAVAILABLE: [isize; 3] = [-5, -6, -7];

/// Domain-state tags: which API produced a stored hash.
const TAG_LEGACY: u8 = 0;
const TAG_DOMAIN_STATE: u8 = 1;

pub(super) struct TouchId;

/// `kSec*` keys are `CFStringRef` statics; wrap one for a dictionary.
fn key(k: CFStringRef) -> CFString {
    // SAFETY: the Security framework's constants are valid, immortal CFStrings.
    unsafe { CFString::wrap_under_get_rule(k) }
}

/// The attributes that name the item, plus "data-protection Keychain".
fn item() -> Vec<(CFString, CFType)> {
    // SAFETY: reading an `extern` static exported by Security.framework.
    let class = unsafe { kSecClass };
    // SAFETY: reading an `extern` static exported by Security.framework.
    let generic_password = unsafe { kSecClassGenericPassword };
    // SAFETY: reading an `extern` static exported by Security.framework.
    let service = unsafe { kSecAttrService };
    // SAFETY: reading an `extern` static exported by Security.framework.
    let account = unsafe { kSecAttrAccount };
    // SAFETY: reading an `extern` static exported by Security.framework.
    let data_protection = unsafe { kSecUseDataProtectionKeychain };
    vec![
        (key(class), key(generic_password).into_CFType()),
        (key(service), CFString::new(SERVICE).into_CFType()),
        (key(account), CFString::new(ACCOUNT).into_CFType()),
        (key(data_protection), CFBoolean::true_value().into_CFType()),
    ]
}

fn yes(query: &mut Vec<(CFString, CFType)>, k: CFStringRef) {
    query.push((key(k), CFBoolean::true_value().into_CFType()));
}

/// Attach an `LAContext`. Every Objective-C object is a valid `CFTypeRef`
/// (toll-free bridging covers retain/release), and the dictionary retains it for
/// as long as the query lives.
fn with_context(mut query: Vec<(CFString, CFType)>, ctx: &LAContext) -> Vec<(CFString, CFType)> {
    // SAFETY: `ctx` is a live Objective-C object; wrapping under the get rule
    // takes our own +1, released when the CFType drops.
    let value = unsafe { CFType::wrap_under_get_rule(std::ptr::from_ref(ctx).cast()) };
    // SAFETY: reading an `extern` static exported by Security.framework.
    let context_key = unsafe { kSecUseAuthenticationContext };
    query.push((key(context_key), value));
    query
}

fn copy_matching(query: &[(CFString, CFType)]) -> (i32, Option<CFType>) {
    let dict = CFDictionary::from_CFType_pairs(query);
    let mut out: CFTypeRef = std::ptr::null();
    // SAFETY: `dict` is a valid dictionary; `out` receives a +1 reference (or
    // stays null), which `wrap_under_create_rule` takes ownership of.
    let status = unsafe { SecItemCopyMatching(dict.as_concrete_TypeRef(), &mut out) };
    // SAFETY: a non-null `out` is the +1 reference SecItemCopyMatching handed
    // us; the create rule takes ownership of exactly that reference.
    let value = (!out.is_null()).then(|| unsafe { CFType::wrap_under_create_rule(out) });
    (status, value)
}

/// A `CFData` value out of an attributes dictionary returned by the Keychain.
fn dict_bytes(dict: &CFDictionary, k: CFStringRef) -> Option<Vec<u8>> {
    let v = dict.find(k.cast::<c_void>())?;
    // SAFETY: the value is a live CF object owned by `dict`; get rule = +1 of ours.
    let v = unsafe { CFType::wrap_under_get_rule(*v) };
    v.downcast_into::<CFData>().map(|d| d.bytes().to_vec())
}

fn new_context() -> Retained<LAContext> {
    // SAFETY: `+[LAContext new]` has no preconditions.
    unsafe { LAContext::new() }
}

/// Preflight on `ctx`: can Touch ID be used now? Lockout (-8) counts as yes —
/// the sensor is there and will come back. A successful preflight also fills in
/// the context's domain state, which is what lets `state()` compare it without a
/// prompt.
fn biometry_available(ctx: &LAContext) -> bool {
    // SAFETY: plain preflight query on a context we own.
    match unsafe { ctx.canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthenticationWithBiometrics) }
    {
        Ok(()) => true,
        Err(e) => !LA_ERROR_UNAVAILABLE.contains(&e.code()),
    }
}

/// The tagged biometric domain-state hash of `ctx`, after a preflight or an
/// evaluation; `None` when the system has none to give (e.g. locked out).
fn domain_hash(ctx: &LAContext) -> Option<Vec<u8>> {
    let (tag, data) = if objc2::available!(macos = 15.0) {
        // SAFETY: `domainState` exists from macOS 15, checked just above.
        let hash = unsafe { ctx.domainState().biometry().stateHash() };
        (TAG_DOMAIN_STATE, hash?)
    } else {
        #[expect(
            deprecated,
            reason = "evaluatedPolicyDomainState is the only domain-state API before macOS 15; the domainState branch above handles 15+"
        )]
        // SAFETY: plain property read; the replacement above is not available.
        let hash = unsafe { ctx.evaluatedPolicyDomainState() };
        (TAG_LEGACY, hash?)
    };
    let mut out = vec![tag];
    out.extend_from_slice(&data.to_vec());
    Some(out)
}

/// The enrolled set provably changed since the item was made: both hashes
/// known, produced by the same API, and different. Anything less is not proof.
fn enrolment_changed(stored: Option<&[u8]>, current: Option<&[u8]>) -> bool {
    match (stored, current) {
        (Some(s), Some(c)) => s.first() == c.first() && s != c,
        _ => false,
    }
}

/// What a failed evaluation means. Unavailable (no password, no sensor or lid
/// closed, nothing enrolled) is not a cancel: the setting says why instead.
fn evaluation_error(code: isize) -> SecretError {
    match code {
        c if LA_ERROR_UNAVAILABLE.contains(&c) => SecretError::Unsupported,
        // Failed match (-1), cancel (-2), fallback (-3), system/app cancel
        // (-4, -9), lockout (-8): the password, this time; keep everything.
        -1 | -2 | -3 | -4 | -8 | -9 => SecretError::Cancelled,
        c => SecretError::Failed(format!("Touch ID evaluation failed: LAError {c}")),
    }
}

/// Show the Touch ID prompt with `reason` on `ctx` and wait for the answer.
/// Called on a blocking thread; the reply arrives on a LocalAuthentication queue.
fn evaluate(ctx: &LAContext, reason: &str) -> Result<(), isize> {
    let (tx, rx) = mpsc::channel::<Result<(), isize>>();
    let reply = RcBlock::new(move |ok: Bool, err: *mut NSError| {
        let result = if ok.as_bool() {
            Ok(())
        } else if err.is_null() {
            Err(0)
        } else {
            // SAFETY: LocalAuthentication passes a valid NSError when it fails.
            Err(unsafe { (*err).code() })
        };
        // The receiver is gone only if `evaluate` already returned, in which
        // case nobody is waiting for this answer.
        if tx.send(result).is_err() {
            log::debug!("biometric: Touch ID reply arrived after the waiter left");
        }
    });
    // SAFETY: the reply block is `Send`-safe (it only owns an mpsc Sender), as
    // the method requires; the reason is a valid NSString.
    unsafe {
        ctx.evaluatePolicy_localizedReason_reply(
            LAPolicy::DeviceOwnerAuthenticationWithBiometrics,
            &NSString::from_str(reason),
            &reply,
        );
    }
    rx.recv().unwrap_or(Err(0))
}

impl DeviceSecretStore for TouchId {
    /// Without a prompt: the item's attributes are read through a context that
    /// forbids interaction, so an item that would need Touch ID answers
    /// `errSecInteractionNotAllowed` instead of asking.
    fn state(&self) -> SecretState {
        let ctx = new_context();
        if !biometry_available(&ctx) {
            return SecretState::Unsupported;
        }
        let current = domain_hash(&ctx);
        let probe = new_context();
        // SAFETY: setter on a fresh context we own.
        unsafe { probe.setInteractionNotAllowed(true) };
        let mut query = with_context(item(), &probe);
        // SAFETY: reading an `extern` static exported by Security.framework.
        yes(&mut query, unsafe { kSecReturnAttributes });
        let (status, value) = copy_matching(&query);
        match status {
            ERR_SEC_SUCCESS => {
                let stored = value
                    .and_then(|v| v.downcast_into::<CFDictionary>())
                    // SAFETY: reading an `extern` static declared above.
                    .and_then(|d| dict_bytes(&d, unsafe { kSecAttrGeneric }));
                if enrolment_changed(stored.as_deref(), current.as_deref()) {
                    SecretState::Absent
                } else {
                    SecretState::Present
                }
            }
            ERR_SEC_INTERACTION_NOT_ALLOWED => SecretState::Present,
            ERR_SEC_ITEM_NOT_FOUND => SecretState::Absent,
            ERR_SEC_MISSING_ENTITLEMENT => SecretState::Unsupported,
            other => {
                log::warn!("biometric: Keychain probe returned OSStatus {other}");
                SecretState::Unknown
            }
        }
    }

    fn create(&self) -> Result<Zeroizing<Vec<u8>>, SecretError> {
        let ctx = new_context();
        if !biometry_available(&ctx) {
            return Err(SecretError::Unsupported);
        }
        let enrolment = domain_hash(&ctx);
        self.delete()?;
        let mut secret = Zeroizing::new(vec![0u8; SECRET_LEN]);
        SecRandom::default()
            .copy_bytes(&mut secret)
            .map_err(|e| SecretError::Failed(format!("system RNG failed: {e}")))?;
        let access = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleWhenPasscodeSetThisDeviceOnly),
            kSecAccessControlBiometryCurrentSet,
        )
        .map_err(|e| SecretError::Failed(format!("access control: OSStatus {}", e.code())))?;
        let mut attrs = item();
        // SAFETY: reading an `extern` static exported by Security.framework.
        let label = unsafe { kSecAttrLabel };
        // SAFETY: reading an `extern` static exported by Security.framework.
        let access_control = unsafe { kSecAttrAccessControl };
        // SAFETY: reading an `extern` static exported by Security.framework.
        let generic = unsafe { kSecAttrGeneric };
        // SAFETY: reading an `extern` static exported by Security.framework.
        let value_data = unsafe { kSecValueData };
        attrs.push((key(label), CFString::new(LABEL).into_CFType()));
        attrs.push((key(access_control), access.into_CFType()));
        if let Some(hash) = &enrolment {
            attrs.push((key(generic), CFData::from_buffer(hash).into_CFType()));
        }
        // The one copy we cannot zeroize: CFData owns its buffer.
        attrs.push((key(value_data), CFData::from_buffer(&secret).into_CFType()));
        let dict = CFDictionary::from_CFType_pairs(&attrs);
        // SAFETY: valid attribute dictionary; no result is requested.
        match unsafe { SecItemAdd(dict.as_concrete_TypeRef(), std::ptr::null_mut()) } {
            ERR_SEC_SUCCESS => Ok(secret),
            ERR_SEC_MISSING_ENTITLEMENT => Err(SecretError::Unsupported),
            other => Err(SecretError::Failed(format!(
                "storing the Touch ID secret failed: OSStatus {other}"
            ))),
        }
    }

    fn read(&self, reason: &str) -> Result<Zeroizing<Vec<u8>>, SecretError> {
        // No prompt for an item that is provably dead or cannot be used here.
        match self.state() {
            SecretState::Unsupported => return Err(SecretError::Unsupported),
            SecretState::Absent => return Err(SecretError::Invalidated),
            SecretState::Present | SecretState::Unknown => {}
        }
        let ctx = new_context();
        evaluate(&ctx, reason).map_err(evaluation_error)?;
        let current = domain_hash(&ctx);
        let mut query = with_context(item(), &ctx);
        // SAFETY: reading an `extern` static exported by Security.framework.
        yes(&mut query, unsafe { kSecReturnData });
        // SAFETY: reading an `extern` static exported by Security.framework.
        yes(&mut query, unsafe { kSecReturnAttributes });
        let (status, value) = copy_matching(&query);
        match status {
            ERR_SEC_SUCCESS => {
                let dict = value
                    .and_then(|v| v.downcast_into::<CFDictionary>())
                    .ok_or_else(|| SecretError::Failed("Keychain returned no item".into()))?;
                // SAFETY: reading an `extern` static exported by Security.framework.
                let stored = dict_bytes(&dict, unsafe { kSecAttrGeneric });
                if enrolment_changed(stored.as_deref(), current.as_deref()) {
                    return Err(SecretError::Invalidated);
                }
                // SAFETY: reading an `extern` static exported by Security.framework.
                let data = dict_bytes(&dict, unsafe { kSecValueData })
                    .ok_or_else(|| SecretError::Failed("Keychain returned no data".into()))?;
                Ok(Zeroizing::new(data))
            }
            ERR_SEC_USER_CANCELED => Err(SecretError::Cancelled),
            // The match on this very context just succeeded, so an item that
            // still refuses it is dead, not a bad finger.
            ERR_SEC_AUTH_FAILED | ERR_SEC_ITEM_NOT_FOUND => Err(SecretError::Invalidated),
            ERR_SEC_MISSING_ENTITLEMENT => Err(SecretError::Unsupported),
            other => Err(SecretError::Failed(format!(
                "reading the Touch ID secret failed: OSStatus {other}"
            ))),
        }
    }

    fn delete(&self) -> Result<(), SecretError> {
        let dict = CFDictionary::from_CFType_pairs(&item());
        // SAFETY: valid query dictionary.
        match unsafe { SecItemDelete(dict.as_concrete_TypeRef()) } {
            // Nothing there, or a build that could never have stored one.
            ERR_SEC_SUCCESS | ERR_SEC_ITEM_NOT_FOUND | ERR_SEC_MISSING_ENTITLEMENT => Ok(()),
            other => Err(SecretError::Failed(format!(
                "deleting the Touch ID secret failed: OSStatus {other}"
            ))),
        }
    }

    fn presence_available(&self) -> bool {
        biometry_available(&new_context())
    }

    /// The prompt and nothing else: no Keychain item is made or read.
    fn confirm_presence(&self, reason: &str) -> Result<(), SecretError> {
        evaluate(&new_context(), reason).map_err(evaluation_error)
    }
}
