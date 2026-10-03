//! macOS: the device secret in a Touch ID-gated Keychain item.
//!
//! One generic-password item (`me.goduni.unissh` / `biometric-device-secret`) in
//! the **data-protection** Keychain, created with an access-control object of
//! `kSecAccessControlBiometryCurrentSet` and protection
//! `WhenPasscodeSetThisDeviceOnly`:
//!
//! * reading its data requires Touch ID, and the prompt carries the reason the
//!   caller passes in, through an `LAContext` attached to the query;
//! * enrolling or removing a finger invalidates it for good — that is what
//!   "current set" means, and it is why a re-enrolment asks the user to enable
//!   biometric unlock again rather than letting a newly added finger in;
//! * `ThisDeviceOnly` keeps it out of backups and iCloud Keychain, and removing
//!   the Mac's login password destroys it.
//!
//! The raw `SecItem*` calls are used instead of security-framework's `passwords`
//! helpers because those cannot attach an authentication context to a query.
//! `keyring` is untouched and keeps serving the Secret Key item.
//!
//! **Status codes this file turns into meaning** (from `SecBase.h`):
//! `errSecUserCanceled` (-128) and `errSecAuthFailed` (-25293) are a dismissed or
//! failed prompt; `errSecItemNotFound` (-25300) on a read is an invalidated
//! secret; `errSecInteractionNotAllowed` (-25308) answers the non-interactive
//! probe with "it exists, and would need Touch ID"; `errSecMissingEntitlement`
//! (-34018) is a build that may not use the data-protection Keychain at all
//! (see the note on [`TouchId::state`]).
//!
//! None of this is unit-testable — every path ends in a system prompt or a
//! Keychain the test runner does not have. It is checked by hand on a Mac.

use core_foundation::base::{CFType, CFTypeRef, TCFType};
use core_foundation::boolean::CFBoolean;
use core_foundation::data::CFData;
use core_foundation::dictionary::CFDictionary;
use core_foundation::string::{CFString, CFStringRef};
use objc2::rc::Retained;
use objc2_foundation::NSString;
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

/// `LAError` codes `canEvaluatePolicy` reports for a Mac that cannot do Touch
/// ID: no sensor (-6), nothing enrolled (-7), no login password (-5). Lockout
/// (-8, too many failed matches) is deliberately absent: the sensor is there and
/// will come back, so the feature stays offered.
const LA_ERROR_UNAVAILABLE: [isize; 3] = [-5, -6, -7];

pub(super) struct TouchId;

/// `kSec*` keys are `CFStringRef` statics; wrap one for a dictionary.
fn key(k: CFStringRef) -> CFString {
    // SAFETY: the Security framework's constants are valid, immortal CFStrings.
    unsafe { CFString::wrap_under_get_rule(k) }
}

/// The attributes that name the item, plus "data-protection Keychain".
fn item() -> Vec<(CFString, CFType)> {
    // SAFETY: reading `extern` statics exported by Security.framework.
    unsafe {
        vec![
            (key(kSecClass), key(kSecClassGenericPassword).into_CFType()),
            (key(kSecAttrService), CFString::new(SERVICE).into_CFType()),
            (key(kSecAttrAccount), CFString::new(ACCOUNT).into_CFType()),
            (
                key(kSecUseDataProtectionKeychain),
                CFBoolean::true_value().into_CFType(),
            ),
        ]
    }
}

/// An `LAContext` as a dictionary value. Every Objective-C object is a valid
/// `CFTypeRef` (toll-free bridging covers retain/release), and the dictionary
/// retains it for as long as the query lives.
fn context_value(ctx: &LAContext) -> CFType {
    // SAFETY: `ctx` is a live Objective-C object; wrapping under the get rule
    // takes our own +1, released when the CFType drops.
    unsafe { CFType::wrap_under_get_rule(std::ptr::from_ref(ctx).cast()) }
}

fn with_context(mut query: Vec<(CFString, CFType)>, ctx: &LAContext) -> Vec<(CFString, CFType)> {
    // SAFETY: reading an `extern` static exported by Security.framework.
    query.push((
        key(unsafe { kSecUseAuthenticationContext }),
        context_value(ctx),
    ));
    query
}

fn copy_matching(query: &[(CFString, CFType)]) -> (i32, Option<CFType>) {
    let dict = CFDictionary::from_CFType_pairs(query);
    let mut out: CFTypeRef = std::ptr::null();
    // SAFETY: `dict` is a valid dictionary; `out` receives a +1 reference (or
    // stays null), which `wrap_under_create_rule` takes ownership of.
    let status = unsafe { SecItemCopyMatching(dict.as_concrete_TypeRef(), &mut out) };
    let value = (!out.is_null()).then(|| unsafe { CFType::wrap_under_create_rule(out) });
    (status, value)
}

fn new_context() -> Retained<LAContext> {
    // SAFETY: `+[LAContext new]` has no preconditions.
    unsafe { LAContext::new() }
}

impl TouchId {
    /// Can this Mac do Touch ID right now (sensor present, a finger enrolled, a
    /// login password set)?
    fn biometry_available() -> bool {
        let ctx = new_context();
        // SAFETY: plain preflight query on a fresh context.
        match unsafe {
            ctx.canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthenticationWithBiometrics)
        } {
            Ok(()) => true,
            Err(e) => !LA_ERROR_UNAVAILABLE.contains(&e.code()),
        }
    }
}

impl DeviceSecretStore for TouchId {
    /// Without a prompt: the item is looked up for its attributes only, through
    /// a context that forbids interaction, so an item that would need Touch ID
    /// answers `errSecInteractionNotAllowed` instead of asking.
    ///
    /// `errSecMissingEntitlement` means this build may not use the
    /// data-protection Keychain at all. Apple ties that Keychain to a signed app
    /// with a keychain-access-group entitlement backed by a provisioning profile,
    /// which an unsigned or ad-hoc-signed bundle does not have. Such a build
    /// reports `Unsupported` and the setting is simply not offered — the honest
    /// answer, rather than an option that fails when switched on.
    fn state(&self) -> SecretState {
        if !Self::biometry_available() {
            return SecretState::Unsupported;
        }
        let ctx = new_context();
        // SAFETY: setter on a fresh context we own.
        unsafe { ctx.setInteractionNotAllowed(true) };
        let mut query = with_context(item(), &ctx);
        // SAFETY: reading an `extern` static exported by Security.framework.
        query.push((
            key(unsafe { kSecReturnAttributes }),
            CFBoolean::true_value().into_CFType(),
        ));
        match copy_matching(&query).0 {
            ERR_SEC_SUCCESS | ERR_SEC_INTERACTION_NOT_ALLOWED => SecretState::Present,
            ERR_SEC_MISSING_ENTITLEMENT => SecretState::Unsupported,
            ERR_SEC_ITEM_NOT_FOUND => SecretState::Absent,
            other => {
                log::warn!("biometric: Keychain probe returned OSStatus {other}");
                SecretState::Absent
            }
        }
    }

    fn create(&self) -> Result<Zeroizing<Vec<u8>>, SecretError> {
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
        // SAFETY: reading `extern` statics exported by Security.framework.
        unsafe {
            attrs.push((key(kSecAttrLabel), CFString::new(LABEL).into_CFType()));
            attrs.push((key(kSecAttrAccessControl), access.into_CFType()));
            // The one copy we cannot zeroize: CFData owns its buffer.
            attrs.push((
                key(kSecValueData),
                CFData::from_buffer(&secret).into_CFType(),
            ));
        }
        let dict = CFDictionary::from_CFType_pairs(&attrs);
        // SAFETY: valid attribute dictionary; no result is requested.
        let status = unsafe { SecItemAdd(dict.as_concrete_TypeRef(), std::ptr::null_mut()) };
        match status {
            ERR_SEC_SUCCESS => Ok(secret),
            other => Err(SecretError::Failed(format!(
                "storing the Touch ID secret failed: OSStatus {other}"
            ))),
        }
    }

    fn read(&self, reason: &str) -> Result<Zeroizing<Vec<u8>>, SecretError> {
        let ctx = new_context();
        // SAFETY: setter on a fresh context we own.
        unsafe { ctx.setLocalizedReason(&NSString::from_str(reason)) };
        let mut query = with_context(item(), &ctx);
        // SAFETY: reading an `extern` static exported by Security.framework.
        query.push((
            key(unsafe { kSecReturnData }),
            CFBoolean::true_value().into_CFType(),
        ));
        let (status, value) = copy_matching(&query);
        match status {
            ERR_SEC_SUCCESS => {
                let data = value
                    .and_then(|v| v.downcast_into::<CFData>())
                    .ok_or_else(|| SecretError::Failed("Keychain returned no data".into()))?;
                Ok(Zeroizing::new(data.bytes().to_vec()))
            }
            ERR_SEC_USER_CANCELED => Err(SecretError::Cancelled),
            // A failed match and a secret that died under us can both surface
            // as an auth failure; only the latter leaves no item behind.
            ERR_SEC_AUTH_FAILED => match self.state() {
                SecretState::Present => Err(SecretError::Cancelled),
                _ => Err(SecretError::Invalidated),
            },
            ERR_SEC_ITEM_NOT_FOUND => Err(SecretError::Invalidated),
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
}
