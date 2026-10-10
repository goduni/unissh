//! Deterministic mutation tests for the hostile-byte decoders of `unissh-sync`.
//!
//! Each test builds a valid encoding with the crate's own public encoder, applies a fixed
//! number of rounds of one to three random mutations (truncate, extend, flip a bit, overwrite
//! a 2/4/8-byte big-endian window with 0, MAX, a top-bit-only or a random value), and feeds the
//! result to the public decoder. The decoder may return `Ok` or `Err`, but it must never
//! panic (tests run in debug, so integer overflow counts) and never request a single
//! allocation above `ALLOC_CAP` (the capped global allocator refuses it, which aborts the
//! binary with "memory allocation of N bytes failed"). This is not a coverage-guided fuzzer:
//! the PRNG is a fixed-seed xorshift64*, so every run explores the same inputs and a failure
//! reproduces exactly; it complements, not replaces, the hand-written truncation tests. To
//! explore further locally, raise the iteration count or change the seed, e.g.
//! `MUTATION_ITERATIONS=200000 MUTATION_SEED=7 cargo test -p unissh-sync --test mutation`.

#![expect(
    clippy::unwrap_used,
    reason = "integration-test helpers; allow-*-in-tests covers only #[test] fns and cfg(test) modules"
)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::panic::{catch_unwind, AssertUnwindSafe};

/// Default number of mutated inputs per decoder (override: `MUTATION_ITERATIONS`).
const ITERATIONS: u64 = 2_000;
/// Default PRNG seed (override: `MUTATION_SEED`).
const SEED: u64 = 0x5EED_D3C0_DE25_0001;
/// The largest single allocation any decoder here may request. Legitimate inputs are a few
/// hundred bytes; a length field read as a capacity is what crosses this.
const ALLOC_CAP: usize = 64 << 20;

/// Forwards to `System`, but refuses any single request above [`ALLOC_CAP`]. A refused
/// request aborts the test binary with "memory allocation of N bytes failed", which turns
/// an absurd length-driven allocation into a loud, deterministic failure on every machine.
struct CappedAlloc;

#[expect(
    unsafe_code,
    reason = "a global allocator is an unsafe trait impl; it only forwards to System or refuses"
)]
// SAFETY: every call forwards to `System` with the caller's layout unchanged; returning null
// for an oversize request is the documented way for `alloc` to report failure.
unsafe impl GlobalAlloc for CappedAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.size() > ALLOC_CAP {
            return std::ptr::null_mut();
        }
        // SAFETY: the caller upholds `alloc`'s contract for `layout`; it is passed on unchanged.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: every block handed out above came from `System.alloc` with this `layout`.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: CappedAlloc = CappedAlloc;

/// xorshift64* (Vigna): tiny, deterministic, good enough to pick mutations.
struct Rng(u64);

impl Rng {
    const fn new(seed: u64) -> Self {
        // xorshift has a fixed point at zero.
        Self(seed | 1)
    }

    const fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Uniform-ish in `0..n`; `n` must be non-zero.
    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next_u64() % u64::try_from(n).unwrap()).unwrap()
    }

    fn byte(&mut self) -> u8 {
        u8::try_from(self.next_u64() >> 56).unwrap()
    }
}

/// Overwrites a random `width`-byte window with a big-endian 0, MAX, top-bit-only or random value.
fn overwrite_field(rng: &mut Rng, out: &mut [u8], width: usize) {
    if out.len() < width {
        return;
    }
    let at = rng.below(out.len() - width + 1);
    let value = match rng.below(4) {
        0 => 0,
        1 => u64::MAX,
        2 => 1_u64 << (8 * width - 1),
        _ => rng.next_u64(),
    };
    let bytes = value.to_be_bytes();
    if let (Some(dst), Some(src)) = (out.get_mut(at..at + width), bytes.get(8 - width..)) {
        dst.copy_from_slice(src);
    }
}

/// Applies one to three random mutations to a copy of `valid`.
fn mutate(rng: &mut Rng, valid: &[u8]) -> Vec<u8> {
    let mut out = valid.to_vec();
    for _ in 0..=rng.below(3) {
        match rng.below(6) {
            0 => out.truncate(rng.below(out.len() + 1)),
            1 => {
                for _ in 0..=rng.below(16) {
                    out.push(rng.byte());
                }
            }
            2 => {
                let at = rng.below(out.len().max(1));
                let bit = rng.below(8);
                if let Some(b) = out.get_mut(at) {
                    *b ^= 1 << bit;
                }
            }
            3 => overwrite_field(rng, &mut out, 2),
            4 => overwrite_field(rng, &mut out, 4),
            _ => overwrite_field(rng, &mut out, 8),
        }
    }
    out
}

fn env_or(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Feeds mutations of `valid` to `decode` (which reports whether it accepted the input) and
/// fails with the offending bytes if the decoder panics.
fn check_decoder(valid: &[u8], decode: impl Fn(&[u8]) -> bool) {
    assert!(decode(valid), "the unmutated input must decode");
    let mut rng = Rng::new(env_or("MUTATION_SEED", SEED));
    for iteration in 0..env_or("MUTATION_ITERATIONS", ITERATIONS) {
        let input = mutate(&mut rng, valid);
        let outcome = catch_unwind(AssertUnwindSafe(|| decode(&input)));
        assert!(
            outcome.is_ok(),
            "decoder panicked at iteration {iteration} on input {}",
            hex(&input)
        );
    }
}

use unissh_storage::{
    CachePolicy, ItemRecord, MemberRole, MembershipGrant, MembershipManifest, SyncTarget,
    VaultRecord,
};
use unissh_sync::{AccountStateObject, AuditObject, SyncObject};

/// One valid object per wire tag, so every field reader of `from_bytes` is reached.
fn objects() -> Vec<SyncObject> {
    vec![
        SyncObject::Vault(VaultRecord {
            vault_id: b"v1".to_vec(),
            sync_target: SyncTarget::Cloud,
            name_blob: vec![1, 2, 3],
            wrapped_vk: vec![4, 5, 6],
            version: 7,
            tombstone: false,
            signature: vec![9_u8; 67],
            author_pubkey: vec![0_u8; 32],
            key_epoch: 2,
            cache_policy: CachePolicy::OfflineAllowed,
            sync_tenant: Vec::new(),
        }),
        SyncObject::Item(ItemRecord {
            vault_id: b"v1".to_vec(),
            item_id: b"i1".to_vec(),
            item_type: 42,
            content_blob: vec![1, 2, 3, 4],
            wrapped_item_key: vec![5, 6],
            version: 9,
            tombstone: true,
            signature: vec![7_u8; 67],
            author_pubkey: vec![8_u8; 32],
            created_at: 0,
            updated_at: 0,
            key_epoch: 3,
        }),
        SyncObject::MembershipManifest(MembershipManifest {
            vault_id: b"v1".to_vec(),
            key_epoch: 1,
            manifest_blob: vec![1, 2, 3],
            signature: vec![4_u8; 67],
            author_pubkey: vec![5_u8; 32],
        }),
        SyncObject::MembershipGrant(MembershipGrant {
            vault_id: b"v1".to_vec(),
            member_pubkey: vec![3_u8; 32],
            key_epoch: 4,
            role: MemberRole::Editor,
            not_after: -5,
            wrapped_vk: vec![6, 7],
            signature: vec![8_u8; 67],
            author_pubkey: vec![9_u8; 32],
        }),
        SyncObject::Audit(AuditObject {
            vault_id: b"v1".to_vec(),
            entry_blob: vec![1, 2, 3],
            signature: vec![4_u8; 67],
            author_pubkey: vec![5_u8; 32],
        }),
        SyncObject::Keyset(vec![9, 9, 9]),
        SyncObject::AccountState(AccountStateObject {
            author_pubkey: vec![0xA_u8; 32],
            version: 12_345,
            payload: vec![1, 2, 3, 4, 5],
            signature: vec![0xB_u8; 67],
        }),
    ]
}

#[test]
fn sync_object_from_bytes_never_panics_on_mutated_input() {
    for object in objects() {
        let valid = object.to_bytes().unwrap();
        check_decoder(&valid, |b| SyncObject::from_bytes(b).is_ok());
    }
}
