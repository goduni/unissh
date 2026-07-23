//! First-open race regression (an integration test so it owns its process):
//! SQLCipher initializes process-global crypto state on the first keyed
//! connection, and several first-opens racing from different threads used to
//! observe it half-built — "sqlcipherCodecAttach: sqlcipher not initialized",
//! surfacing as a PRAGMA key error. `Storage` now serializes opens on a
//! process-wide lock; the barrier here lines every thread up on the very
//! first initialization to make a regression as loud as possible.

use std::sync::{Arc, Barrier};

use unissh_storage::Storage;

#[test]
fn concurrent_first_opens_do_not_race_sqlcipher_init() {
    const THREADS: usize = 8;
    let barrier = Arc::new(Barrier::new(THREADS));
    let handles: Vec<_> = (0..THREADS)
        .map(|i| {
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                let storage =
                    Storage::open_in_memory(&[i as u8 + 1; 32]).expect("concurrent first open");
                storage.set_meta("probe", b"v").expect("write after open");
            })
        })
        .collect();
    for h in handles {
        h.join().expect("no thread panicked");
    }
}
