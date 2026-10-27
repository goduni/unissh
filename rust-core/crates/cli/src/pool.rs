//! A pool of scoped threads over a slice: every item once, a few at a time.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

/// Runs `work` on every item of `items`, on up to `workers` threads at once
/// (at least one, at most one per item), and returns when all are done. Items
/// are taken in order, each by whichever thread is free; `work` reports its
/// own results (through atomics, a lock or a channel).
pub fn each<T: Sync>(items: &[T], workers: u32, work: impl Fn(&T) + Sync) {
    let next = AtomicUsize::new(0);
    let workers = usize::try_from(workers)
        .unwrap_or(1)
        .clamp(1, items.len().max(1));
    thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                while let Some(item) = items.get(next.fetch_add(1, Ordering::Relaxed)) {
                    work(item);
                }
            });
        }
    });
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::each;

    #[test]
    fn each_runs_every_item_once_whatever_the_worker_count() {
        for workers in [1, 3, 16] {
            let runs: Vec<AtomicUsize> = std::iter::repeat_with(|| AtomicUsize::new(0))
                .take(10)
                .collect();
            let items: Vec<usize> = (0..10).collect();
            each(&items, workers, |&i| {
                runs[i].fetch_add(1, Ordering::Relaxed);
            });
            assert!(
                runs.iter().all(|r| r.load(Ordering::Relaxed) == 1),
                "{workers} workers"
            );
        }
    }
}
