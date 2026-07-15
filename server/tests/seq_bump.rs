//! Anti-rollback restore runbook (§14.3): instance-wide seq-bump raises next_seq and
//! NEVER lowers it — otherwise clients get report_version < cursor → TransportRollback.

use unissh_server::store::Store;

async fn store() -> Store {
    let s = Store::connect_sqlite(":memory:", 1).await.unwrap();
    s.migrate().await.unwrap();
    s.ensure_instance(1).await.unwrap();
    s
}

#[tokio::test]
async fn bump_by_raises_next_seq() {
    let s = store().await;
    s.bump_instance_seq_to(42).await.unwrap();
    s.bump_instance_seq_by(100_000).await.unwrap();
    assert_eq!(s.report_version().await.unwrap(), 100_042);
}

#[tokio::test]
async fn bump_to_never_lowers() {
    let s = store().await;
    s.bump_instance_seq_to(500).await.unwrap();
    assert_eq!(s.report_version().await.unwrap(), 500);

    // target below current → no change (monotonic)
    let (old, new) = s.bump_instance_seq_to(50).await.unwrap();
    assert_eq!((old, new), (500, 500));
    assert_eq!(
        s.report_version().await.unwrap(),
        500,
        "must never lower next_seq"
    );

    // target above current → raised
    let (old, new) = s.bump_instance_seq_to(900).await.unwrap();
    assert_eq!((old, new), (500, 900));
}
