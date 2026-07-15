//! v2 baseline schema smoke test (staged in migrations_v2 until the Task-6 cutover).

use unissh_server::Store;

const TABLES: &[&str] = &[
    "instance",
    "accounts",
    "devices",
    "sessions",
    "auth_nonces",
    "spaces",
    "space_members",
    "vaults",
    "objects",
    "membership_manifests",
    "membership_grants",
    "audit_log",
    "keyset_blobs",
    "invites",
    "pending_actions",
    "key_attestations",
    "pake_relay",
    "idempotency_keys",
];

#[tokio::test]
async fn v2_baseline_creates_all_tables() {
    let store = Store::connect_sqlite(":memory:", 1).await.unwrap();
    store.migrate().await.unwrap();
    for t in TABLES {
        let n = store
            .fetch_scalar_i64(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name = ?",
                vec![unissh_server::store::Val::t(*t)],
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(n, 1, "missing table {t}");
    }
}
