//! Instance-wide `server_seq` semantics (spec §4.3/§7.2): a monotonic u64 across ALL
//! object types, append-only, no renumbering/reuse. Assigned in the
//! push transaction (implemented in store/objects + modules/sync, Phase 2/4).
