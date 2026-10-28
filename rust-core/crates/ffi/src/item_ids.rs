//! Item ids the core mints, and the create-only guard.
//!
//! A new host, group or snippet is saved with an empty id and gets one here:
//! a readable slug of its label and the time in milliseconds
//! (`web-server-1761650000000`), the shape the app has always used. The id is
//! checked against every record of the vault, live or deleted, so a new item
//! never takes over the id of one that a group, a binding or a hop may still
//! name. Clients do not mint ids of their own.

use std::time::{SystemTime, UNIX_EPOCH};

use unissh_storage::Storage;

use crate::{resolve_vid, FfiError};

/// The longest slug an id starts with, in bytes (the slug is ASCII).
const SLUG_MAX: usize = 40;

/// `label` lowercased with every run of characters other than ASCII letters
/// and digits made one dash, at most [`SLUG_MAX`] characters; `fallback` when
/// nothing is left.
pub(crate) fn slug(label: &str, fallback: &str) -> String {
    let mut out = String::new();
    let mut gap = false;
    for c in label.chars().flat_map(char::to_lowercase) {
        if c.is_ascii_lowercase() || c.is_ascii_digit() {
            if gap && !out.is_empty() {
                out.push('-');
            }
            gap = false;
            out.push(c);
        } else {
            gap = true;
        }
    }
    // Only ASCII went in, so any length is a character boundary.
    out.truncate(SLUG_MAX);
    let out = out.trim_end_matches('-');
    if out.is_empty() {
        fallback.to_owned()
    } else {
        out.to_owned()
    }
}

/// A fresh id in `vault_id` for a new item labelled `label`:
/// `slug(label)-<millis now>`, see [`mint_item_id_at`].
pub(crate) fn mint_item_id(
    storage: &Storage,
    vault_id: &str,
    label: &str,
    fallback: &str,
) -> Result<String, FfiError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis());
    mint_item_id_at(storage, vault_id, label, fallback, millis)
}

/// `slug(label)-<millis>`, or — when any record of the vault (a tombstone
/// included) already holds that id — the same with `-2`, `-3`, … appended,
/// the first one free.
pub(crate) fn mint_item_id_at(
    storage: &Storage,
    vault_id: &str,
    label: &str,
    fallback: &str,
    millis: u128,
) -> Result<String, FfiError> {
    let vid = resolve_vid(storage, vault_id);
    let base = format!("{}-{millis}", slug(label, fallback));
    let mut id = base.clone();
    let mut n: u32 = 1;
    while storage
        .get_item(&vid, id.as_bytes())
        .map_err(FfiError::other)?
        .is_some()
    {
        n = n.saturating_add(1);
        id = format!("{base}-{n}");
    }
    Ok(id)
}

/// The create-only guard: [`FfiError::AlreadyExists`] when a live item of any
/// type holds `item_id` in `vault_id`. A tombstone does not count — creating
/// over a deleted item is a new version of it, as any write is.
pub(crate) fn refuse_taken(
    storage: &Storage,
    vault_id: &str,
    item_id: &[u8],
) -> Result<(), FfiError> {
    let vid = resolve_vid(storage, vault_id);
    match storage.get_item(&vid, item_id).map_err(FfiError::other)? {
        Some(rec) if !rec.tombstone => Err(FfiError::AlreadyExists),
        Some(_) | None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{mint_item_id_at, slug};
    use crate::{ConnectionProfile, Core, FfiError, Identity, ProfileAuth, ServerGroup, Snippet};

    /// An Ed25519 OpenSSH key encrypted with the passphrase `secret` (the
    /// ssh-agent crate's import fixture).
    const ENCRYPTED_KEY: &str = "\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABBhWyUDQ0
LH5fgFmZybFVGsAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIDDxyy7jcqQSO7Rp
Z3up+OaKtad5xPLA0fSAt93YICPGAAAAkIahBcpaJCrNyYUPbaaKso44xI2ZYmiSrb92MC
Nlvin/PJJN/GTW2LlzHA099vtHXGRP246MJnvDJKcbBZXuc4Lfkm1nvyYGC6b4C0q324Ck
NhGHKcKs9BW8DCq9KkAc4T8gPe5Gz/NP/jWwaAJWPUt5tJ2qWXWHy8OskCc9/wsspARTE0
bQ+jhbv16Otv7qiw==
-----END OPENSSH PRIVATE KEY-----";

    fn core_with_vault() -> (Arc<Core>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let core = Core::new(
            dir.path().join("i.db").to_string_lossy().to_string(),
            dir.path().join("i.keyset").to_string_lossy().to_string(),
        );
        core.create_account(None).unwrap();
        core.create_vault("v".into(), "V".into()).unwrap();
        (core, dir)
    }

    /// `<slug>-<millis>`: the slug, then a dash and digits only.
    fn minted_from(id: &str, slug: &str) -> bool {
        id.strip_prefix(slug)
            .and_then(|rest| rest.strip_prefix('-'))
            .is_some_and(|millis| !millis.is_empty() && millis.bytes().all(|b| b.is_ascii_digit()))
    }

    /// Letters and digits with single dashes between, at most 40 of them; a
    /// label of only other characters falls back.
    #[test]
    fn a_slug_keeps_ascii_letters_and_digits_with_single_dashes() {
        assert_eq!(slug("  Web Server #2 ", "host"), "web-server-2");
        assert_eq!(slug("Привет!!!", "host"), "host");
        assert_eq!(slug(&"a".repeat(50), "host").len(), 40);
    }

    #[test]
    fn a_new_host_group_or_snippet_saved_without_an_id_gets_one_from_its_label() {
        let (core, _dir) = core_with_vault();
        let host = core
            .save_connection(
                "v".into(),
                ConnectionProfile {
                    profile_id: String::new(),
                    uid: String::new(),
                    label: "Web Server (prod) ü".into(),
                    host: "h".into(),
                    port: 22,
                    user: "x".into(),
                    auth: ProfileAuth::PromptPassword,
                    username_template: None,
                    jumps: vec![],
                    proxy: None,
                    tags: vec![],
                    startup_snippet_ids: Vec::new(),
                    record_sessions: false,
                    agent_forward: false,
                    color: None,
                    icon: None,
                },
            )
            .unwrap();
        let group = core
            .save_group(
                "v".into(),
                ServerGroup {
                    group_id: String::new(),
                    label: "Prod Boxes".into(),
                    member_ids: vec![host.clone()],
                    parent_id: None,
                    color: None,
                    icon: None,
                },
            )
            .unwrap();
        let snippet = core
            .save_snippet(
                "v".into(),
                Snippet {
                    snippet_id: String::new(),
                    label: "Tail logs".into(),
                    command: "journalctl -f".into(),
                    tags: vec![],
                },
            )
            .unwrap();
        assert!(minted_from(&host, "web-server-prod"), "host id {host}");
        assert!(minted_from(&group, "prod-boxes"), "group id {group}");
        assert!(minted_from(&snippet, "tail-logs"), "snippet id {snippet}");
        assert_eq!(
            core.get_connection("v".into(), host.clone())
                .unwrap()
                .profile_id,
            host
        );
        assert_eq!(
            core.get_group("v".into(), group).unwrap().member_ids,
            vec![host]
        );
        assert_eq!(
            core.list_snippets("v".into()).unwrap()[0].snippet_id,
            snippet
        );
    }

    #[test]
    fn a_minted_id_steps_past_ids_the_vault_already_has_live_or_deleted() {
        let (core, _dir) = core_with_vault();
        core.save_password("v".into(), "web-7".into(), "pw".into())
            .unwrap();
        core.save_note("v".into(), "web-7-2".into(), "n".into())
            .unwrap();
        core.delete_item("v".into(), "web-7-2".into()).unwrap();
        let minted = {
            let guard = core.locked_state();
            let state = guard.as_ref().unwrap();
            mint_item_id_at(&state.storage, "v", "Web", "host", 7).unwrap()
        };
        assert_eq!(minted, "web-7-3");
    }

    #[test]
    fn creating_a_key_or_identity_refuses_an_id_already_taken() {
        let (core, _dir) = core_with_vault();
        core.create_ssh_key("v".into(), "k".into()).unwrap();
        let fingerprint = core
            .get_public_key("v".into(), "k".into())
            .unwrap()
            .fingerprint;
        let identity = |id: &str| Identity {
            identity_id: id.into(),
            label: id.into(),
            user: "me".into(),
            key_item_id: None,
            password_item_id: None,
        };
        core.create_identity("v".into(), identity("me")).unwrap();

        assert!(matches!(
            core.create_ssh_key("v".into(), "k".into()),
            Err(FfiError::AlreadyExists)
        ));
        assert!(matches!(
            core.create_imported_ssh_key(
                "v".into(),
                "k".into(),
                ENCRYPTED_KEY.into(),
                Some("secret".into())
            ),
            Err(FfiError::AlreadyExists)
        ));
        assert!(matches!(
            core.create_identity("v".into(), identity("me")),
            Err(FfiError::AlreadyExists)
        ));
        // Nothing was replaced.
        assert_eq!(
            core.get_public_key("v".into(), "k".into())
                .unwrap()
                .fingerprint,
            fingerprint
        );
    }

    #[test]
    fn creating_over_a_deleted_item_is_allowed() {
        let (core, _dir) = core_with_vault();
        core.create_ssh_key("v".into(), "k".into()).unwrap();
        core.delete_item("v".into(), "k".into()).unwrap();
        core.create_ssh_key("v".into(), "k".into()).unwrap();
        assert!(core.get_public_key("v".into(), "k".into()).is_ok());
    }

    #[test]
    fn an_encrypted_key_imported_without_its_passphrase_asks_for_it() {
        let (core, _dir) = core_with_vault();
        assert!(matches!(
            core.import_ssh_key("v".into(), "k".into(), ENCRYPTED_KEY.into(), None),
            Err(FfiError::PassphraseRequired)
        ));
    }

    #[test]
    fn an_encrypted_key_imported_with_a_wrong_passphrase_says_so() {
        let (core, _dir) = core_with_vault();
        assert!(matches!(
            core.import_ssh_key(
                "v".into(),
                "k".into(),
                ENCRYPTED_KEY.into(),
                Some("nope".into())
            ),
            Err(FfiError::WrongPassphrase)
        ));
    }
}
