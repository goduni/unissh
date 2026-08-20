//! Importing an `~/.ssh/config` **file**, with its `Include` directives
//! followed the way `ssh` follows them.
//!
//! These tests assert what a user gets from a given set of files on disk: these
//! hosts, from these files, with these files read and these includes skipped.
//! The include *rules* — where a block splices in, the depth cap, skip-on-
//! unreadable — belong to the parser and are covered in the `ssh-transport`
//! config tests; what is exercised here is the loader that turns a path into
//! files, and the wiring that carries the result into a vault.

use std::fs;
use std::path::{Path, PathBuf};

use unissh_ffi::Core;

/// A vault at `dir`, unlocked, ready to import into.
fn vault(dir: &Path) -> std::sync::Arc<Core> {
    let core = Core::new(
        dir.join("inst.db").to_str().unwrap().to_string(),
        dir.join("keyset.bin").to_str().unwrap().to_string(),
    );
    core.create_account(Some("pw".to_string())).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();
    core
}

/// Writes `text` to `dir/rel`, creating parent directories.
fn write(dir: &Path, rel: &str, text: &str) -> PathBuf {
    let p = dir.join(rel);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(&p, text).unwrap();
    p
}

fn path(p: &Path) -> String {
    p.to_str().unwrap().to_string()
}

/// The aliases a report lists, in order.
fn aliases(report: &unissh_ffi::SshConfigReport) -> Vec<String> {
    report.hosts.iter().map(|h| h.alias.clone()).collect()
}

#[test]
fn a_relative_include_is_resolved_against_the_configs_own_directory() {
    // The layout from the report: a top-level config that is little more than an
    // Include line. Picking it must import the hosts behind it.
    let dir = tempfile::tempdir().unwrap();
    let ssh = dir.path().join(".ssh");
    write(
        &ssh,
        "project1/config",
        "Host p1\n  HostName p1.example.com\n",
    );
    let cfg = write(&ssh, "config", "Include project1/config\n");

    let core = vault(dir.path());
    let report = core.ssh_config_report_at_path(path(&cfg)).unwrap();
    assert_eq!(aliases(&report), ["p1"]);
    assert_eq!(report.hosts[0].hostname, "p1.example.com");
    assert_eq!(
        report.hosts[0].origin_file.as_deref(),
        Some(path(&ssh.join("project1/config")).as_str()),
        "the host has to name the file it came from — the group is derived from it"
    );
    assert!(report.pending_includes.is_empty());
    assert_eq!(
        report.files_read,
        [path(&cfg), path(&ssh.join("project1/config"))],
        "the preview must be able to show every file the import touched"
    );

    let created = core
        .import_ssh_config_at_path("v".to_string(), path(&cfg), None)
        .unwrap();
    assert_eq!(created.len(), 1);
    assert_eq!(created[0].alias, "p1");
    assert_eq!(
        created[0].origin_file.as_deref(),
        Some(path(&ssh.join("project1/config")).as_str())
    );
    let prof = core
        .get_connection("v".to_string(), "p1".to_string())
        .unwrap();
    assert_eq!(prof.host, "p1.example.com");
}

#[test]
fn one_include_line_may_name_several_files() {
    // `Include project1/config project2/config` — the layout the request named.
    let dir = tempfile::tempdir().unwrap();
    let ssh = dir.path().join(".ssh");
    write(&ssh, "project1/config", "Host p1\n");
    write(&ssh, "project2/config", "Host p2\n");
    let cfg = write(&ssh, "config", "Include project1/config project2/config\n");

    let core = vault(dir.path());
    let report = core.ssh_config_report_at_path(path(&cfg)).unwrap();
    assert_eq!(aliases(&report), ["p1", "p2"]);
    assert_eq!(
        report.hosts[1].origin_file.as_deref(),
        Some(path(&ssh.join("project2/config")).as_str())
    );
}

#[test]
fn a_glob_include_expands_in_a_stable_order() {
    let dir = tempfile::tempdir().unwrap();
    let ssh = dir.path().join(".ssh");
    write(&ssh, "conf.d/b.conf", "Host beta\n");
    write(&ssh, "conf.d/a.conf", "Host alpha\n");
    let cfg = write(&ssh, "config", "Include conf.d/*\n");

    let core = vault(dir.path());
    let report = core.ssh_config_report_at_path(path(&cfg)).unwrap();
    assert_eq!(
        aliases(&report),
        ["alpha", "beta"],
        "sorted by name, so the same directory always imports the same way"
    );
}

#[test]
fn a_missing_include_is_skipped_reported_and_costs_nothing_else() {
    // One stale line must not cost the user every host in the file.
    let dir = tempfile::tempdir().unwrap();
    let ssh = dir.path().join(".ssh");
    write(&ssh, "there/config", "Host there\n");
    let cfg = write(
        &ssh,
        "config",
        "Include gone/config\nInclude there/config\nHost local\n",
    );

    let core = vault(dir.path());
    let report = core.ssh_config_report_at_path(path(&cfg)).unwrap();
    assert_eq!(aliases(&report), ["there", "local"]);
    assert_eq!(
        report.pending_includes,
        ["gone/config"],
        "an include that went nowhere must be visible, or a missing host has no explanation"
    );
    assert_eq!(report.files_read.len(), 2, "{:?}", report.files_read);
}

#[cfg(unix)]
#[test]
fn an_unreadable_include_is_skipped_and_reported_like_a_missing_one() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let ssh = dir.path().join(".ssh");
    let secret = write(&ssh, "secret/config", "Host secret\n");
    fs::set_permissions(&secret, fs::Permissions::from_mode(0o000)).unwrap();
    let cfg = write(&ssh, "config", "Include secret/config\nHost local\n");

    let core = vault(dir.path());
    let report = core.ssh_config_report_at_path(path(&cfg)).unwrap();
    // Running as root defeats the permission bits entirely; then this asserts
    // nothing about permissions, and the missing-include test carries the case.
    if fs::read_to_string(&secret).is_ok() {
        return;
    }
    assert_eq!(aliases(&report), ["local"]);
    assert_eq!(report.pending_includes, ["secret/config"]);
    assert_eq!(report.files_read, [path(&cfg)]);
}

#[test]
fn an_included_file_may_include_another() {
    let dir = tempfile::tempdir().unwrap();
    let ssh = dir.path().join(".ssh");
    write(&ssh, "b/config", "Host deep\n");
    write(&ssh, "a/config", "Include b/config\nHost mid\n");
    let cfg = write(&ssh, "config", "Include a/config\n");

    let core = vault(dir.path());
    let report = core.ssh_config_report_at_path(path(&cfg)).unwrap();
    assert_eq!(aliases(&report), ["deep", "mid"]);
    assert_eq!(
        report.hosts[0].origin_file.as_deref(),
        Some(path(&ssh.join("b/config")).as_str()),
        "a nested include's hosts belong to the file they were written in"
    );
}

#[test]
fn a_cyclic_include_terminates() {
    let dir = tempfile::tempdir().unwrap();
    let ssh = dir.path().join(".ssh");
    write(&ssh, "a/config", "Include config\nHost a\n");
    let cfg = write(&ssh, "config", "Include a/config\nHost root\n");

    let core = vault(dir.path());
    let report = core.ssh_config_report_at_path(path(&cfg)).unwrap();
    assert_eq!(aliases(&report), ["a", "root"]);
    assert_eq!(
        report.files_read,
        [path(&cfg), path(&ssh.join("a/config"))],
        "a file reached twice is read once"
    );
}

#[test]
fn an_included_host_still_beats_a_catch_all_written_after_the_include() {
    // The parser splices an include in where the Include line sits, and this is
    // the property that makes it matter: appending included blocks instead would
    // hand every imported host the catch-all's user.
    let dir = tempfile::tempdir().unwrap();
    let ssh = dir.path().join(".ssh");
    write(&ssh, "conf.d/prod", "Host prod\n  User deploy\n");
    let cfg = write(
        &ssh,
        "config",
        "Include conf.d/*\nHost *\n  User fallback\n",
    );

    let core = vault(dir.path());
    core.import_ssh_config_at_path("v".to_string(), path(&cfg), None)
        .unwrap();
    let prof = core
        .get_connection("v".to_string(), "prod".to_string())
        .unwrap();
    assert_eq!(
        prof.user, "deploy",
        "the included block precedes the catch-all, so it must win"
    );
}

#[test]
fn a_skipped_directive_names_the_file_it_was_written_in() {
    let dir = tempfile::tempdir().unwrap();
    let ssh = dir.path().join(".ssh");
    write(&ssh, "conf.d/x", "Host a\n  ProxyCommand nc %h %p\n");
    let cfg = write(
        &ssh,
        "config",
        "Include conf.d/x\nHost b\n  Ciphers aes128-ctr\n",
    );

    let core = vault(dir.path());
    let report = core.ssh_config_report_at_path(path(&cfg)).unwrap();
    let proxy = report
        .skipped
        .iter()
        .find(|s| s.keyword == "ProxyCommand")
        .expect("ProxyCommand is reported, not silently dropped");
    assert_eq!(
        proxy.origin_file.as_deref(),
        Some(path(&ssh.join("conf.d/x")).as_str())
    );
    let ciphers = report
        .skipped
        .iter()
        .find(|s| s.keyword == "Ciphers")
        .expect("a skipped directive in the picked file is still reported");
    assert_eq!(
        ciphers.origin_file, None,
        "the config the user picked is not an included file"
    );
}

#[test]
fn only_the_named_aliases_are_imported() {
    // The preview's checkboxes. Filtering the config *text* cannot work once the
    // hosts live in files other than the one being filtered, so the import takes
    // the list instead.
    let dir = tempfile::tempdir().unwrap();
    let ssh = dir.path().join(".ssh");
    write(&ssh, "conf.d/all", "Host keep\nHost drop\n");
    let cfg = write(&ssh, "config", "Include conf.d/all\n");

    let core = vault(dir.path());
    let created = core
        .import_ssh_config_at_path("v".to_string(), path(&cfg), Some(vec!["keep".to_string()]))
        .unwrap();
    assert_eq!(created.len(), 1);
    assert_eq!(created[0].alias, "keep");
    assert!(core
        .get_connection("v".to_string(), "drop".to_string())
        .is_err());
}

#[test]
fn re_importing_the_same_config_updates_rather_than_duplicates() {
    // #9: overwriting an existing profile MUST preserve its immutable uid —
    // personal bindings and hop_refs hang off it. Following includes must not
    // have changed that.
    let dir = tempfile::tempdir().unwrap();
    let ssh = dir.path().join(".ssh");
    write(
        &ssh,
        "conf.d/hosts",
        "Host web\n  HostName one.example.com\n",
    );
    let cfg = write(&ssh, "config", "Include conf.d/hosts\n");

    let core = vault(dir.path());
    core.import_ssh_config_at_path("v".to_string(), path(&cfg), None)
        .unwrap();
    let uid = core
        .get_connection("v".to_string(), "web".to_string())
        .unwrap()
        .uid;

    write(
        &ssh,
        "conf.d/hosts",
        "Host web\n  HostName two.example.com\n",
    );
    core.import_ssh_config_at_path("v".to_string(), path(&cfg), None)
        .unwrap();
    let again = core
        .get_connection("v".to_string(), "web".to_string())
        .unwrap();
    assert_eq!(again.host, "two.example.com", "a re-import updates");
    assert_eq!(
        again.uid, uid,
        "and keeps the uid everything else points at"
    );
    assert_eq!(core.list_connections("v".to_string()).unwrap().len(), 1);
}

#[test]
fn a_config_without_includes_behaves_exactly_as_before() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = write(
        dir.path(),
        "config",
        "Host solo\n  HostName solo.example.com\n",
    );

    let core = vault(dir.path());
    let report = core.ssh_config_report_at_path(path(&cfg)).unwrap();
    assert_eq!(aliases(&report), ["solo"]);
    assert_eq!(report.hosts[0].origin_file, None);
    assert_eq!(report.files_read, [path(&cfg)]);
    assert!(report.pending_includes.is_empty());
}

#[test]
fn config_text_still_reports_includes_as_unfollowed() {
    // Pasted text has no filesystem to follow anything into, and says so.
    let dir = tempfile::tempdir().unwrap();
    let core = vault(dir.path());
    let report = core
        .ssh_config_report("Include conf.d/*\nHost a\n".to_string())
        .unwrap();
    assert_eq!(aliases(&report), ["a"]);
    assert_eq!(report.pending_includes, ["conf.d/*"]);
    assert!(report.files_read.is_empty());
    assert_eq!(report.hosts[0].origin_file, None);
}
