//! Unit tests of ssh-config import (no network).

use unissh_ssh_transport::{HostSettings, IncludedFile, SshConfig};

/// One included file, for the loader closures below.
fn pending(cfg: &SshConfig) -> Vec<String> {
    cfg.pending_includes()
        .iter()
        .map(|p| p.path.clone())
        .collect()
}

fn file(path: &str, text: &str) -> Vec<IncludedFile> {
    vec![IncludedFile {
        path: path.to_string(),
        text: text.to_string(),
    }]
}

#[test]
fn parses_and_resolves_first_match_wins() {
    let text = "\
Host prod
  HostName 10.0.0.5
  User deploy
  Port 2222
  IdentityFile ~/.ssh/id_ed25519

Host *.internal
  User admin

Host *
  User fallback
";
    let cfg = SshConfig::parse(text).unwrap();
    let prod = cfg.resolve("prod");
    assert_eq!(prod.hostname.as_deref(), Some("10.0.0.5"));
    assert_eq!(prod.user.as_deref(), Some("deploy")); // the first value wins
    assert_eq!(prod.port, Some(2222));
    assert_eq!(prod.identity_file.as_deref(), Some("~/.ssh/id_ed25519"));

    // *.internal matches before *, so User=admin
    let db = cfg.resolve("db.internal");
    assert_eq!(db.user.as_deref(), Some("admin"));
}

#[test]
fn proxy_jump_parsed() {
    let cfg = SshConfig::parse("Host target\n  HostName 10.0.0.9\n  ProxyJump bastion\n").unwrap();
    let r = cfg.resolve("target");
    assert_eq!(r.proxy_jump.as_deref(), Some("bastion"));
}

#[test]
fn equals_and_comments() {
    let cfg = SshConfig::parse("# comment\nHost a\n  Port=2200\n").unwrap();
    assert_eq!(cfg.resolve("a").port, Some(2200));
}

#[test]
fn unknown_host_is_empty() {
    let cfg = SshConfig::parse("Host a\n  HostName x\n").unwrap();
    assert_eq!(cfg.resolve("b"), HostSettings::default());
}

#[test]
fn glob_question_mark() {
    let cfg = SshConfig::parse("Host web?\n  User w\n").unwrap();
    assert_eq!(cfg.resolve("web1").user.as_deref(), Some("w"));
    assert_eq!(cfg.resolve("web42").user, None);
}

#[test]
fn bad_port_errors() {
    assert!(SshConfig::parse("Host a\n  Port notnum\n").is_err());
}

#[test]
fn negated_pattern_excludes_block() {
    // `Host *.example.com !secret.example.com` must apply to ALL
    // *.example.com EXCEPT secret.example.com (OpenSSH negation semantics).
    let cfg = SshConfig::parse(
        "Host *.example.com !secret.example.com\n  ProxyJump bastion\n  User deploy\n",
    )
    .unwrap();
    // an ordinary host — the block applies
    let web = cfg.resolve("web.example.com");
    assert_eq!(web.proxy_jump.as_deref(), Some("bastion"));
    assert_eq!(web.user.as_deref(), Some("deploy"));
    // the excluded host — the block does NOT apply (no unintended ProxyJump)
    let secret = cfg.resolve("secret.example.com");
    assert_eq!(secret.proxy_jump, None);
    assert_eq!(secret.user, None);
}

#[test]
fn negation_takes_precedence_regardless_of_order() {
    // Negation applies regardless of position in the pattern list.
    let cfg = SshConfig::parse("Host !secret.example.com *.example.com\n  User deploy\n").unwrap();
    assert_eq!(
        cfg.resolve("web.example.com").user.as_deref(),
        Some("deploy")
    );
    assert_eq!(cfg.resolve("secret.example.com").user, None);
}

#[test]
fn host_aliases_lists_concrete_only() {
    let cfg = SshConfig::parse(
        "Host bastion\n  HostName 10.0.0.1\n\
         Host web prod\n  User deploy\n\
         Host *.internal\n  User svc\n\
         Host gw?\n  Port 2222\n",
    )
    .unwrap();
    // concrete aliases in order of appearance; patterns (*, ?) are dropped
    assert_eq!(cfg.host_aliases(), vec!["bastion", "web", "prod"]);
}

#[test]
fn a_match_block_does_not_contaminate_the_host_above_it() {
    // The regression this guards. `Match` was not recognised, so the directives
    // inside it were merged into the preceding Host block — here, silently
    // rewriting prod's user to root and pointing it at a different machine.
    let text = "\
Host prod
  HostName 10.0.0.5
  User deploy

Match user root
  HostName 10.0.0.99
  User root
";
    let cfg = SshConfig::parse(text).unwrap();
    let prod = cfg.resolve("prod");
    assert_eq!(
        prod.user.as_deref(),
        Some("deploy"),
        "Match must not rewrite the host above it"
    );
    assert_eq!(prod.hostname.as_deref(), Some("10.0.0.5"));
    assert!(
        cfg.skipped()
            .iter()
            .any(|s| s.keyword.eq_ignore_ascii_case("match")),
        "the skipped Match must be reported, not silently dropped"
    );
}

#[test]
fn unsupported_directives_are_reported_with_their_line() {
    let text = "\
Host gw
  HostName gw.example.com
  ProxyCommand /usr/bin/nc %h %p
";
    let cfg = SshConfig::parse(text).unwrap();
    let pc = cfg
        .skipped()
        .iter()
        .find(|s| s.keyword.eq_ignore_ascii_case("proxycommand"))
        .expect("ProxyCommand must be reported: it silently not working is the bug");
    assert_eq!(
        pc.line, 3,
        "the line number is what makes the report actionable"
    );
}

#[test]
fn forwards_accumulate_across_matching_blocks() {
    // OpenSSH applies every matching LocalForward, and a `Host *` block adding a
    // tunnel to everything is ordinary. First-wins would drop all but one.
    let text = "\
Host db
  HostName db.internal
  LocalForward 5432 127.0.0.1:5432

Host *
  LocalForward 9000 127.0.0.1:9000
  DynamicForward 1080
";
    let cfg = SshConfig::parse(text).unwrap();
    let db = cfg.resolve("db");
    assert_eq!(db.local_forwards.len(), 2);
    assert!(db.local_forwards.iter().any(|f| f.starts_with("5432 ")));
    assert!(db.local_forwards.iter().any(|f| f.starts_with("9000 ")));
    assert_eq!(db.dynamic_forwards, vec!["1080".to_string()]);
}

#[test]
fn scalar_directives_are_parsed() {
    let text = "\
Host box
  HostName box.example.com
  ServerAliveInterval 30
  ConnectTimeout 5
  Compression yes
  SetEnv LANG=C.UTF-8
";
    let s = SshConfig::parse(text).unwrap().resolve("box");
    assert_eq!(s.server_alive_interval, Some(30));
    assert_eq!(s.connect_timeout, Some(5));
    assert_eq!(s.compression, Some(true));
    assert_eq!(s.set_env, vec!["LANG=C.UTF-8".to_string()]);
}

#[test]
fn includes_are_followed_through_the_loader_and_cannot_loop() {
    // A cycle must terminate rather than run until memory does.
    let root = "Include conf.d/*\nHost a\n  User from_root\n";
    let mut seen = 0;
    let cfg = SshConfig::parse_with_includes(root, |path, _via| {
        seen += 1;
        assert_eq!(path, "conf.d/*");
        // Every included file includes the parent again.
        file(
            "conf.d/a",
            "Include conf.d/*\nHost b\n  User from_include\n",
        )
    })
    .unwrap();
    assert_eq!(cfg.resolve("a").user.as_deref(), Some("from_root"));
    assert_eq!(cfg.resolve("b").user.as_deref(), Some("from_include"));
    assert!(
        seen <= 16,
        "include recursion must be bounded, saw {seen} rounds"
    );
}

#[test]
fn an_include_is_spliced_where_it_sits_not_appended() {
    // Resolution is first-match-wins, so position IS the meaning. A config that
    // opens with an Include and then has a catch-all expects the included host
    // to win; appending the include would give every host the catch-all's user.
    let root = "\
Include conf.d/hosts
Host *
  User fallback
";
    let cfg = SshConfig::parse_with_includes(root, |path, _via| {
        assert_eq!(path, "conf.d/hosts");
        file("conf.d/hosts", "Host prod\n  User deploy\n")
    })
    .unwrap();
    assert_eq!(
        cfg.resolve("prod").user.as_deref(),
        Some("deploy"),
        "the included block precedes the catch-all, so it must win"
    );
    assert_eq!(cfg.resolve("other").user.as_deref(), Some("fallback"));
}

#[test]
fn an_include_inside_a_host_block_does_not_end_it() {
    // OpenSSH keeps the Host block open across an Include; directives after it
    // still belong to that host.
    let root = "\
Host web
  HostName web.example.com
  Include conf.d/common
  User after
";
    let cfg = SshConfig::parse_with_includes(root, |_, _| {
        file("conf.d/common", "Host other\n  User someone\n")
    })
    .unwrap();
    let web = cfg.resolve("web");
    assert_eq!(web.hostname.as_deref(), Some("web.example.com"));
    assert_eq!(
        web.user.as_deref(),
        Some("after"),
        "a directive after the Include still belongs to the host it was written under"
    );
    assert_eq!(cfg.resolve("other").user.as_deref(), Some("someone"));
}

#[test]
fn a_cyclic_include_terminates_and_is_reported() {
    let root = "Include loop\nHost a\n  User u\n";
    let cfg = SshConfig::parse_with_includes(root, |_, _| file("loop", "Include loop\n")).unwrap();
    assert_eq!(cfg.resolve("a").user.as_deref(), Some("u"));
    assert!(
        cfg.skipped()
            .iter()
            .any(|s| s.keyword.eq_ignore_ascii_case("include")),
        "hitting the depth limit must be reported, not silently truncated"
    );
}

#[test]
fn a_hosts_origin_is_the_file_it_was_written_in() {
    // The importer groups hosts by the file they came from, so an alias that is
    // only reachable through an Include has to carry that file with it — and one
    // written in the config the user picked has to carry nothing, so the top-level
    // config never becomes a group of its own.
    let root = "Include project1/config\nHost local\n  User me\n";
    let cfg = SshConfig::parse_with_includes(root, |_, _| {
        file("project1/config", "Host p1a\nHost p1b\n")
    })
    .unwrap();

    let origins: Vec<(String, Option<String>)> = cfg
        .host_aliases_with_origin()
        .into_iter()
        .map(|h| (h.alias, h.origin))
        .collect();
    assert_eq!(
        origins,
        vec![
            ("p1a".to_string(), Some("project1/config".to_string())),
            ("p1b".to_string(), Some("project1/config".to_string())),
            ("local".to_string(), None),
        ]
    );
}

#[test]
fn a_skipped_directive_carries_the_file_it_was_written_in() {
    // "ProxyCommand did not come across" is only actionable with the file to fix.
    let root = "Include conf.d/x\n";
    let cfg = SshConfig::parse_with_includes(root, |_, _| {
        file("conf.d/x", "Host a\n  ProxyCommand nc %h %p\n")
    })
    .unwrap();
    let s = cfg.skipped();
    assert_eq!(s.len(), 1, "{s:?}");
    assert_eq!(s[0].keyword, "ProxyCommand");
    assert_eq!(s[0].origin.as_deref(), Some("conf.d/x"));
}

#[test]
fn an_include_that_expands_to_nothing_stays_pending() {
    // OpenSSH ignores an include it cannot read. Ignoring it silently, though,
    // costs the user the one clue for why a host is missing — so an include the
    // loader could not open keeps its documented meaning: seen, not followed.
    let root = "Include missing/config\nInclude conf.d/ok\n";
    let cfg = SshConfig::parse_with_includes(root, |path, _via| {
        if path == "conf.d/ok" {
            file("conf.d/ok", "Host a\n")
        } else {
            Vec::new()
        }
    })
    .unwrap();
    assert_eq!(pending(&cfg), ["missing/config"]);
    assert_eq!(cfg.host_aliases(), ["a"], "the rest of the config survives");
}

#[test]
fn one_include_line_may_name_several_files() {
    // `Include project1/config project2/config` is an ordinary layout, and each
    // path is its own include: a missing one must not cost the line's others.
    let root = "Include project1/config missing/config \"with space/config\"\n";
    let mut asked: Vec<String> = Vec::new();
    let cfg = SshConfig::parse_with_includes(root, |path, _via| {
        asked.push(path.to_string());
        match path {
            "project1/config" => file("project1/config", "Host p1\n"),
            "with space/config" => file("with space/config", "Host spaced\n"),
            _ => Vec::new(),
        }
    })
    .unwrap();
    assert_eq!(
        asked,
        ["project1/config", "missing/config", "with space/config"]
    );
    assert_eq!(cfg.host_aliases(), ["p1", "spaced"]);
    assert_eq!(pending(&cfg), ["missing/config"]);
}

#[test]
fn without_a_loader_every_path_on_the_line_is_reported() {
    // Pasted config text follows nothing, so it has to name everything it did
    // not follow — one entry per path, not one per line.
    let cfg = SshConfig::parse("Include a/config b/config\n").unwrap();
    assert_eq!(pending(&cfg), ["a/config", "b/config"]);
}

#[test]
fn the_loader_is_told_which_file_the_include_line_sits_in() {
    // An importer that maps included files onto groups needs the include tree,
    // not just the flat list: a file pulled in by an included file belongs to
    // whatever group that file stands for.
    let root = "Include a/config\n";
    let mut asked: Vec<(String, Option<String>)> = Vec::new();
    SshConfig::parse_with_includes(root, |path, via| {
        asked.push((path.to_string(), via.map(str::to_string)));
        match path {
            "a/config" => file("a/config", "Include b/config\n"),
            "b/config" => file("b/config", "Host deep\n"),
            _ => Vec::new(),
        }
    })
    .unwrap();
    assert_eq!(
        asked,
        [
            ("a/config".to_string(), None),
            ("b/config".to_string(), Some("a/config".to_string())),
        ]
    );
}

#[test]
fn an_unfollowed_include_names_the_file_it_was_written_in() {
    // Two files can each say `Include local`. Without the origin the report
    // shows the same string twice and neither is a place to go and fix.
    let root = "Include local\nInclude a/config\n";
    let cfg = SshConfig::parse_with_includes(root, |path, _via| match path {
        "a/config" => file("a/config", "Include local\n"),
        _ => Vec::new(),
    })
    .unwrap();
    let got: Vec<(String, Option<String>)> = cfg
        .pending_includes()
        .iter()
        .map(|p| (p.path.clone(), p.origin.clone()))
        .collect();
    assert_eq!(
        got,
        [
            ("local".to_string(), None),
            ("local".to_string(), Some("a/config".to_string())),
        ]
    );
}
