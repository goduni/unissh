//! Unit tests of ssh-config import (no network).

use unissh_ssh_transport::{HostSettings, SshConfig};

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
    let cfg = SshConfig::parse_with_includes(root, |path| {
        seen += 1;
        assert_eq!(path, "conf.d/*");
        // Every included file includes the parent again.
        vec!["Include conf.d/*\nHost b\n  User from_include\n".to_string()]
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
    let cfg = SshConfig::parse_with_includes(root, |path| {
        assert_eq!(path, "conf.d/hosts");
        vec!["Host prod\n  User deploy\n".to_string()]
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
    let cfg =
        SshConfig::parse_with_includes(root, |_| vec!["Host other\n  User someone\n".to_string()])
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
    let cfg = SshConfig::parse_with_includes(root, |_| vec!["Include loop\n".to_string()]).unwrap();
    assert_eq!(cfg.resolve("a").user.as_deref(), Some("u"));
    assert!(
        cfg.skipped()
            .iter()
            .any(|s| s.keyword.eq_ignore_ascii_case("include")),
        "hitting the depth limit must be reported, not silently truncated"
    );
}
