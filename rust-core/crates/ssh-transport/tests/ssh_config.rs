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
