//! Snippet parameters (#107): the one place in the core that reads
//! `{{name}}` / `{{name:default}}` in a snippet's command text.
//!
//! The same rules as the app's `client/src/support/snippetParams.ts`, which
//! the palette, Fleet and the startup path use; a client without a JavaScript
//! side (the CLI) uses this module, so the two cannot drift apart unnoticed:
//! their tests pin the same cases.
//!
//! Syntax: a name is `[A-Za-z_][A-Za-z0-9_]*`; a default runs to the first
//! closing `}}`. `\{{` is a literal `{{`. Anything else — `{{ spaced }}`, a
//! stray brace, an unterminated placeholder — is literal text, so there is no
//! error case: a shell command full of braces still goes through untouched.

use std::collections::BTreeMap;

use crate::ConnectionProfile;

/// A parameter, in order of first appearance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnippetParam {
    /// The name between the braces.
    pub name: String,
    /// `None` for `{{name}}`, a (possibly empty) string for `{{name:...}}`.
    /// A repeated name keeps the default of its first occurrence.
    pub default: Option<String>,
    /// Byte offset of the first occurrence in the command text.
    pub position: usize,
}

/// Names that come from the connect target rather than from the user.
pub const BUILTIN_PARAMS: [&str; 3] = ["host", "user", "port"];

/// Whether `name` is one of [`BUILTIN_PARAMS`].
pub fn is_builtin_param(name: &str) -> bool {
    BUILTIN_PARAMS.contains(&name)
}

/// The built-ins one target answers: name → value.
pub type BuiltinValues = BTreeMap<String, String>;

/// The built-ins a host answers: its address and port, and its user unless
/// the profile leaves it empty (an identity-bound login) — that one is then
/// asked like any other parameter. As the app's `builtinsFromProfile`.
pub fn builtins_from_profile(profile: &ConnectionProfile) -> BuiltinValues {
    let mut values = BuiltinValues::new();
    values.insert("host".to_owned(), profile.host.clone());
    values.insert("port".to_owned(), profile.port.to_string());
    if !profile.user.is_empty() {
        values.insert("user".to_owned(), profile.user.clone());
    }
    values
}

enum Token<'c> {
    Text(String),
    Param {
        raw: &'c str,
        name: &'c str,
        default: Option<&'c str>,
        position: usize,
    },
}

/// A well-formed placeholder at the start of `rest`: its length, name and
/// default. `None` when `rest` does not start with one.
fn placeholder(rest: &str) -> Option<(usize, &str, Option<&str>)> {
    let body = rest.strip_prefix("{{")?;
    let name_len = body
        .char_indices()
        .find(|&(i, c)| {
            let ok = if i == 0 {
                c.is_ascii_alphabetic() || c == '_'
            } else {
                c.is_ascii_alphanumeric() || c == '_'
            };
            !ok
        })
        .map_or(body.len(), |(i, _)| i);
    if name_len == 0 {
        return None;
    }
    let name = body.get(..name_len)?;
    let after = body.get(name_len..)?;
    if after.starts_with("}}") {
        return Some((2 + name_len + 2, name, None));
    }
    let tail = after.strip_prefix(':')?;
    let end = tail.find("}}")?;
    let default = tail.get(..end)?;
    Some((2 + name_len + 1 + end + 2, name, Some(default)))
}

fn tokenize(command: &str) -> Vec<Token<'_>> {
    let mut tokens = Vec::new();
    let mut text = String::new();
    let mut i = 0;
    while let Some(rest) = command.get(i..) {
        if rest.is_empty() {
            break;
        }
        if rest.starts_with("\\{{") {
            text.push_str("{{");
            i += 3;
            continue;
        }
        if let Some((len, name, default)) = placeholder(rest) {
            if !text.is_empty() {
                tokens.push(Token::Text(std::mem::take(&mut text)));
            }
            tokens.push(Token::Param {
                raw: rest.get(..len).unwrap_or_default(),
                name,
                default,
                position: i,
            });
            i += len;
            continue;
        }
        let Some(c) = rest.chars().next() else {
            break;
        };
        text.push(c);
        i += c.len_utf8();
    }
    if !text.is_empty() {
        tokens.push(Token::Text(text));
    }
    tokens
}

/// The parameters a command takes, each name once, in order of first appearance.
pub fn parse_params(command: &str) -> Vec<SnippetParam> {
    let mut params: Vec<SnippetParam> = Vec::new();
    for token in tokenize(command) {
        if let Token::Param {
            name,
            default,
            position,
            ..
        } = token
        {
            if !params.iter().any(|p| p.name == name) {
                params.push(SnippetParam {
                    name: name.to_owned(),
                    default: default.map(str::to_owned),
                    position,
                });
            }
        }
    }
    params
}

/// The command with every placeholder replaced from `values`. A placeholder
/// with no value is left as written, so a gap shows up instead of silently
/// becoming an empty string.
pub fn substitute_params(command: &str, values: &BTreeMap<String, String>) -> String {
    tokenize(command)
        .into_iter()
        .map(|token| match token {
            Token::Text(text) => text,
            Token::Param { raw, name, .. } => {
                values.get(name).map_or(raw, String::as_str).to_owned()
            }
        })
        .collect()
}

/// The command as it should run on one target: the user's answers, with the
/// target's built-ins winning over a user parameter of the same name.
pub fn resolve_command(
    command: &str,
    user_values: &BTreeMap<String, String>,
    builtins: &BuiltinValues,
) -> String {
    let mut values = user_values.clone();
    values.extend(builtins.iter().map(|(k, v)| (k.clone(), v.clone())));
    substitute_params(command, &values)
}

/// What a run on several targets asks once, for all of them.
#[derive(Debug, PartialEq, Eq)]
pub struct FleetParams {
    /// The parameters to ask the user, in order of first appearance.
    pub ask: Vec<SnippetParam>,
    /// The built-ins every target answers, which come from each host.
    pub from_host: Vec<String>,
}

/// Splits a command's parameters for a run on `targets` (each given by the
/// built-ins it answers). A built-in that every target answers shadows a user
/// parameter of the same name and comes from each host; one that some target
/// lacks (a profile with no user) is asked, and the answer fills only the
/// targets that lack it — built-ins still win where present
/// ([`resolve_command`]). As the app's `splitFleetParams`.
pub fn split_fleet_params(command: &str, targets: &[BuiltinValues]) -> FleetParams {
    let every_host = |name: &str| {
        is_builtin_param(name)
            && !targets.is_empty()
            && targets.iter().all(|t| t.contains_key(name))
    };
    let (from_host, ask): (Vec<_>, Vec<_>) = parse_params(command)
        .into_iter()
        .partition(|p| every_host(&p.name));
    FleetParams {
        ask,
        from_host: from_host.into_iter().map(|p| p.name).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    fn param(name: &str, default: Option<&str>, position: usize) -> SnippetParam {
        SnippetParam {
            name: name.to_owned(),
            default: default.map(str::to_owned),
            position,
        }
    }

    fn names(params: &[SnippetParam]) -> Vec<&str> {
        params.iter().map(|p| p.name.as_str()).collect()
    }

    #[test]
    fn finds_nothing_in_a_plain_command() {
        assert_eq!(parse_params("systemctl restart nginx"), []);
    }

    #[test]
    fn finds_one_parameter_and_substitutes_it() {
        let cmd = "systemctl restart {{service}}";
        assert_eq!(parse_params(cmd), [param("service", None, 18)]);
        assert_eq!(
            substitute_params(cmd, &values(&[("service", "nginx")])),
            "systemctl restart nginx"
        );
    }

    #[test]
    fn asks_a_repeated_name_once_at_its_first_position_and_fills_every_occurrence() {
        let cmd = "echo {{x}} && echo {{x:late}}";
        assert_eq!(parse_params(cmd), [param("x", None, 5)]);
        assert_eq!(
            substitute_params(cmd, &values(&[("x", "1")])),
            "echo 1 && echo 1"
        );
    }

    #[test]
    fn reads_a_default() {
        assert_eq!(
            parse_params("journalctl -u {{unit:nginx.service}} -n 200"),
            [param("unit", Some("nginx.service"), 14)]
        );
    }

    #[test]
    fn tells_an_empty_default_apart_from_no_default() {
        assert_eq!(parse_params("ls {{flags:}}"), [param("flags", Some(""), 3)]);
    }

    #[test]
    fn types_an_escaped_brace_pair_as_a_literal() {
        let cmd = "echo \\{{x}} {{y}}";
        assert_eq!(names(&parse_params(cmd)), ["y"]);
        assert_eq!(
            substitute_params(cmd, &values(&[("x", "no"), ("y", "yes")])),
            "echo {{x}} yes"
        );
        // Also when the escaped one is the only placeholder.
        assert_eq!(parse_params("echo \\{{x}}"), []);
        assert_eq!(
            substitute_params("echo \\{{x}}", &values(&[])),
            "echo {{x}}"
        );
    }

    #[test]
    fn leaves_spaced_braces_as_literal_text() {
        let cmd = "echo '{{ .Status }}'";
        assert_eq!(parse_params(cmd), []);
        assert_eq!(substitute_params(cmd, &values(&[])), cmd);
    }

    #[test]
    fn counts_only_the_inner_well_formed_placeholder_in_nested_braces() {
        let cmd = "{{a{{b}}}}";
        assert_eq!(parse_params(cmd), [param("b", None, 3)]);
        assert_eq!(
            substitute_params(cmd, &values(&[("a", "A"), ("b", "B")])),
            "{{aB}}"
        );
    }

    #[test]
    fn lets_a_builtin_win_over_a_user_value_of_the_same_name() {
        let builtins = values(&[("host", "web1")]);
        assert_eq!(
            resolve_command(
                "{{user}}@{{host}}",
                &values(&[("user", "typed"), ("host", "typed")]),
                &builtins
            ),
            "typed@web1"
        );
    }

    #[test]
    fn takes_host_and_port_from_a_profile_and_omits_an_empty_user() {
        let profile = ConnectionProfile {
            profile_id: "p".to_owned(),
            uid: String::new(),
            label: "web1".to_owned(),
            host: "web1".to_owned(),
            port: 2222,
            user: String::new(),
            auth: crate::ProfileAuth::Personal,
            username_template: None,
            jumps: Vec::new(),
            proxy: None,
            tags: Vec::new(),
            startup_snippet_ids: Vec::new(),
            record_sessions: false,
            agent_forward: false,
            color: None,
            icon: None,
        };
        assert_eq!(
            builtins_from_profile(&profile),
            values(&[("host", "web1"), ("port", "2222")])
        );
    }

    #[test]
    fn lists_parameters_in_order_of_first_appearance_not_by_name() {
        assert_eq!(
            names(&parse_params("{{zeta}} {{alpha}} {{mid}} {{alpha}}")),
            ["zeta", "alpha", "mid"]
        );
    }

    #[test]
    fn leaves_a_placeholder_with_no_value_visible() {
        assert_eq!(
            substitute_params("kill {{pid:1}} {{sig}}", &values(&[("sig", "-9")])),
            "kill {{pid:1}} -9"
        );
    }

    #[test]
    fn keeps_text_around_placeholders_intact_beyond_ascii() {
        assert_eq!(
            substitute_params("écho «{{x}}» ✓", &values(&[("x", "да")])),
            "écho «да» ✓"
        );
    }

    #[test]
    fn resolves_user_parameters_once_and_builtins_per_host() {
        let web1 = values(&[("host", "web1"), ("user", "deploy"), ("port", "22")]);
        let web2 = values(&[("host", "web2"), ("user", "ops"), ("port", "2222")]);
        let cmd = "systemctl restart {{service}} # {{user}}@{{host}}:{{port}}";
        let split = split_fleet_params(cmd, &[web1.clone(), web2.clone()]);
        assert_eq!(names(&split.ask), ["service"]);
        assert_eq!(split.from_host, ["user", "host", "port"]);
        let answers = values(&[("service", "nginx")]);
        assert_eq!(
            resolve_command(cmd, &answers, &web1),
            "systemctl restart nginx # deploy@web1:22"
        );
        assert_eq!(
            resolve_command(cmd, &answers, &web2),
            "systemctl restart nginx # ops@web2:2222"
        );
    }

    #[test]
    fn asks_a_builtin_some_target_lacks_and_fills_only_that_target() {
        let web1 = values(&[("host", "web1"), ("user", "deploy"), ("port", "22")]);
        let no_user = values(&[("host", "web3"), ("port", "22")]);
        let split = split_fleet_params("id {{user}}", &[web1.clone(), no_user.clone()]);
        assert_eq!(names(&split.ask), ["user"]);
        let answers = values(&[("user", "root")]);
        assert_eq!(resolve_command("id {{user}}", &answers, &web1), "id deploy");
        assert_eq!(
            resolve_command("id {{user}}", &answers, &no_user),
            "id root"
        );
    }
}
