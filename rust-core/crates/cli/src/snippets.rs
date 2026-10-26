//! Snippets: the vaults' saved commands, listed, and run on hosts the way
//! `unissh run` runs a command.
//!
//! Parameters (`{{name}}`, `{{name:default}}`) are read and filled by the
//! core's `snippet_params`, the same rules as the app: `{{host}}`, `{{user}}`
//! and `{{port}}` come from each host, the rest is asked once for all of them.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde_json::{json, Value};
use unissh_ffi::snippet_params::{parse_params, SnippetParam};
use unissh_ffi::{Core, Snippet};

use crate::failure::{Failure, Res};
use crate::hosts::{self, Named};
use crate::tty::{one_line, Tty};

/// A snippet and the vault it lives in.
pub struct Saved {
    /// The vault's id.
    #[expect(dead_code, reason = "read once snippets are edited in their vault")]
    pub vault_id: String,
    /// The vault's name.
    pub vault_name: String,
    /// The snippet.
    pub snippet: Snippet,
}

impl Named for Saved {
    const KIND: &'static str = "snippet";
    const LISTED_BY: Option<&'static str> = Some("unissh snippets list");

    fn vault_name(&self) -> &str {
        &self.vault_name
    }

    fn label(&self) -> &str {
        &self.snippet.label
    }

    fn detail(&self) -> String {
        first_line(&self.snippet.command)
    }
}

/// Every snippet of every vault, sorted by vault, then label.
pub fn load(core: &Core) -> Res<Vec<Saved>> {
    let mut snippets = hosts::per_vault(
        core,
        |vault_id| core.list_snippets(vault_id),
        |vault_id, vault_name, snippet| Saved {
            vault_id: vault_id.to_owned(),
            vault_name: vault_name.to_owned(),
            snippet,
        },
    )?;
    snippets.sort_by_cached_key(|s| (s.vault_name.to_lowercase(), s.snippet.label.to_lowercase()));
    Ok(snippets)
}

/// The first line of a command, marked when more follow.
fn first_line(command: &str) -> String {
    let mut lines = command.lines();
    let first = one_line(lines.next().unwrap_or_default());
    if lines.next().is_some() {
        format!("{first} …")
    } else {
        first
    }
}

/// The snippets as a table: label, vault, the parameters it asks, the command.
pub fn table(snippets: &[Saved]) -> String {
    let width = |f: &dyn Fn(&Saved) -> usize, cap: usize| {
        snippets.iter().map(f).max().unwrap_or(0).min(cap)
    };
    let label_w = width(&|s| s.snippet.label.chars().count(), 32);
    let vault_w = width(&|s| s.vault_name.chars().count(), 24);
    let mut text = String::new();
    for s in snippets {
        let params: Vec<String> = parse_params(&s.snippet.command)
            .iter()
            .map(|p| format!("{{{{{}}}}}", p.name))
            .collect();
        let _ = writeln!(
            text,
            "{:<label_w$}  {:<vault_w$}  {}{}",
            one_line(&s.snippet.label),
            one_line(&s.vault_name),
            if params.is_empty() {
                String::new()
            } else {
                format!("{}  ", params.join(" "))
            },
            first_line(&s.snippet.command)
        );
    }
    text
}

/// The snippets as JSON, for scripts: label, vault, tags, the command and its parameters.
pub fn json(snippets: &[Saved]) -> Value {
    Value::Array(
        snippets
            .iter()
            .map(|s| {
                let params: Vec<Value> = parse_params(&s.snippet.command)
                    .into_iter()
                    .map(|p| json!({ "name": p.name, "default": p.default }))
                    .collect();
                json!({
                    "vault": s.vault_name,
                    "label": s.snippet.label,
                    "tags": s.snippet.tags,
                    "command": s.snippet.command,
                    "params": params,
                })
            })
            .collect(),
    )
}

/// `--set name=value`, as clap parses it.
pub fn parse_set(arg: &str) -> Result<(String, String), String> {
    match arg.split_once('=') {
        Some((name, value)) if !name.trim().is_empty() => {
            Ok((name.trim().to_owned(), value.to_owned()))
        }
        Some(_) | None => Err("expected name=value".to_owned()),
    }
}

/// The values for the parameters `ask`: from `sets` first, then asked with
/// `prompt`, which returns `None` when there is no terminal to ask on — then
/// a parameter's default is taken, and one without a default is an error.
///
/// A `--set` for a name the snippet does not ask is refused rather than
/// ignored: it is a typo, or a built-in each host answers (`from_host`).
pub fn answers(
    ask: &[SnippetParam],
    from_host: &[String],
    sets: &[(String, String)],
    prompt: &mut dyn FnMut(&SnippetParam) -> Res<Option<String>>,
) -> Res<BTreeMap<String, String>> {
    let mut values = BTreeMap::new();
    for (name, value) in sets {
        if from_host.contains(name) {
            return Err(Failure::msg(format!(
                "{{{{{name}}}}} comes from each host; it cannot be set"
            )));
        }
        if !ask.iter().any(|p| &p.name == name) {
            let takes: Vec<&str> = ask.iter().map(|p| p.name.as_str()).collect();
            let takes = if takes.is_empty() {
                "it takes none".to_owned()
            } else {
                format!("it takes: {}", takes.join(", "))
            };
            return Err(Failure::msg(format!(
                "the snippet has no parameter \"{}\" ({takes})",
                one_line(name)
            )));
        }
        values.insert(name.clone(), value.clone());
    }
    for param in ask {
        if values.contains_key(&param.name) {
            continue;
        }
        let value = match (prompt(param)?, &param.default) {
            (Some(typed), _) => typed,
            (None, Some(default)) => default.clone(),
            (None, None) => {
                return Err(Failure::msg(format!(
                    "the snippet needs a value for {{{{{0}}}}}: pass --set {0}=VALUE",
                    param.name
                )))
            }
        };
        values.insert(param.name.clone(), value);
    }
    Ok(values)
}

/// Asks the terminal for a parameter, showing its default; an empty answer
/// takes the default. `None` when there is no terminal.
pub fn ask_on_tty(tty: Option<&mut Tty>, param: &SnippetParam) -> Res<Option<String>> {
    let Some(tty) = tty else {
        return Ok(None);
    };
    let prompt = match &param.default {
        Some(default) => format!("{} [{}]: ", param.name, one_line(default)),
        None => format!("{}: ", param.name),
    };
    let typed = tty.line(&prompt)?;
    Ok(Some(match &param.default {
        Some(default) if typed.is_empty() => default.clone(),
        Some(_) | None => typed,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn param(name: &str, default: Option<&str>) -> SnippetParam {
        SnippetParam {
            name: name.to_owned(),
            default: default.map(str::to_owned),
            position: 0,
        }
    }

    fn set(name: &str, value: &str) -> (String, String) {
        (name.to_owned(), value.to_owned())
    }

    fn no_terminal(_: &SnippetParam) -> Res<Option<String>> {
        Ok(None)
    }

    #[test]
    fn set_takes_the_value_after_the_first_equals_sign() {
        assert_eq!(parse_set("q=a=b"), Ok(("q".to_owned(), "a=b".to_owned())));
        assert_eq!(parse_set("empty="), Ok(("empty".to_owned(), String::new())));
        assert!(parse_set("=x").is_err());
        assert!(parse_set("flag").is_err());
    }

    #[test]
    fn set_values_come_first_and_the_terminal_is_asked_the_rest() {
        let ask = [param("service", None), param("lines", Some("200"))];
        let mut asked = Vec::new();
        let values = answers(&ask, &[], &[set("service", "nginx")], &mut |p| {
            asked.push(p.name.clone());
            Ok(Some("50".to_owned()))
        })
        .unwrap();
        assert_eq!(asked, ["lines"]);
        assert_eq!(values.get("service").map(String::as_str), Some("nginx"));
        assert_eq!(values.get("lines").map(String::as_str), Some("50"));
    }

    #[test]
    fn without_a_terminal_a_default_is_taken_and_a_missing_value_is_an_error() {
        let values = answers(&[param("lines", Some("200"))], &[], &[], &mut no_terminal).unwrap();
        assert_eq!(values.get("lines").map(String::as_str), Some("200"));
        let Err(err) = answers(&[param("service", None)], &[], &[], &mut no_terminal) else {
            panic!("a parameter with no value and no default must not run");
        };
        assert!(err.message.contains("--set service="), "{err}");
    }

    #[test]
    fn a_set_for_a_name_the_snippet_does_not_ask_is_refused() {
        let ask = [param("service", None)];
        let from_host = ["host".to_owned()];
        for name in ["servcie", "host"] {
            assert!(
                answers(&ask, &from_host, &[set(name, "x")], &mut no_terminal).is_err(),
                "--set {name} must be refused"
            );
        }
    }

    #[test]
    fn the_table_lists_the_parameters_and_the_first_line_of_the_command() {
        let saved = Saved {
            vault_id: "v".to_owned(),
            vault_name: "team".to_owned(),
            snippet: Snippet {
                snippet_id: "s".to_owned(),
                label: "restart".to_owned(),
                command: "systemctl restart {{service}}\njournalctl -u {{service}}".to_owned(),
                tags: Vec::new(),
            },
        };
        assert_eq!(
            table(&[saved]),
            "restart  team  {{service}}  systemctl restart {{service}} …\n"
        );
    }
}
