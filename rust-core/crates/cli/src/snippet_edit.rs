//! Writing snippets: `unissh snippets add|edit|rm`, as the app's snippet
//! editor does; listing and running them is `unissh snippets list|run`.
//!
//! A snippet's command is vault content, encrypted and synced, but it is not a
//! secret the way a password is: it may be given with `--command`, piped on
//! stdin, or written in `$VISUAL` / `$EDITOR`.

use std::io::{self, Read as _};
use std::path::Path;
use std::process::{Command, ExitStatus};
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Args, Subcommand};
use unissh_ffi::{Core, Snippet};

use crate::device::Device;
use crate::edit::{self, commit, list, mint_id, without_line_ending, VaultArg};
use crate::failure::{best_effort, Failure, Res};
use crate::hosts::{find_named, Kind, Named};
use crate::manage::confirm;
use crate::tty::one_line;

/// Snippets, for lookups.
pub const SNIPPETS: Kind = Kind {
    one: "snippet",
    many: "snippets",
    list: "unissh snippets list",
};

/// A snippet and the vault it lives in.
pub struct SnippetEntry {
    /// The vault's id.
    pub vault_id: String,
    /// The vault's name.
    pub vault_name: String,
    /// The snippet.
    pub snippet: Snippet,
}

impl Named for SnippetEntry {
    fn vault_name(&self) -> &str {
        &self.vault_name
    }

    fn label(&self) -> &str {
        &self.snippet.label
    }

    fn alias(&self) -> &str {
        &self.snippet.snippet_id
    }

    fn detail(&self) -> String {
        first_line(&self.snippet.command)
    }
}

/// The first line of `command`, at most 40 characters: the app's default
/// label, and what tells two snippets with one label apart.
fn first_line(command: &str) -> String {
    command
        .trim()
        .lines()
        .next()
        .unwrap_or_default()
        .chars()
        .take(40)
        .collect()
}

/// Every snippet, or those of the vault `scope` names.
pub fn load(core: &Core, scope: Option<&str>) -> Res<Vec<SnippetEntry>> {
    let mut out = Vec::new();
    for vault in core.list_vaults()? {
        if !edit::in_scope(scope, &vault.vault_id) {
            continue;
        }
        match core.list_snippets(vault.vault_id.clone()) {
            Ok(snippets) => out.extend(snippets.into_iter().map(|snippet| SnippetEntry {
                vault_id: vault.vault_id.clone(),
                vault_name: vault.name.clone(),
                snippet,
            })),
            Err(e) => eprintln!("unissh: skipping vault \"{}\": {e}", one_line(&vault.name)),
        }
    }
    Ok(out)
}

/// The id of the snippet `query` names in vault `vault_id` — for a host's
/// startup snippets, which run from the host's own vault.
pub fn find_in(core: &Core, vault_id: &str, query: &str) -> Res<String> {
    let all = load(core, Some(vault_id))?;
    Ok(find_named(&all, query, &SNIPPETS)?
        .snippet
        .snippet_id
        .clone())
}

/// Where a snippet's command comes from.
#[derive(Args)]
pub struct Body {
    /// The command itself.
    #[arg(long, value_name = "COMMAND", conflicts_with_all = ["stdin", "editor"])]
    command: Option<String>,
    /// Read the command from stdin.
    #[arg(long, conflicts_with = "editor")]
    stdin: bool,
    /// Write the command in $VISUAL or $EDITOR (what `add` does by default).
    #[arg(long)]
    editor: bool,
}

impl Body {
    const fn given(&self) -> bool {
        self.command.is_some() || self.stdin || self.editor
    }

    /// The command: given, piped, or written in the editor starting from
    /// `current`.
    fn read(self, current: &str) -> Res<String> {
        let text = if let Some(command) = self.command {
            command
        } else if self.stdin {
            let mut text = String::new();
            io::stdin().read_to_string(&mut text)?;
            without_line_ending(&text).to_owned()
        } else {
            let text = in_editor(current)?;
            without_line_ending(&text).to_owned()
        };
        if text.trim().is_empty() {
            return Err(Failure::msg("a snippet needs a command; nothing was saved"));
        }
        Ok(text)
    }
}

/// `unissh snippets add|edit|rm`.
#[derive(Subcommand)]
pub enum SnippetWrite {
    /// Add a snippet. `{{name}}` in the command is a parameter, asked when it
    /// runs (`{{name=default}}` gives a default).
    Add {
        /// Its label [default: the command's first line].
        #[arg(long)]
        label: Option<String>,
        /// Tags, comma-separated.
        #[arg(long, value_name = "TAGS")]
        tags: Option<String>,
        #[command(flatten)]
        body: Body,
        #[command(flatten)]
        vault: VaultArg,
    },
    /// Change a snippet: its label, tags or command. Without a flag the
    /// command opens in the editor.
    Edit {
        /// The snippet (label, vault/label or id).
        name: String,
        /// A new label.
        #[arg(long)]
        label: Option<String>,
        /// Tags, comma-separated; empty for none.
        #[arg(long, value_name = "TAGS")]
        tags: Option<String>,
        #[command(flatten)]
        body: Body,
        #[command(flatten)]
        vault: VaultArg,
    },
    /// Delete a snippet.
    Rm {
        /// The snippet (label, vault/label or id).
        name: String,
        #[command(flatten)]
        vault: VaultArg,
        /// Do not ask for confirmation.
        #[arg(long)]
        yes: bool,
    },
}

/// Runs `unissh snippets add|edit|rm`.
pub fn run(device: &Device, offline: bool, action: SnippetWrite) -> Res<()> {
    let core = &device.core;
    match action {
        SnippetWrite::Add {
            label,
            tags,
            body,
            vault,
        } => {
            let target = vault.pick(core, None)?;
            let command = body.read("")?;
            let label = label
                .as_deref()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map_or_else(|| first_line(&command), str::to_owned);
            let snippet = Snippet {
                snippet_id: mint_id(&label, "snippet"),
                label: label.clone(),
                command,
                tags: tags.as_deref().map(list).unwrap_or_default(),
            };
            core.save_snippet(target.vault_id, snippet)?;
            commit(
                device,
                offline,
                &format!("Added snippet {}", one_line(&label)),
            )
        }
        SnippetWrite::Edit {
            name,
            label,
            tags,
            body,
            vault,
        } => {
            let scope = vault.scope(core)?;
            let all = load(core, scope.as_deref())?;
            let found = find_named(&all, &name, &SNIPPETS)?;
            let mut snippet = found.snippet.clone();
            let only_fields = !body.given() && (label.is_some() || tags.is_some());
            if !only_fields {
                snippet.command = body.read(&snippet.command)?;
            }
            if let Some(label) = label {
                let label = label.trim();
                snippet.label = if label.is_empty() {
                    first_line(&snippet.command)
                } else {
                    label.to_owned()
                };
            }
            if let Some(tags) = tags {
                snippet.tags = list(&tags);
            }
            let shown = one_line(&snippet.label);
            core.save_snippet(found.vault_id.clone(), snippet)?;
            commit(device, offline, &format!("Changed snippet {shown}"))
        }
        SnippetWrite::Rm { name, vault, yes } => {
            let scope = vault.scope(core)?;
            let all = load(core, scope.as_deref())?;
            let found = find_named(&all, &name, &SNIPPETS)?;
            let id = &found.snippet.snippet_id;
            let mut warning = format!(
                "This deletes the snippet \"{}\" from vault \"{}\".\n",
                one_line(&found.snippet.label),
                one_line(&found.vault_name)
            );
            let starting = core
                .list_connections(found.vault_id.clone())?
                .iter()
                .filter(|p| p.startup_snippet_ids.contains(id))
                .count();
            if starting > 0 {
                warning.push_str(&format!(
                    "{starting} host(s) run it after connecting; they will no longer.\n"
                ));
            }
            confirm(yes, &warning)?;
            core.delete_snippet(found.vault_id.clone(), id.clone())?;
            commit(
                device,
                offline,
                &format!("Deleted snippet {}", one_line(&found.snippet.label)),
            )
        }
    }
}

/// Lets the user write `current` over in their editor and returns what they
/// saved. The file is owner-only and removed afterwards.
fn in_editor(current: &str) -> Res<String> {
    let editor = ["VISUAL", "EDITOR"]
        .iter()
        .filter_map(|name| std::env::var(name).ok())
        .find(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "vi".to_owned());
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis());
    let path =
        std::env::temp_dir().join(format!("unissh-snippet-{}-{millis}.sh", std::process::id()));
    write_private(&path, current)?;
    let edited = launch(&editor, &path).and_then(|status| {
        if status.success() {
            std::fs::read_to_string(&path).map_err(Failure::from)
        } else {
            Err(Failure::msg(format!(
                "the editor ({editor}) exited with {status}; nothing was saved"
            )))
        }
    });
    best_effort(std::fs::remove_file(&path));
    edited
}

/// Creates `path` (it must not exist) readable by its owner only.
fn write_private(path: &Path, text: &str) -> Res<()> {
    use std::io::Write as _;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|e| Failure::msg(format!("cannot create {}: {e}", path.display())))?;
    file.write_all(text.as_bytes())?;
    Ok(())
}

/// Runs `editor` on `path` as git does: through the shell, so a value like
/// `code --wait` works.
fn launch(editor: &str, path: &Path) -> Res<ExitStatus> {
    #[cfg(unix)]
    let mut command = {
        let mut c = Command::new("sh");
        c.arg("-c").arg(format!("{editor} \"$@\"")).arg(editor);
        c
    };
    #[cfg(not(unix))]
    let mut command = Command::new(editor);
    command
        .arg(path)
        .status()
        .map_err(|e| Failure::msg(format!("cannot start the editor ({editor}): {e}")))
}

#[cfg(test)]
mod tests {
    use super::first_line;

    /// A snippet without a label is named after its command, as in the app.
    #[test]
    fn the_default_label_is_the_commands_first_line_cut_to_40() {
        assert_eq!(
            first_line("  systemctl restart nginx\nsecond"),
            "systemctl restart nginx"
        );
        assert_eq!(first_line(&"x".repeat(60)).len(), 40);
    }
}
