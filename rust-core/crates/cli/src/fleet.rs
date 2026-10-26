//! `unissh run`: one command on many hosts, as the app's Fleet screen runs it.
//!
//! Each host resolves on its own with the core's resolver (personal identities,
//! jump hosts and proxies included) and runs through `Core::ssh_exec_multi`
//! with a per-host deadline, a bounded number at a time. That is how Fleet
//! does it rather than through the core's group or tag fan-out, which leaves
//! personal hosts out and files results by address: here each result belongs
//! to its host, and each host can run its own command (a snippet's `{{host}}`).
//!
//! Hosts that want a password typed at every connection are skipped, as in
//! Fleet: a run on many hosts cannot stop to ask for one.

use std::collections::VecDeque;
use std::fmt::Write as _;
use std::io::{self, Write as _};
use std::sync::{mpsc, Mutex, PoisonError};
use std::thread;

use serde_json::{json, Value};
use unissh_ffi::{Core, MultiExecTarget, ResolveStatus, ServerGroup};

use crate::connect;
use crate::failure::{best_effort, Failure, Res, EXIT_FAILURE};
use crate::hosts::{self, Host, Named};
use crate::tty::one_line;

/// How many hosts run at once by default — the app's Fleet limit.
pub const DEFAULT_PARALLEL: u32 = 8;
/// The per-host deadline by default, in seconds — the app's Fleet limit.
pub const DEFAULT_TIMEOUT_SECS: u32 = 30;

/// Which hosts a run goes to.
pub enum Selection {
    /// The hosts carrying every one of these tags (any case).
    Tags(Vec<String>),
    /// The hosts of a group, nested groups included.
    Group(String),
    /// These hosts, named as `unissh ssh` names them.
    Hosts(Vec<String>),
}

/// How a run goes.
pub struct Options {
    /// Hosts at a time (at least one).
    pub parallel: u32,
    /// Per-host deadline in seconds; 0 for none.
    pub timeout_secs: u32,
    /// Show what would run, and where, without connecting.
    pub dry_run: bool,
    /// Print JSON instead of prefixed output.
    pub json: bool,
}

/// A host group and the vault it lives in.
struct Group {
    vault_id: String,
    vault_name: String,
    group: ServerGroup,
}

impl Named for Group {
    const KIND: &'static str = "group";
    const LISTED_BY: Option<&'static str> = None;

    fn vault_name(&self) -> &str {
        &self.vault_name
    }

    fn label(&self) -> &str {
        &self.group.label
    }
}

/// Every group of every vault; a vault that cannot be read is reported and skipped.
fn load_groups(core: &Core) -> Res<Vec<Group>> {
    let mut groups = Vec::new();
    for vault in core.list_vaults()? {
        match core.list_groups(vault.vault_id.clone()) {
            Ok(list) => groups.extend(list.into_iter().map(|group| Group {
                vault_id: vault.vault_id.clone(),
                vault_name: vault.name.clone(),
                group,
            })),
            Err(e) => eprintln!("unissh: skipping vault \"{}\": {e}", one_line(&vault.name)),
        }
    }
    Ok(groups)
}

/// The hosts carrying every tag in `tags`, compared in any case.
fn tagged<'h>(all: &'h [Host], tags: &[String]) -> Vec<&'h Host> {
    all.iter()
        .filter(|h| {
            tags.iter()
                .all(|t| h.profile.tags.iter().any(|own| own.eq_ignore_ascii_case(t)))
        })
        .collect()
}

/// The hosts `selection` picks, each once, in the order picked.
pub fn select<'h>(core: &Core, all: &'h [Host], selection: &Selection) -> Res<Vec<&'h Host>> {
    let picked = match selection {
        Selection::Tags(tags) => {
            let found = tagged(all, tags);
            if found.is_empty() {
                return Err(Failure::msg(format!(
                    "no host carries {}",
                    tags.iter()
                        .map(|t| format!("the tag \"{}\"", one_line(t)))
                        .collect::<Vec<_>>()
                        .join(" and ")
                )));
            }
            found
        }
        Selection::Group(name) => group_hosts(core, all, name)?,
        Selection::Hosts(names) => names
            .iter()
            .map(|name| hosts::find(all, name))
            .collect::<Res<Vec<_>>>()?,
    };
    let mut unique: Vec<&Host> = Vec::with_capacity(picked.len());
    for host in picked {
        if !unique.iter().any(|u| same_host(u, host)) {
            unique.push(host);
        }
    }
    Ok(unique)
}

fn same_host(a: &Host, b: &Host) -> bool {
    a.vault_id == b.vault_id && a.profile.profile_id == b.profile.profile_id
}

/// The hosts of the group `name`, expanded by the core (nested groups, with
/// cycles broken) without connecting anywhere.
fn group_hosts<'h>(core: &Core, all: &'h [Host], name: &str) -> Res<Vec<&'h Host>> {
    let groups = load_groups(core)?;
    let group = hosts::find_named(&groups, name)?;
    let plans = core.dry_run_group(group.vault_id.clone(), group.group.group_id.clone())?;
    let mut found = Vec::new();
    for plan in plans {
        match plan.status {
            ResolveStatus::Ok | ResolveStatus::PromptPassword | ResolveStatus::Personal => {
                if let Some(host) = all.iter().find(|h| {
                    h.vault_id == group.vault_id && h.profile.profile_id == plan.member_id
                }) {
                    found.push(host);
                }
            }
            ResolveStatus::CycleSkipped => eprintln!(
                "unissh: group \"{}\": skipped a nested group (a cycle, or nested too deep)",
                one_line(&group.group.label)
            ),
            // A member whose host was deleted: nothing to run on.
            ResolveStatus::Dangling => {}
        }
    }
    if found.is_empty() {
        return Err(Failure::msg(format!(
            "the group \"{}\" has no hosts",
            one_line(&group.group.label)
        )));
    }
    Ok(found)
}

/// What became of one host.
#[derive(Debug)]
enum Outcome {
    /// Resolved, not run yet (or a dry run).
    Planned,
    /// Not run, on purpose.
    Skipped(String),
    /// Could not be resolved into a connection.
    Unresolved(String),
    /// Ran (or tried to connect).
    Ran(Ran),
}

/// A host's result.
#[derive(Debug)]
struct Ran {
    exit: i32,
    stdout: String,
    stderr: String,
    /// Connecting or running failed (the other fields are then empty).
    error: Option<String>,
    timed_out: bool,
    duration_ms: u64,
}

impl Outcome {
    /// Ran with status 0, or (a dry run) would run.
    fn ok(&self) -> bool {
        matches!(self.status(), "ok" | "planned")
    }

    const fn status(&self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::Skipped(_) => "skipped",
            Self::Unresolved(_) => "failed",
            Self::Ran(r) => {
                if r.error.is_none() && !r.timed_out && r.exit == 0 {
                    "ok"
                } else {
                    "failed"
                }
            }
        }
    }
}

/// One host of a run.
struct Row<'h> {
    host: &'h Host,
    /// How the output names it: its label, or `vault/label` when another
    /// host of the run has the same label.
    name: String,
    /// Where it connects, as resolved (the profile's when it did not resolve).
    user: String,
    address: String,
    port: u16,
    command: String,
    outcome: Outcome,
}

/// The names the output gives `picked`: labels, qualified by vault where two
/// hosts of the run share one.
fn display_names(picked: &[&Host]) -> Vec<String> {
    picked
        .iter()
        .map(|h| {
            let label = &h.profile.label;
            let shared = picked
                .iter()
                .filter(|o| o.profile.label.eq_ignore_ascii_case(label))
                .count()
                > 1;
            let name = if shared {
                format!("{}/{label}", h.vault_name)
            } else {
                label.clone()
            };
            one_line(&name)
        })
        .collect()
}

/// Resolves every picked host. Returns the rows and the work: the targets
/// to run, by row index.
fn plan<'h>(
    core: &Core,
    picked: &[&'h Host],
    command_for: &dyn Fn(&Host) -> String,
) -> (Vec<Row<'h>>, VecDeque<(usize, MultiExecTarget, String)>) {
    let mut rows = Vec::with_capacity(picked.len());
    let mut work = VecDeque::new();
    for (index, (host, name)) in picked
        .iter()
        .copied()
        .zip(display_names(picked))
        .enumerate()
    {
        let command = command_for(host);
        let p = &host.profile;
        let mut row = Row {
            host,
            name,
            user: p.user.clone(),
            address: p.host.clone(),
            port: p.port,
            command: command.clone(),
            outcome: Outcome::Planned,
        };
        match hosts::resolve(core, host, None) {
            Ok(target) if target.ask_password => {
                row.outcome = Outcome::Skipped(
                    "asks for a password at every connection; run it with `unissh ssh`".to_owned(),
                );
            }
            Ok(target) => {
                row.user.clone_from(&target.user);
                row.address.clone_from(&target.host);
                row.port = target.port;
                work.push_back((
                    index,
                    MultiExecTarget {
                        host: target.host,
                        port: target.port,
                        user: target.user,
                        auth: target.auth,
                        jumps: target.jumps,
                        proxy: target.proxy,
                        publickey_only: false,
                    },
                    command,
                ));
            }
            Err(failure) => row.outcome = Outcome::Unresolved(failure.message),
        }
        rows.push(row);
    }
    (rows, work)
}

/// Runs `command_for(host)` on each of `picked` (or shows the plan, for a dry
/// run). The exit code is 0 when every host ran it with status 0 (or, for a
/// dry run, would run it), else 1.
pub fn run(
    core: &Core,
    picked: &[&Host],
    command_for: &dyn Fn(&Host) -> String,
    options: &Options,
) -> Res<u8> {
    if picked.is_empty() {
        return Err(Failure::msg("no hosts to run on"));
    }
    let (mut rows, work) = plan(core, picked, command_for);
    if options.dry_run {
        if options.json {
            print_json(&rows)?;
        } else {
            print!("{}", plan_text(&rows));
            eprintln!("unissh: {}", summary(&rows, true));
        }
        return Ok(exit_of(&rows));
    }
    if !options.json {
        for row in &rows {
            if let Outcome::Skipped(why) | Outcome::Unresolved(why) = &row.outcome {
                eprint!("{}", prefixed(&row.name, &format!("unissh: {why}")));
            }
        }
    }
    execute(core, &mut rows, work, options);
    if options.json {
        print_json(&rows)?;
    } else {
        eprintln!("unissh: {}", summary(&rows, false));
    }
    Ok(exit_of(&rows))
}

fn exit_of(rows: &[Row<'_>]) -> u8 {
    if rows.iter().all(|r| r.outcome.ok()) {
        0
    } else {
        EXIT_FAILURE
    }
}

/// Runs the work `parallel` at a time; each host's output is printed (unless
/// JSON is wanted) as it finishes.
fn execute(
    core: &Core,
    rows: &mut [Row<'_>],
    work: VecDeque<(usize, MultiExecTarget, String)>,
    options: &Options,
) {
    let workers = usize::try_from(options.parallel)
        .unwrap_or(usize::MAX)
        .clamp(1, work.len().max(1));
    let queue = Mutex::new(work);
    let (done, results) = mpsc::channel::<(usize, Ran)>();
    thread::scope(|scope| {
        for _ in 0..workers {
            let done = done.clone();
            let queue = &queue;
            scope.spawn(move || loop {
                let next = queue
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .pop_front();
                let Some((index, target, command)) = next else {
                    break;
                };
                let ran = exec_one(core, target, command, options.timeout_secs);
                if done.send((index, ran)).is_err() {
                    break;
                }
            });
        }
        drop(done);
        for (index, ran) in results {
            let Some(row) = rows.get_mut(index) else {
                continue;
            };
            if !options.json {
                print_ran(&row.name, &ran);
            }
            row.outcome = Outcome::Ran(ran);
        }
    });
}

/// Runs `command` on one host, saying so when the connection pinned a new host key.
fn exec_one(core: &Core, target: MultiExecTarget, command: String, timeout_secs: u32) -> Ran {
    let (host, port) = (target.host.clone(), target.port);
    let new_host = !connect::is_known(core, &host, port);
    let result = core
        .ssh_exec_multi(vec![target], command, 0, timeout_secs)
        .map_err(Failure::from)
        .and_then(|mut results| {
            results
                .pop()
                .ok_or_else(|| Failure::msg("the core returned no result"))
        });
    match result {
        Ok(r) => {
            if new_host {
                connect::announce_pinned(core, &host, port);
            }
            Ran {
                exit: r.exit_status,
                stdout: r.stdout,
                stderr: r.stderr,
                error: r.error,
                timed_out: r.timed_out,
                duration_ms: r.duration_ms,
            }
        }
        Err(failure) => Ran {
            exit: -1,
            stdout: String::new(),
            stderr: String::new(),
            error: Some(failure.message),
            timed_out: false,
            duration_ms: 0,
        },
    }
}

/// One host's output, each line led by its name: stdout to stdout, stderr and
/// what went wrong to stderr.
fn print_ran(name: &str, ran: &Ran) {
    let mut out = io::stdout().lock();
    best_effort(
        out.write_all(prefixed(name, &ran.stdout).as_bytes())
            .and_then(|()| out.flush()),
    );
    drop(out);
    let mut notes = ran.stderr.clone();
    if let Some(error) = &ran.error {
        let hint = if error.starts_with("host key mismatch") {
            " (`unissh ssh` on this host says what to do)"
        } else {
            ""
        };
        let _ = writeln!(notes, "unissh: {error}{hint}");
    } else if ran.exit != 0 {
        let _ = writeln!(notes, "unissh: exit status {}", ran.exit);
    }
    eprint!("{}", prefixed(name, &notes));
}

/// `text` line by line, each led by `name | `. Control characters other than
/// a tab are dropped: one host's output must not move the cursor over another's.
fn prefixed(name: &str, text: &str) -> String {
    let mut out = String::new();
    let text = text.strip_suffix('\n').unwrap_or(text);
    if text.is_empty() {
        return out;
    }
    for line in text.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        let shown: String = line
            .chars()
            .filter(|c| *c == '\t' || !c.is_control())
            .collect();
        let _ = writeln!(out, "{name} | {shown}");
    }
    out
}

/// A dry run: each host, where it connects, and the command it would run.
fn plan_text(rows: &[Row<'_>]) -> String {
    let width = rows
        .iter()
        .map(|r| r.name.chars().count())
        .max()
        .unwrap_or(0)
        .min(32);
    let mut text = String::new();
    for row in rows {
        let at = match &row.outcome {
            Outcome::Skipped(why) => format!("skipped: {why}"),
            Outcome::Unresolved(why) => format!("cannot run: {why}"),
            Outcome::Planned | Outcome::Ran(_) => {
                let user = if row.user.is_empty() {
                    String::new()
                } else {
                    format!("{}@", row.user)
                };
                format!("{user}{}:{}", row.address, row.port)
            }
        };
        let _ = writeln!(text, "{:<width$}  {}", row.name, one_line(&at));
        if matches!(row.outcome, Outcome::Planned) {
            for line in row.command.lines() {
                let _ = writeln!(text, "{:<width$}    $ {}", "", one_line(line));
            }
        }
    }
    text
}

/// `5 hosts: 3 ok, 1 failed, 1 skipped` (for a dry run, `would run`).
fn summary(rows: &[Row<'_>], dry_run: bool) -> String {
    let count = |status: &str| rows.iter().filter(|r| r.outcome.status() == status).count();
    let parts = [
        (
            count(if dry_run { "planned" } else { "ok" }),
            if dry_run { "would run" } else { "ok" },
        ),
        (
            count("failed"),
            if dry_run { "cannot run" } else { "failed" },
        ),
        (count("skipped"), "skipped"),
    ];
    let shown: Vec<String> = parts
        .iter()
        .filter(|(n, _)| *n > 0)
        .map(|(n, what)| format!("{n} {what}"))
        .collect();
    let hosts = if rows.len() == 1 { "host" } else { "hosts" };
    format!("{} {hosts}: {}", rows.len(), shown.join(", "))
}

/// The rows as JSON, in the order the hosts were picked: names, addresses,
/// the command and what it printed; never a credential.
fn json_rows(rows: &[Row<'_>]) -> Value {
    Value::Array(
        rows.iter()
            .map(|row| {
                let mut entry = json!({
                    "vault": row.host.vault_name,
                    "label": row.host.profile.label,
                    "host": row.address,
                    "port": row.port,
                    "user": row.user,
                    "command": row.command,
                    "status": row.outcome.status(),
                });
                let extra = match &row.outcome {
                    Outcome::Planned => json!({}),
                    Outcome::Skipped(why) | Outcome::Unresolved(why) => json!({ "error": why }),
                    Outcome::Ran(r) => json!({
                        "exit": (r.error.is_none() && !r.timed_out).then_some(r.exit),
                        "stdout": r.stdout,
                        "stderr": r.stderr,
                        "error": r.error,
                        "timed_out": r.timed_out,
                        "duration_ms": r.duration_ms,
                    }),
                };
                if let (Some(entry), Value::Object(extra)) = (entry.as_object_mut(), extra) {
                    entry.extend(extra);
                }
                entry
            })
            .collect(),
    )
}

fn print_json(rows: &[Row<'_>]) -> Res<()> {
    let text =
        serde_json::to_string_pretty(&json_rows(rows)).map_err(|e| Failure::msg(e.to_string()))?;
    println!("{text}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use unissh_ffi::{ConnectionProfile, ProfileAuth};

    fn host(vault: &str, label: &str, tags: &[&str]) -> Host {
        Host {
            vault_id: vault.to_owned(),
            vault_name: vault.to_owned(),
            profile: ConnectionProfile {
                profile_id: label.to_owned(),
                uid: String::new(),
                label: label.to_owned(),
                host: format!("{label}.internal"),
                port: 22,
                user: "deploy".to_owned(),
                auth: ProfileAuth::PromptPassword,
                username_template: None,
                jumps: Vec::new(),
                proxy: None,
                tags: tags.iter().map(|t| (*t).to_owned()).collect(),
                startup_snippet_ids: Vec::new(),
                record_sessions: false,
                agent_forward: false,
                color: None,
                icon: None,
            },
        }
    }

    fn ran(exit: i32, error: Option<&str>) -> Outcome {
        Outcome::Ran(Ran {
            exit,
            stdout: String::new(),
            stderr: String::new(),
            error: error.map(str::to_owned),
            timed_out: false,
            duration_ms: 0,
        })
    }

    fn row<'h>(host: &'h Host, outcome: Outcome) -> Row<'h> {
        Row {
            host,
            name: host.profile.label.clone(),
            user: host.profile.user.clone(),
            address: host.profile.host.clone(),
            port: host.profile.port,
            command: "uptime".to_owned(),
            outcome,
        }
    }

    #[test]
    fn tags_pick_the_hosts_carrying_every_one_in_any_case() {
        let hosts = [
            host("team", "web", &["prod", "web"]),
            host("team", "db", &["prod"]),
            host("team", "lab", &["web"]),
        ];
        let labels: Vec<_> = tagged(&hosts, &["PROD".to_owned(), "web".to_owned()])
            .iter()
            .map(|h| h.profile.label.clone())
            .collect();
        assert_eq!(labels, ["web"]);
    }

    #[test]
    fn a_label_two_hosts_share_is_shown_with_its_vault() {
        let hosts = [
            host("team", "db", &[]),
            host("lab", "db", &[]),
            host("team", "web", &[]),
        ];
        let picked: Vec<&Host> = hosts.iter().collect();
        assert_eq!(display_names(&picked), ["team/db", "lab/db", "web"]);
    }

    #[test]
    fn every_output_line_is_led_by_the_host_and_cleaned_of_control_characters() {
        assert_eq!(
            prefixed("web", "up 3 days\r\n\x1b[2Jcol\tumn\n"),
            "web | up 3 days\nweb | [2Jcol\tumn\n"
        );
        assert_eq!(prefixed("web", ""), "", "no output, no lines");
    }

    #[test]
    fn the_run_fails_when_any_host_did_not_run_with_status_zero() {
        let h = host("team", "web", &[]);
        assert_eq!(exit_of(&[row(&h, ran(0, None)), row(&h, ran(0, None))]), 0);
        for bad in [
            ran(3, None),
            ran(-1, Some("connection refused")),
            Outcome::Skipped("asks".to_owned()),
            Outcome::Unresolved("no identity".to_owned()),
        ] {
            assert_eq!(exit_of(&[row(&h, ran(0, None)), row(&h, bad)]), 1);
        }
    }

    #[test]
    fn the_summary_counts_only_what_happened() {
        let h = host("team", "web", &[]);
        let rows = [
            row(&h, ran(0, None)),
            row(&h, ran(1, None)),
            row(&h, Outcome::Skipped("asks".to_owned())),
        ];
        assert_eq!(summary(&rows, false), "3 hosts: 1 ok, 1 failed, 1 skipped");
        assert_eq!(
            summary(&[row(&h, Outcome::Planned)], true),
            "1 host: 1 would run"
        );
    }

    #[test]
    fn a_dry_run_shows_where_each_host_connects_and_the_command_it_would_run() {
        let web = host("team", "web", &[]);
        let db = host("team", "db", &[]);
        let mut planned = row(&web, Outcome::Planned);
        planned.command = "cd /srv\nmake".to_owned();
        let text = plan_text(&[planned, row(&db, Outcome::Skipped("asks".to_owned()))]);
        assert_eq!(
            text,
            "web  deploy@web.internal:22\n       $ cd /srv\n       $ make\ndb   skipped: asks\n"
        );
    }

    #[test]
    fn json_carries_the_exit_only_for_a_command_that_ran_to_the_end() {
        let h = host("team", "web", &[]);
        let rows = [row(&h, ran(2, None)), row(&h, ran(-1, Some("refused")))];
        let value = json_rows(&rows);
        assert_eq!(value[0]["status"], "failed");
        assert_eq!(value[0]["exit"], 2);
        assert_eq!(value[1]["exit"], Value::Null);
        assert_eq!(value[1]["error"], "refused");
        assert_eq!(value[0]["command"], "uptime");
    }
}
