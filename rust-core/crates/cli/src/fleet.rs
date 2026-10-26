//! `unissh run`: one command on many hosts, as the app's Fleet screen runs it.
//!
//! Each host resolves on its own with the core's resolver (personal identities,
//! jump hosts and proxies included) and runs through `Core::ssh_exec_multi`
//! with a per-host deadline, a bounded number at a time. That is how Fleet
//! does it rather than through the core's group or tag fan-out: the group
//! fan-out leaves personal hosts out, the tag fan-out drops unbound personal
//! hosts and password-prompt ones without a word and covers one vault, and
//! both file results by address and run one command everywhere. Here each
//! result belongs to its host, and each host can run its own command (its
//! `{{host}}`).
//!
//! Hosts that want a password typed at every connection are skipped, as in
//! Fleet: a run on many hosts cannot stop to ask for one.
//!
//! A run goes in two steps, as Fleet's does: [`plan`] resolves every host,
//! then the caller fills the command's parameters for the hosts that will run
//! ([`Plan::params`]) and [`run`] runs it.

use std::collections::VecDeque;
use std::fmt::Write as _;
use std::io::{self, Write as _};
use std::sync::{mpsc, Mutex, PoisonError};
use std::thread;

use serde_json::{json, Value};
use unissh_ffi::snippet_params::{builtins_from_profile, split_fleet_params, FleetParams};
use unissh_ffi::{Core, MultiExecTarget, ResolveStatus};

use crate::connect;
use crate::failure::{best_effort, Failure, Res, EXIT_FAILURE};
use crate::hosts::{self, Host};
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
    let groups = hosts::load_groups(core)?;
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
    /// What it runs (set by [`run`]).
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

/// A run's hosts, resolved: where each connects, or why it will not run.
pub struct Plan<'h> {
    rows: Vec<Row<'h>>,
    /// The targets to run, by row index.
    work: VecDeque<(usize, MultiExecTarget)>,
}

impl Plan<'_> {
    /// The command's parameters for this run: split over the hosts that will
    /// run, as Fleet splits over its runnable hosts. A skipped or unresolved
    /// host neither answers a built-in nor makes one be asked.
    pub fn params(&self, command: &str) -> FleetParams {
        let targets: Vec<_> = self
            .rows
            .iter()
            .filter(|r| matches!(r.outcome, Outcome::Planned))
            .map(|r| builtins_from_profile(&r.host.profile))
            .collect();
        split_fleet_params(command, &targets)
    }

    /// Whether no host will run.
    pub fn nothing_runs(&self) -> bool {
        self.work.is_empty()
    }
}

/// What a host with no user is told to do in a run.
fn no_user_hint(label: &str) -> String {
    format!(
        "give it a user in the UniSSH app, or run on it with `unissh ssh user@{label} -- COMMAND`"
    )
}

/// Resolves every picked host, without connecting.
pub fn plan<'h>(core: &Core, picked: &[&'h Host]) -> Res<Plan<'h>> {
    if picked.is_empty() {
        return Err(Failure::msg("no hosts to run on"));
    }
    let mut rows = Vec::with_capacity(picked.len());
    let mut work = VecDeque::new();
    for (index, (host, name)) in picked
        .iter()
        .copied()
        .zip(display_names(picked))
        .enumerate()
    {
        let p = &host.profile;
        let mut row = Row {
            host,
            name,
            user: p.user.clone(),
            address: p.host.clone(),
            port: p.port,
            command: String::new(),
            outcome: Outcome::Planned,
        };
        match hosts::resolve_with_hint(core, host, None, &no_user_hint) {
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
                ));
            }
            Err(failure) => row.outcome = Outcome::Unresolved(failure.message),
        }
        rows.push(row);
    }
    Ok(Plan { rows, work })
}

/// Runs `command_for(host)` on each host of `plan` that resolved (or shows
/// the plan, for a dry run). The exit code is 0 when every host ran it with
/// status 0 (or, for a dry run, would run it), else 1.
pub fn run(
    core: &Core,
    plan: Plan<'_>,
    command_for: &dyn Fn(&Host) -> String,
    options: &Options,
) -> Res<u8> {
    let Plan { mut rows, work } = plan;
    for row in &mut rows {
        row.command = command_for(row.host);
    }
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
    let work = work
        .into_iter()
        .filter_map(|(index, target)| {
            let command = rows.get(index)?.command.clone();
            Some((index, target, command))
        })
        .collect();
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
/// the command and what it printed; never a credential. Every entry has every
/// key: `exit` and `duration_ms` are null for a command that did not run (and
/// `exit` for one that did not run to the end), `error` is null when nothing
/// went wrong.
fn json_rows(rows: &[Row<'_>]) -> Value {
    Value::Array(
        rows.iter()
            .map(|row| {
                let (exit, stdout, stderr, error, timed_out, duration_ms) = match &row.outcome {
                    Outcome::Planned => (None, "", "", None, false, None),
                    Outcome::Skipped(why) | Outcome::Unresolved(why) => {
                        (None, "", "", Some(why.as_str()), false, None)
                    }
                    Outcome::Ran(r) => (
                        (r.error.is_none() && !r.timed_out).then_some(r.exit),
                        r.stdout.as_str(),
                        r.stderr.as_str(),
                        r.error.as_deref(),
                        r.timed_out,
                        Some(r.duration_ms),
                    ),
                };
                json!({
                    "vault": row.host.vault_name,
                    "label": row.host.profile.label,
                    "host": row.address,
                    "port": row.port,
                    "user": row.user,
                    "command": row.command,
                    "status": row.outcome.status(),
                    "exit": exit,
                    "stdout": stdout,
                    "stderr": stderr,
                    "error": error,
                    "timed_out": timed_out,
                    "duration_ms": duration_ms,
                })
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

    #[test]
    fn every_json_entry_has_every_key_whatever_became_of_the_host() {
        let h = host("team", "web", &[]);
        let rows = [
            row(&h, ran(0, None)),
            row(&h, Outcome::Planned),
            row(&h, Outcome::Skipped("asks".to_owned())),
            row(&h, Outcome::Unresolved("no identity".to_owned())),
        ];
        let value = json_rows(&rows);
        let keys = |i: usize| {
            value[i]
                .as_object()
                .map(|o| o.keys().cloned().collect::<Vec<_>>())
                .unwrap_or_default()
        };
        assert_eq!(keys(0).len(), 13, "{:?}", keys(0));
        for i in 1..rows.len() {
            assert_eq!(keys(i), keys(0), "entry {i}");
        }
    }

    #[test]
    fn a_skipped_host_does_not_add_a_parameter_to_ask() {
        let web = host("team", "web", &[]);
        let mut no_user = host("team", "lab", &[]);
        no_user.profile.user = String::new();
        let plan = Plan {
            rows: vec![
                row(&web, Outcome::Planned),
                row(&no_user, Outcome::Skipped("asks".to_owned())),
            ],
            work: VecDeque::new(),
        };
        let params = plan.params("id {{user}}");
        assert!(params.ask.is_empty(), "{:?}", params.ask);
        assert_eq!(params.from_host, ["user"]);
    }
}
