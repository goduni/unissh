//! `unissh keys rotation`: the app's guided staged key rotation, on the
//! core's planner and driver (`unissh_ffi::key_rotation_plan`) — the same
//! plan, the same steps and the same remote commands as the app's rotation
//! dialog.
//!
//! - `begin` generates the new key beside the original (the candidate) and
//!   shows which machines have to learn it;
//! - `run` deploys the candidate on each machine and proves a key-only login
//!   with it. It removes nothing, so it can be run again — for some machines
//!   with `--host` — until every machine takes the candidate;
//! - `finish` checks the candidate on every machine again, says which ones a
//!   finish would lock out and asks; then it removes the old key where the
//!   candidate logs in, checks the old key is refused there, and commits the
//!   candidate into the key item;
//! - `list` and `abandon`.
//!
//! What a run learned is not stored: the steps are idempotent, so each command
//! finds out again where the machines stand, as the app's dialog does when it
//! is reopened. The staged state is the candidate itself, in the core.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use clap::Subcommand;
use serde_json::{json, Value};
use unissh_ffi::key_rotation_plan::{
    RotationDriver, RotationPlan, RotationRun, RotationSkipReason, RotationStep, RotationTarget,
    RunScope, TargetState,
};
use unissh_ffi::{Core, KeyRotationLink};

use crate::device::Device;
use crate::edit::{self, columns, commit, print_json, stored, VaultArg};
use crate::failure::{Failure, Res};
use crate::fleet::{DEFAULT_PARALLEL, DEFAULT_TIMEOUT_SECS};
use crate::hosts;
use crate::secrets::{find_one, Key};
use crate::signals;
use crate::tty::{confirm, one_line};

/// `unissh keys rotation`.
#[derive(Subcommand)]
pub enum RotationAction {
    /// Begin a guided rotation of a key: generate the new key beside it and
    /// show which machines have to learn it.
    Begin {
        /// The key's name (or vault/name).
        name: String,
        #[command(flatten)]
        vault: VaultArg,
    },
    /// Deploy the new key on each machine and prove a key-only login with
    /// it. Removes nothing: run it again until every machine passes.
    Run {
        /// The original key's name, or its candidate's.
        name: String,
        #[command(flatten)]
        vault: VaultArg,
        /// Only this machine (a host's label, user@host[:port] or address).
        /// Repeat for several.
        #[arg(long = "host", value_name = "NAME")]
        hosts: Vec<String>,
        /// Print JSON.
        #[arg(long)]
        json: bool,
    },
    /// Check the new key on every machine, then remove the old key where the
    /// new one logs in, check that the old key is refused, and make the new
    /// key the key's current version.
    Finish {
        /// The original key's name, or its candidate's.
        name: String,
        #[command(flatten)]
        vault: VaultArg,
        /// Do not ask for confirmation.
        #[arg(long)]
        yes: bool,
        /// With --yes: finish even though machines where the new key does not
        /// log in would be locked out.
        #[arg(long, requires = "yes")]
        allow_lockout: bool,
    },
    /// List the rotations in progress.
    List {
        #[command(flatten)]
        vault: VaultArg,
        /// Print JSON.
        #[arg(long)]
        json: bool,
    },
    /// Abandon a rotation: delete its candidate key; the original is not
    /// changed.
    Abandon {
        /// The original key's name, or its candidate's.
        name: String,
        #[command(flatten)]
        vault: VaultArg,
        /// Do not ask for confirmation.
        #[arg(long)]
        yes: bool,
    },
}

/// Runs `unissh keys rotation`.
pub fn rotation(device: &Device, offline: bool, action: RotationAction) -> Res<()> {
    match action {
        RotationAction::Begin { name, vault } => begin(device, offline, &vault, &name),
        RotationAction::Run {
            name,
            vault,
            hosts,
            json,
        } => run(&device.core, &vault, &name, &hosts, json),
        RotationAction::Finish {
            name,
            vault,
            yes,
            allow_lockout,
        } => finish(device, offline, &vault, &name, yes, allow_lockout),
        RotationAction::List { vault, json } => list(&device.core, &vault, json),
        RotationAction::Abandon { name, vault, yes } => {
            abandon(device, offline, &vault, &name, yes)
        }
    }
}

/// A rotation and the vault it is in.
struct Rotation {
    vault_id: String,
    vault_name: String,
    link: KeyRotationLink,
}

fn load_rotations(core: &Core, vault: &VaultArg) -> Res<Vec<Rotation>> {
    let scope = vault.scope(core)?;
    hosts::per_vault(
        core,
        |vault_id| {
            if edit::in_scope(scope.as_deref(), &vault_id) {
                core.list_key_rotations(vault_id)
            } else {
                Ok(Vec::new())
            }
        },
        |vault_id, vault_name, link| Rotation {
            vault_id: vault_id.to_owned(),
            vault_name: vault_name.to_owned(),
            link,
        },
    )
}

/// The rotation of the key `name` names (or of the candidate it names), the
/// key looked up as `begin` and every other key command look it up.
fn find_rotation(core: &Core, vault: &VaultArg, name: &str) -> Res<Rotation> {
    let key = find_one::<Key>(core, vault, name)?;
    let id = &key.info.item_id;
    let link = core
        .list_key_rotations(key.vault_id.clone())?
        .into_iter()
        .find(|l| &l.key_id == id || &l.candidate_id == id)
        .ok_or_else(|| {
            Failure::msg(format!(
                "no rotation of \"{}\" is in progress (`unissh keys rotation list`)",
                one_line(id)
            ))
        })?;
    Ok(Rotation {
        vault_id: key.vault_id,
        vault_name: key.vault_name,
        link,
    })
}

/// [`find_rotation`], for moving machines: only a rotation begun on this
/// device can be run or finished.
fn own_rotation(core: &Core, vault: &VaultArg, name: &str) -> Res<Rotation> {
    let rotation = find_rotation(core, vault, name)?;
    if rotation.link.started_elsewhere {
        return Err(Failure::msg(format!(
            "the rotation of \"{}\" was started on another device: run and finish it there, or \
             abandon it here (`unissh keys rotation abandon`)",
            one_line(&rotation.link.key_id)
        )));
    }
    Ok(rotation)
}

const fn started(link: &KeyRotationLink) -> &'static str {
    if link.started_elsewhere {
        "started on another device"
    } else {
        "started here"
    }
}

fn list(core: &Core, vault: &VaultArg, json: bool) -> Res<()> {
    let all = load_rotations(core, vault)?;
    if json {
        return print_json(&Value::Array(
            all.iter()
                .map(|r| {
                    json!({
                        "vault": r.vault_name,
                        "key": r.link.key_id,
                        "candidate": r.link.candidate_id,
                        "started_elsewhere": r.link.started_elsewhere,
                    })
                })
                .collect(),
        ));
    }
    if all.is_empty() {
        eprintln!("unissh: no key rotation is in progress");
        return Ok(());
    }
    let rows: Vec<Vec<String>> = all
        .iter()
        .map(|r| {
            vec![
                r.link.key_id.clone(),
                format!("→ {}", r.link.candidate_id),
                r.vault_name.clone(),
                started(&r.link).to_owned(),
            ]
        })
        .collect();
    print!("{}", columns(&rows));
    Ok(())
}

fn abandon(device: &Device, offline: bool, vault: &VaultArg, name: &str, yes: bool) -> Res<()> {
    let rotation = find_rotation(&device.core, vault, name)?;
    let link = &rotation.link;
    let (key, candidate) = (one_line(&link.key_id), one_line(&link.candidate_id));
    let elsewhere = if link.started_elsewhere {
        " (started on another device)"
    } else {
        ""
    };
    // Said either way: a rotation run on another device may have removed the
    // old key from machines just as well.
    let warning = format!(
        "The candidate key \"{candidate}\"{elsewhere} will be deleted. \"{key}\" is not changed.\n\
         Any machine where the rotation already removed the old key accepts only\n\
         \"{candidate}\": deleting it locks you out of that machine.\n"
    );
    confirm(yes, &warning)?;
    stored(
        &rotation.vault_name,
        device
            .core
            .abandon_key_rotation(rotation.vault_id.clone(), link.candidate_id.clone()),
    )?;
    commit(
        device,
        &rotation.vault_id,
        offline,
        &format!("Abandoned the rotation of {key}"),
    )
}

// ---------- begin ----------

fn begin(device: &Device, offline: bool, vault: &VaultArg, name: &str) -> Res<()> {
    let core = &device.core;
    let key = find_one::<Key>(core, vault, name)?;
    let id = key.info.item_id.clone();
    // The plan first: a key no host logs in with has no machine to move.
    let plan = core.plan_key_rotation(key.vault_id.clone(), id.clone())?;
    if plan.targets.is_empty() {
        return Err(Failure::msg(format!(
            "no host logs in with \"{0}\", so no machine has to learn a new key; replace it at \
             once with `unissh keys rotate \"{0}\"`",
            one_line(&id)
        )));
    }
    print!("{}", plan_text(&plan));
    let candidate = stored(
        &key.vault_name,
        core.begin_key_rotation(key.vault_id.clone(), id.clone()),
    )?;
    if key.info.has_certificate {
        eprintln!(
            "unissh: the certificate on \"{}\" certifies the old key; finishing removes it",
            one_line(&id)
        );
    }
    commit(
        device,
        &key.vault_id,
        offline,
        &format!(
            "Began the rotation of {} (new key \"{}\")",
            one_line(&id),
            one_line(&candidate)
        ),
    )?;
    eprintln!(
        "unissh: next, `unissh keys rotation run \"{}\"` deploys the new key and checks it on each machine",
        one_line(&id)
    );
    Ok(())
}

/// Where a target is and how it is reached: `user@host[:port]`, the host it
/// is a hop of, the hops and proxy in front of it.
fn target_detail(t: &RotationTarget) -> String {
    let mut text = if t.port == 22 {
        format!("{}@{}", t.user, t.host)
    } else {
        format!("{}@{}:{}", t.user, t.host, t.port)
    };
    if let Some(via) = &t.via {
        text.push_str(&format!(" · hop of {}", via.label));
    }
    if !t.route.is_empty() {
        text.push_str(&format!(" · via {}", t.route.join(" → ")));
    }
    if let Some(p) = &t.proxy {
        text.push_str(&format!(" · proxy {}:{}", p.host, p.port));
    }
    text
}

const fn skip_reason(reason: RotationSkipReason) -> &'static str {
    match reason {
        RotationSkipReason::Personal => "personal login, which the rotation does not own",
        RotationSkipReason::SystemAgent => "system agent key, not in the vault",
        RotationSkipReason::Password => "password login",
    }
}

/// The plan as the app's dialog lists it.
fn plan_text(plan: &RotationPlan) -> String {
    let mut text = String::new();
    if plan.targets.is_empty() {
        text.push_str("No host logs in with this key: there is no machine to move.\n");
    } else {
        text.push_str("Machines that get the new key:\n");
        let rows: Vec<Vec<String>> = plan
            .targets
            .iter()
            .map(|t| vec![format!("  {}", t.label()), target_detail(t)])
            .collect();
        text.push_str(&columns(&rows));
        if plan.has_shared_endpoint() {
            text.push_str(
                "One login is reached over more than one route: each route is switched and \
                 reported on its own.\n",
            );
        }
    }
    if !plan.dependents.is_empty() {
        text.push_str("Hosts that follow (they hop through a machine above):\n");
        let label_of = |id: &String| {
            plan.target(id)
                .map_or_else(|| id.clone(), RotationTarget::label)
        };
        let rows: Vec<Vec<String>> = plan
            .dependents
            .iter()
            .map(|d| {
                let through: Vec<String> = d.target_ids.iter().map(label_of).collect();
                vec![
                    format!("  {}", d.host.label),
                    format!("through {}", through.join(", ")),
                ]
            })
            .collect();
        text.push_str(&columns(&rows));
    }
    if !plan.skipped.is_empty() {
        text.push_str("Left alone:\n");
        let rows: Vec<Vec<String>> = plan
            .skipped
            .iter()
            .map(|s| {
                vec![
                    format!("  {}", s.host.label),
                    skip_reason(s.reason).to_owned(),
                ]
            })
            .collect();
        text.push_str(&columns(&rows));
    }
    text
}

// ---------- run and finish ----------

/// What a step of `id` that just landed comes to, as a progress line; `None`
/// while one is in flight.
fn progress_line(plan: &RotationPlan, id: &str, run: &RotationRun) -> Option<String> {
    let label = plan
        .target(id)
        .map_or_else(|| id.to_owned(), RotationTarget::label);
    let what = match run.state(id)? {
        TargetState::Running { .. } => return None,
        TargetState::Pending { step } => format!("{} ok", step.previous()?.name()),
        TargetState::Failed { step, failure } => {
            format!("{} failed: {}", step.name(), failure.describe())
        }
        TargetState::Switched | TargetState::KeptOld { .. } | TargetState::Unconfirmed => {
            verdict(run, id)
        }
    };
    Some(one_line(&format!("{label}: {what}")))
}

/// Where target `id` stands after a run.
fn verdict(run: &RotationRun, id: &str) -> String {
    match run.state(id) {
        None => "not in this run".to_owned(),
        Some(TargetState::Switched) => {
            "switched: the new key logs in, the old key is refused".to_owned()
        }
        Some(TargetState::Pending { .. }) if run.is_verified(id) => {
            "the new key logs in".to_owned()
        }
        Some(TargetState::Pending { .. }) => "not run".to_owned(),
        Some(TargetState::Running { step }) => format!("{} running", step.name()),
        Some(TargetState::Failed { step, failure }) => {
            format!("{} failed: {}", step.name(), failure.describe())
        }
        Some(TargetState::KeptOld { .. }) => "stopped: the old key is still authorized".to_owned(),
        Some(TargetState::Unconfirmed) => {
            "stopped after the old line was removed: the old key was not checked".to_owned()
        }
    }
}

/// The run machine by machine.
fn results_text(plan: &RotationPlan, run: &RotationRun) -> String {
    let rows: Vec<Vec<String>> = plan
        .targets
        .iter()
        .map(|t| vec![t.label(), target_detail(t), verdict(run, &t.id)])
        .collect();
    columns(&rows)
}

fn results_json(plan: &RotationPlan, run: &RotationRun) -> Value {
    Value::Array(
        plan.targets
            .iter()
            .map(|t| {
                let (state, step, error) = match run.state(&t.id) {
                    None => ("skipped", None, None),
                    Some(TargetState::Pending { step }) => ("pending", Some(step.name()), None),
                    Some(TargetState::Running { step }) => ("running", Some(step.name()), None),
                    Some(TargetState::Failed { step, failure }) => {
                        ("failed", Some(step.name()), Some(failure.describe()))
                    }
                    Some(TargetState::Switched) => ("switched", None, None),
                    Some(TargetState::KeptOld { .. }) => ("kept_old", None, None),
                    Some(TargetState::Unconfirmed) => ("unconfirmed", None, None),
                };
                json!({
                    "machine": t.label(),
                    "id": t.id,
                    "state": state,
                    "step": step,
                    "new_key_works": run.is_verified(&t.id),
                    "error": error,
                })
            })
            .collect(),
    )
}

/// The targets of `plan` that `names` choose (a target's label, its
/// `user@host[:port]` or address, or a host that hops through it), `None`
/// for no names (all of them).
fn select(plan: &RotationPlan, names: &[String]) -> Res<Option<BTreeSet<String>>> {
    if names.is_empty() {
        return Ok(None);
    }
    let mut chosen = BTreeSet::new();
    for name in names {
        let before = chosen.len();
        for t in &plan.targets {
            let login = format!("{}@{}", t.user, t.host);
            let login_port = format!("{login}:{}", t.port);
            if [t.label(), login, login_port, t.host.clone()].contains(name) {
                chosen.insert(t.id.clone());
            }
        }
        for d in plan.dependents.iter().filter(|d| &d.host.label == name) {
            chosen.extend(d.target_ids.iter().cloned());
        }
        if chosen.len() == before {
            let known: Vec<String> = plan.targets.iter().map(RotationTarget::label).collect();
            return Err(Failure::msg(format!(
                "\"{}\" is not a machine of this rotation; its machines: {}",
                one_line(name),
                one_line(&known.join(", "))
            )));
        }
    }
    Ok(Some(chosen))
}

/// The host to connect to so that target `id` gets pinned: its own host, or
/// for a hop the host it is a hop of.
fn connect_host(plan: &RotationPlan, id: &str) -> String {
    plan.target(id).map_or_else(
        || id.to_owned(),
        |t| {
            t.via
                .as_ref()
                .or(t.profile.as_ref())
                .map_or_else(|| t.label(), |h| h.label.clone())
        },
    )
}

/// The refusal for targets reached over a machine whose host key is not
/// pinned yet (`Core::key_rotation_unpinned`): the commands that pin them.
fn unpinned_refusal(plan: &RotationPlan, unpinned: &[String]) -> Failure {
    let mut hosts: Vec<String> = Vec::new();
    for id in unpinned {
        let host = connect_host(plan, id);
        if !hosts.contains(&host) {
            hosts.push(host);
        }
    }
    let commands: Vec<String> = hosts
        .iter()
        .map(|h| format!("`unissh ssh \"{}\"`", one_line(h)))
        .collect();
    Failure::msg(format!(
        "{} machine(s) of this rotation have no pinned host key yet, and a rotation logs in \
         with both keys only where the machine is known; connect once first: {}",
        unpinned.len(),
        commands.join(", ")
    ))
}

/// Refuses to drive the targets `only` chooses (all for `None`) while one is
/// reached over a machine whose host key is not pinned: the rotation would
/// trust whatever answers there first. A changed host key fails the connect
/// as always.
fn refuse_unpinned(core: &Core, plan: &RotationPlan, only: Option<&BTreeSet<String>>) -> Res<()> {
    let unpinned: Vec<String> = core
        .key_rotation_unpinned(plan)?
        .into_iter()
        .filter(|id| only.is_none_or(|o| o.contains(id)))
        .collect();
    if unpinned.is_empty() {
        Ok(())
    } else {
        Err(unpinned_refusal(plan, &unpinned))
    }
}

/// The labels of targets `ids`, each followed by the hosts that hop through
/// it; every name once.
fn with_followers(
    plan: &RotationPlan,
    ids: impl IntoIterator<Item = impl AsRef<str>>,
) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for id in ids {
        let id = id.as_ref();
        let label = plan
            .target(id)
            .map_or_else(|| id.to_owned(), RotationTarget::label);
        let deps = plan.dependents_of(id).into_iter().map(|h| h.label.clone());
        for name in std::iter::once(label).chain(deps) {
            if !names.contains(&name) {
                names.push(name);
            }
        }
    }
    names
}

/// The targets whose old key line the run has removed: they refuse the key
/// item's current key from then on.
fn old_key_removed(run: &RotationRun) -> Vec<String> {
    run.states()
        .filter(|(_, s)| {
            matches!(
                s,
                TargetState::Switched
                    | TargetState::Unconfirmed
                    | TargetState::Failed {
                        step: RotationStep::Confirm,
                        ..
                    }
            )
        })
        .map(|(id, _)| id.to_owned())
        .collect()
}

/// Drives `driver` to the end with up to the fleet's parallelism, printing a
/// line as each step lands (unless `quiet`). Ctrl-C or SIGTERM noted in
/// `signal` stops it: nothing new starts, steps in flight still land.
fn drive(core: &Core, driver: &RotationDriver, quiet: bool, signal: &AtomicU8) -> RotationRun {
    let plan = driver.plan();
    let progress = |id: &str, run: &RotationRun| {
        if !quiet {
            if let Some(line) = progress_line(plan, id, run) {
                eprintln!("{line}");
            }
        }
    };
    let done = AtomicBool::new(false);
    let parallel = usize::try_from(DEFAULT_PARALLEL).unwrap_or(1);
    std::thread::scope(|s| {
        s.spawn(|| {
            while !done.load(Ordering::SeqCst) {
                if signal.load(Ordering::SeqCst) != 0 {
                    eprintln!("unissh: stopping: steps in flight finish, nothing new starts");
                    driver.stop();
                    return;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        });
        let run = driver.drive(core, parallel, DEFAULT_TIMEOUT_SECS, &progress);
        done.store(true, Ordering::SeqCst);
        run
    })
}

/// `unissh keys rotation run`: deploy and verify, nothing removed.
fn run(core: &Core, vault: &VaultArg, name: &str, names: &[String], json: bool) -> Res<()> {
    let rotation = own_rotation(core, vault, name)?;
    let (vault_id, link) = (&rotation.vault_id, &rotation.link);
    let key = one_line(&link.key_id);
    let keys = core.key_rotation_keys(vault_id.clone(), link.key_id.clone())?;
    if keys.committed() {
        return Err(Failure::msg(format!(
            "\"{key}\" already holds the new key: an earlier finish was interrupted; complete it \
             with `unissh keys rotation finish \"{key}\"`"
        )));
    }
    let plan = core.plan_key_rotation(vault_id.clone(), link.key_id.clone())?;
    if plan.targets.is_empty() {
        eprintln!(
            "unissh: no host logs in with \"{key}\": there is nothing to deploy; \
             `unissh keys rotation finish \"{key}\"` makes the new key current"
        );
        return Ok(());
    }
    let scope = RunScope {
        first: RotationStep::Deploy,
        last: RotationStep::Verify,
        only: select(&plan, names)?,
    };
    refuse_unpinned(core, &plan, scope.only.as_ref())?;
    // Begun by `unissh keys rotation begin` (or the app) before this run: a
    // machine an earlier run got to is tried with the new key first.
    let driver = RotationDriver::new(plan, keys, true, &scope);
    let signal = Arc::new(AtomicU8::new(0));
    signals::watch(signals::STOP, &signal)?;
    let result = drive(core, &driver, json, &signal);
    let plan = driver.plan();
    if json {
        print_json(&results_json(plan, &result))?;
    } else {
        print!("{}", results_text(plan, &result));
    }
    let ran: Vec<&str> = result.states().map(|(id, _)| id).collect();
    let unproven = ran.iter().filter(|id| !result.is_verified(id)).count();
    if signal.load(Ordering::SeqCst) != 0 {
        return Err(Failure::msg("stopped"));
    }
    if unproven > 0 {
        return Err(Failure::msg(format!(
            "the new key does not log in on {unproven} of {} machines yet: fix them and run again",
            ran.len()
        )));
    }
    if !json {
        eprintln!(
            "unissh: the new key logs in everywhere it was tried; next, \
             `unissh keys rotation finish \"{key}\"`"
        );
    }
    Ok(())
}

/// The confirmation a finish asks, from the verify pass just made.
fn finish_warning(plan: &RotationPlan, run: &RotationRun, key: &str, candidate: &str) -> String {
    let mut text = String::new();
    let outlook = run.finish_outlook(plan);
    // The machines the new key does not log in on, and those reached only
    // through one of them; each followed by the hosts that hop through it.
    let names = with_followers(plan, outlook.locked_out());
    if !names.is_empty() {
        text.push_str(&format!(
            "Locked out once you finish: {}. The new key does not log in there yet (or not on a \
             jump host in front of them), and they stay locked out until the new public key is \
             installed on them some other way.\n",
            one_line(&names.join(", "))
        ));
    }
    text.push_str(&format!(
        "The old key is removed from every machine where the new key logs in. Then the key from \
         \"{candidate}\" becomes the current version of \"{key}\", so every host using \"{key}\" \
         logs in with it from now on. The previous private key is kept in this device's local \
         history for reference only; any certificate on \"{key}\" is removed. \"{candidate}\" is \
         deleted.\n"
    ));
    text
}

/// `unissh keys rotation finish`.
fn finish(
    device: &Device,
    offline: bool,
    vault: &VaultArg,
    name: &str,
    yes: bool,
    allow_lockout: bool,
) -> Res<()> {
    let core = &device.core;
    let rotation = own_rotation(core, vault, name)?;
    let (vault_id, link) = (&rotation.vault_id, &rotation.link);
    let (key, candidate) = (one_line(&link.key_id), one_line(&link.candidate_id));
    let keys = core.key_rotation_keys(vault_id.clone(), link.key_id.clone())?;
    let signal = Arc::new(AtomicU8::new(0));
    let driver = if keys.committed() {
        confirm(
            yes,
            &format!(
                "\"{key}\" already holds the new key: an earlier finish was interrupted after that \
                 step. Finishing now changes no key — any certificate still on \"{key}\" is \
                 removed and \"{candidate}\" is deleted.\n"
            ),
        )?;
        None
    } else {
        // Prove the candidate on every machine first, removing nothing: the
        // confirmation has to say which machines a finish locks out.
        let plan = core.plan_key_rotation(vault_id.clone(), link.key_id.clone())?;
        refuse_unpinned(core, &plan, None)?;
        let scope = RunScope {
            first: RotationStep::Verify,
            last: RotationStep::Verify,
            only: None,
        };
        let driver = RotationDriver::new(plan, keys, true, &scope);
        signals::watch(signals::STOP, &signal)?;
        let verified = drive(core, &driver, false, &signal);
        if signal.load(Ordering::SeqCst) != 0 {
            return Err(Failure::msg("stopped: nothing was removed or changed"));
        }
        print!("{}", results_text(driver.plan(), &verified));
        let outlook = verified.finish_outlook(driver.plan());
        if yes && !allow_lockout && outlook.locked_out().next().is_some() {
            let names = with_followers(driver.plan(), outlook.locked_out());
            return Err(Failure::msg(format!(
                "finishing now locks you out of {}; nothing was removed or changed. Get the new \
                 key onto them (`unissh keys rotation run \"{key}\"`) and finish again, or add \
                 --allow-lockout to finish anyway",
                one_line(&names.join(", "))
            )));
        }
        confirm(
            yes,
            &finish_warning(driver.plan(), &verified, &key, &candidate),
        )?;
        if signal.load(Ordering::SeqCst) != 0 {
            return Err(Failure::msg("stopped: nothing was removed or changed"));
        }
        Some(driver)
    };
    let mut left = Vec::new();
    if let Some(driver) = &driver {
        driver.extend_to(RotationStep::Confirm);
        let done = drive(core, driver, false, &signal);
        let plan = driver.plan();
        print!("{}", results_text(plan, &done));
        if signal.load(Ordering::SeqCst) != 0 {
            let removed = old_key_removed(&done);
            let refusing = if removed.is_empty() {
                String::new()
            } else {
                format!(
                    "; these no longer take the current key of \"{key}\", only the new one: {}",
                    one_line(&with_followers(plan, &removed).join(", "))
                )
            };
            return Err(Failure::msg(format!(
                "stopped before \"{key}\" took the new key{refusing}. Run `unissh keys rotation \
                 finish \"{key}\"` again"
            )));
        }
        let outlook = done.finish_outlook(plan);
        let locked = with_followers(plan, outlook.locked_out());
        if !locked.is_empty() {
            left.push(format!(
                "locked out until the new public key is installed there some other way: {}",
                one_line(&locked.join(", "))
            ));
        }
        if !outlook.old_not_refused.is_empty() {
            let names: Vec<String> = outlook
                .old_not_refused
                .iter()
                .map(|id| {
                    plan.target(id)
                        .map_or_else(|| id.clone(), RotationTarget::label)
                })
                .collect();
            left.push(format!(
                "the new key logs in, but the old key was not seen refused: {}",
                one_line(&names.join(", "))
            ));
        }
    }
    stored(
        &rotation.vault_name,
        core.finish_key_rotation(
            vault_id.clone(),
            link.key_id.clone(),
            link.candidate_id.clone(),
        ),
    )?;
    commit(
        device,
        vault_id,
        offline,
        &format!("Finished the rotation of {key}"),
    )?;
    if left.is_empty() {
        Ok(())
    } else {
        Err(Failure::msg(format!(
            "\"{key}\" now holds the new key, but not every machine is done; {}",
            left.join("; ")
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use unissh_ffi::key_rotation_plan::plan_rotation;
    use unissh_ffi::{AuthMethod, ConnectionProfile, JumpHost, ProfileAuth};

    fn host(name: &str, auth: ProfileAuth, jumps: Vec<JumpHost>) -> ConnectionProfile {
        ConnectionProfile {
            profile_id: name.to_owned(),
            uid: name.to_owned(),
            label: name.to_owned(),
            host: format!("{name}.example"),
            port: 22,
            user: "root".to_owned(),
            auth,
            username_template: None,
            jumps,
            proxy: None,
            tags: Vec::new(),
            startup_snippet_ids: Vec::new(),
            record_sessions: false,
            agent_forward: false,
            color: None,
            icon: None,
        }
    }

    fn key() -> ProfileAuth {
        ProfileAuth::Key {
            key_item_id: "k".to_owned(),
        }
    }

    fn plan() -> RotationPlan {
        let hop = JumpHost {
            host: "jump.example".to_owned(),
            port: 2222,
            user: "ops".to_owned(),
            auth: AuthMethod::Agent {
                vault_id: "v".to_owned(),
                key_item_id: "k".to_owned(),
            },
            hop_ref: None,
        };
        plan_rotation(
            vec![
                host("web", key(), Vec::new()),
                host("db", ProfileAuth::PromptPassword, vec![hop]),
            ],
            "v",
            "k",
        )
    }

    fn names(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn host_selection_takes_a_label_a_login_or_a_host_that_hops_through_the_machine() {
        let p = plan();
        let chosen = |items: &[&str]| select(&p, &names(items)).map_err(|e| e.message);
        let web = "root@web.example:22".to_owned();
        let jump = "ops@jump.example:2222".to_owned();
        assert_eq!(
            (
                chosen(&[]),
                chosen(&["web"]),
                chosen(&["ops@jump.example:2222", "root@web.example"]),
                chosen(&["db"]),
            ),
            (
                Ok(None),
                Ok(Some(BTreeSet::from([web.clone()]))),
                Ok(Some(BTreeSet::from([web, jump.clone()]))),
                Ok(Some(BTreeSet::from([jump]))),
            ),
            "all, a label, logins, a dependent host"
        );
    }

    #[test]
    fn host_selection_refuses_a_name_that_is_no_machine_of_the_rotation_naming_them() {
        let p = plan();
        assert_eq!(
            select(&p, &names(&["nope"])).map_err(|e| e.message),
            Err("\"nope\" is not a machine of this rotation; its machines: web, ops@jump.example:2222"
                .to_owned()),
            "lists the machines"
        );
    }

    #[test]
    fn a_landed_step_prints_one_line_and_a_step_in_flight_none() {
        let p = plan();
        let web = "root@web.example:22";
        let mut run = RotationRun::start(&p, &RunScope::full());
        run.begin_step(web);
        let in_flight = progress_line(&p, web, &run);
        run.record_step(
            web,
            RotationStep::Deploy,
            Err(unissh_ffi::key_rotation_plan::StepFailure::Error {
                message: "denied\x1b[2J".to_owned(),
            }),
        );
        assert_eq!(
            (in_flight, progress_line(&p, web, &run)),
            (None, Some("web: deploy failed: denied[2J".to_owned())),
            "the remote's words, without terminal control"
        );
    }

    #[test]
    fn the_finish_warning_names_each_machine_it_locks_out_and_the_hosts_behind_it() {
        let p = plan();
        let scope = RunScope {
            first: RotationStep::Verify,
            last: RotationStep::Verify,
            only: None,
        };
        let mut run = RotationRun::start(&p, &scope);
        for (id, outcome) in [
            ("root@web.example:22", Ok(())),
            (
                "ops@jump.example:2222",
                Err(unissh_ffi::key_rotation_plan::StepFailure::TimedOut),
            ),
        ] {
            run.begin_step(id);
            run.record_step(id, RotationStep::Verify, outcome);
        }
        let warning = finish_warning(&p, &run, "k", "k (rotation)");
        assert_eq!(
            warning.lines().next(),
            Some(
                "Locked out once you finish: ops@jump.example:2222, db. The new key does not log \
                 in there yet (or not on a jump host in front of them), and they stay locked out \
                 until the new public key is installed on them some other way."
            ),
            "the hop, then db that hops through it"
        );
    }

    #[test]
    fn an_unpinned_machine_is_refused_with_the_host_to_connect_to_first() {
        let p = plan();
        let unpinned = [
            "root@web.example:22".to_owned(),
            "ops@jump.example:2222".to_owned(),
        ];
        assert_eq!(
            unpinned_refusal(&p, &unpinned).message,
            "2 machine(s) of this rotation have no pinned host key yet, and a rotation logs in \
             with both keys only where the machine is known; connect once first: \
             `unissh ssh \"web\"`, `unissh ssh \"db\"`",
            "a hop is pinned through the host it is a hop of"
        );
    }
}
