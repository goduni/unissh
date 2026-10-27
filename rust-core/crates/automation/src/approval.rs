//! Commands waiting for a native decision, for approvers outside the desktop UI
//! (the CLI asks on its terminal). The decision itself is [`Broker::approve`].
use super::*;

/// A command awaiting manual approval, with everything the user must see to
/// decide: the exact immutable command and inputs, the resolved destination and
/// the application asking. Holds secrets (stdin, environment values): it has no
/// `Debug` and must never be logged.
pub struct PendingApproval {
    /// Run to approve or deny.
    pub run_id: String,
    /// Integration that submitted the command.
    pub integration_id: String,
    /// The grant's native application label.
    pub application: String,
    /// Where the command would run.
    pub target: TargetInfo,
    /// The command, exactly as it would be executed.
    pub command: Zeroizing<String>,
    /// Literal working directory for this command, if any.
    pub cwd: Option<Zeroizing<String>>,
    /// Initial standard input, followed by EOF, if any.
    pub stdin: Option<Zeroizing<String>>,
    /// Literal environment variables for this command.
    pub env: Vec<(String, Zeroizing<String>)>,
    /// Runtime limit once started.
    pub timeout_ms: u32,
    /// Time left to decide; afterwards the request expires as `approval_expired`.
    pub expires_in: Duration,
}

impl Broker {
    /// Trusted native API: the commands awaiting approval, oldest first. A run
    /// cancelled, revoked or expired meanwhile drops out of the list, so an
    /// approver can also poll this to withdraw a question it is showing.
    pub fn pending_approvals(&self) -> Vec<PendingApproval> {
        let now = Instant::now();
        let state = lock(&self.state);
        let mut pending: Vec<_> = state
            .runs
            .iter()
            .filter(|(_, r)| awaiting(r, now))
            .filter_map(|(id, r)| {
                let grant = state.grants.get(&r.owner).filter(|g| g.epoch == r.epoch)?;
                let target = grant.targets.get(&r.target)?;
                Some((
                    r.created_unix_ms,
                    PendingApproval {
                        run_id: id.clone(),
                        integration_id: r.owner.clone(),
                        application: grant.label.clone(),
                        target: target.info.clone(),
                        command: r.command.clone(),
                        cwd: r.cwd.clone(),
                        stdin: r.stdin.clone(),
                        env: r
                            .env
                            .iter()
                            .map(|(k, v)| (k.clone(), Zeroizing::new(v.clone())))
                            .collect(),
                        timeout_ms: r.timeout_ms,
                        expires_in: r.approval_until.saturating_duration_since(now),
                    },
                ))
            })
            .collect();
        drop(state);
        pending.sort_by_key(|(created, _)| *created);
        pending.into_iter().map(|(_, p)| p).collect()
    }

    /// Trusted native API: whether `run_id` still waits for a decision — what an
    /// approver showing its question polls, without copying every pending request.
    pub fn is_pending(&self, run_id: &str) -> bool {
        let now = Instant::now();
        let state = lock(&self.state);
        state.runs.get(run_id).is_some_and(|r| {
            awaiting(r, now)
                && state
                    .grants
                    .get(&r.owner)
                    .is_some_and(|g| g.epoch == r.epoch && g.targets.contains_key(&r.target))
        })
    }

    /// Trusted native API: ends `run_id`, still waiting for a decision, with
    /// `approval_unavailable` rather than a denial: for an approver that cannot
    /// ask just now (a CLI server sent to the background), so that the agent
    /// learns nobody was asked. Errors as [`Self::approve`] does when it no
    /// longer waits.
    pub fn approval_unavailable(&self, run_id: &str) -> Result<()> {
        let now = Instant::now();
        let mut state = lock(&self.state);
        let run = state
            .runs
            .get_mut(run_id)
            .filter(|r| awaiting(r, now))
            .ok_or(ToolError::ApprovalExpired)?;
        finish(run, "failed", Some(ToolError::ApprovalUnavailable));
        drop(state);
        Ok(())
    }

    /// Native lifecycle only: whether someone can confirm commands of manual
    /// grants. While false (a CLI server with no terminal), such a command is
    /// refused at submission with `approval_unavailable` instead of waiting for a
    /// decision nobody can make. The desktop always has its native dialog.
    pub fn set_manual_approval_available(&self, available: bool) {
        self.manual_approval.store(available, Ordering::SeqCst);
    }
}

/// A run waiting for a decision that can still be made.
fn awaiting(run: &Run, now: Instant) -> bool {
    run.state == "awaiting_approval" && !cancelled(&run.cancel) && now < run.approval_until
}

/// `text` in JSON string notation with every control visible, as the desktop's
/// approval dialog shows a command: C0 controls, DEL, C1 controls, the bidi
/// marks, overrides and isolates, and the invisible format characters (zero
/// width space/joiners, word joiner, invisible operators, BOM, soft hyphen)
/// are escaped, so a newline, a terminal escape, a right-to-left trick or an
/// invisible character cannot hide part of what would run.
pub fn visible(text: &str) -> String {
    let mut out = String::with_capacity(text.len().saturating_add(2));
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            // C0, DEL and C1 (`is_control`), then the bidi controls and the
            // invisible format characters. Keep in step with `visibleCommand`
            // (client/src/bridge/mcp.ts).
            c if c.is_control()
                || matches!(
                    c,
                    '\u{ad}'
                        | '\u{61c}'
                        | '\u{200b}'..='\u{200f}'
                        | '\u{202a}'..='\u{202e}'
                        | '\u{2060}'..='\u{2064}'
                        | '\u{2066}'..='\u{2069}'
                        | '\u{feff}'
                ) =>
            {
                out.push_str(&format!("\\u{:04x}", u32::from(c)));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::visible;

    /// The same notation as the desktop dialog (`visibleCommand`): what could
    /// move the cursor, end the line or reorder text is spelled out.
    #[test]
    fn every_control_that_could_hide_part_of_a_command_is_spelled_out() {
        assert_eq!(
            visible("rm -rf /tmp/x\n\u{1b}[2K\"ok\"\\\u{9b}\u{202e}fdp\u{2066}"),
            r#""rm -rf /tmp/x\n\u001b[2K\"ok\"\\\u009b\u202efdp\u2066""#
        );
        assert_eq!(
            visible("a\u{ad}b\u{61c}c\u{200b}d\u{200f}e\u{2060}f\u{2064}g\u{feff}h"),
            r#""a\u00adb\u061cc\u200bd\u200fe\u2060f\u2064g\ufeffh""#
        );
        assert_eq!(visible("ls -la ü"), "\"ls -la ü\"");
    }
}
