//! Import of `~/.ssh/config` (spec 10.4).
//!
//! Applied directives: `Host` (with `*`/`?`/`!` patterns), `HostName`, `Port`,
//! `User`, `IdentityFile`, `ProxyJump`, `LocalForward`, `RemoteForward`,
//! `DynamicForward`, `ServerAliveInterval`, `SetEnv`, `Compression`,
//! `ConnectTimeout`. Semantics as in OpenSSH: for each key the **first** value
//! encountered among the matching blocks wins.
//!
//! Everything else is **reported, not silently dropped** — see
//! [`SshConfig::skipped`]. A real config is mostly directives we do not
//! implement, and importing it while saying nothing leaves the user believing
//! their `ProxyCommand` came across.
//!
//! `Include` is resolved by the caller through [`SshConfig::parse_with_includes`],
//! so this crate stays free of any filesystem policy.

use crate::error::TransportError;

/// Parsed settings for a single host.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostSettings {
    /// The real host name (`HostName`).
    pub hostname: Option<String>,
    /// Port (`Port`).
    pub port: Option<u16>,
    /// User (`User`).
    pub user: Option<String>,
    /// Path to the key (`IdentityFile`).
    pub identity_file: Option<String>,
    /// Chain of jump hosts (`ProxyJump`), as in the config (comma-separated).
    pub proxy_jump: Option<String>,
    /// `LocalForward` entries, verbatim (`[bind:]port host:hostport`).
    pub local_forwards: Vec<String>,
    /// `RemoteForward` entries, verbatim.
    pub remote_forwards: Vec<String>,
    /// `DynamicForward` entries, verbatim (`[bind:]port`).
    pub dynamic_forwards: Vec<String>,
    /// `ServerAliveInterval` in seconds.
    pub server_alive_interval: Option<u32>,
    /// `ConnectTimeout` in seconds.
    pub connect_timeout: Option<u32>,
    /// `Compression yes|no`.
    pub compression: Option<bool>,
    /// `SetEnv NAME=VALUE` entries, verbatim.
    pub set_env: Vec<String>,
}

/// A directive that was present in the config but not applied, with the line it
/// came from — so an import can tell the user exactly what did not survive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedDirective {
    /// 1-based line number in the text that was parsed.
    pub line: u32,
    /// The directive keyword as written.
    pub keyword: String,
    /// Why it was not applied.
    pub reason: SkipReason,
    /// The included file it was written in, or `None` for the config text
    /// itself. "`ProxyCommand` did not come across" is only actionable with the
    /// file to go and fix.
    pub origin: Option<String>,
}

/// Why a directive did not make it into the imported settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// Recognised, but UniSSH has no equivalent — e.g. `ProxyCommand`, which
    /// runs an arbitrary program.
    Unsupported,
    /// Inside a `Match` block. Match conditions depend on the connection being
    /// attempted (and `Match exec` runs a command), so the block is skipped
    /// wholesale rather than applied to the wrong host.
    InsideMatch,
}

/// A file an `Include` expanded to: the path it was read from, and what was in
/// it. The path is what the importer shows the user and what it groups by, so it
/// should read the way they wrote it (or the way they would recognise it), not
/// as a canonicalised inode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncludedFile {
    /// Where the text came from.
    pub path: String,
    /// The file's contents.
    pub text: String,
}

/// A concrete host alias together with the file it was written in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostOrigin {
    /// The alias, as in [`SshConfig::host_aliases`].
    pub alias: String,
    /// The included file it came from, or `None` for the config text itself.
    pub origin: Option<String>,
}

/// OpenSSH stops following includes at this depth; matching it keeps a cyclic
/// config terminating instead of recursing until the stack gives out.
const MAX_INCLUDE_DEPTH: u32 = 16;

#[derive(Debug)]
struct HostBlock {
    patterns: Vec<String>,
    settings: HostSettings,
    origin: Option<String>,
}

/// Parsed ssh-config.
#[derive(Debug, Default)]
pub struct SshConfig {
    blocks: Vec<HostBlock>,
    skipped: Vec<SkippedDirective>,
    includes: Vec<String>,
}

impl SshConfig {
    /// Parses the config text. `Include` paths are collected but not read — use
    /// [`Self::parse_with_includes`] when they should be followed.
    pub fn parse(text: &str) -> Result<Self, TransportError> {
        let mut cfg = SshConfig::default();
        // No loader: includes are recorded in `includes` and left alone.
        cfg.parse_into::<fn(&str) -> Vec<IncludedFile>>(text, None, &mut None, 0)?;
        Ok(cfg)
    }

    /// Parses the config text, following `Include` directives through `load`.
    ///
    /// `load` receives the path exactly as written (globs and `~` included) and
    /// returns every file it expands to, in order; resolving those is the
    /// caller's business, since it needs a home directory and a filesystem this
    /// crate has no opinion about. An include that cannot be read is skipped,
    /// matching OpenSSH, which ignores a missing include rather than failing the
    /// whole config — it is reported through [`Self::pending_includes`], which
    /// then means exactly what it says: seen, not followed.
    ///
    /// Each returned file carries its path, and every block parsed out of it
    /// remembers it ([`Self::host_aliases_with_origin`], [`SkippedDirective`]) —
    /// that is what lets an importer say where a host came from.
    pub fn parse_with_includes<F>(text: &str, mut load: F) -> Result<Self, TransportError>
    where
        F: FnMut(&str) -> Vec<IncludedFile>,
    {
        let mut cfg = SshConfig::default();
        cfg.parse_into(text, None, &mut Some(&mut load), 0)?;
        Ok(cfg)
    }

    /// `load` is `None` for [`Self::parse`], which only records include paths.
    ///
    /// Included blocks are spliced in **where the `Include` line sits**, not
    /// appended at the end. Resolution is first-match-wins, so the position is
    /// the meaning: a config that opens with `Include conf.d/*` and then has a
    /// catch-all `Host *` expects the included hosts to win, and appending them
    /// would hand every host the catch-all's user instead.
    fn parse_into<F>(
        &mut self,
        text: &str,
        origin: Option<&str>,
        load: &mut Option<&mut F>,
        depth: u32,
    ) -> Result<(), TransportError>
    where
        F: FnMut(&str) -> Vec<IncludedFile>,
    {
        let mut current: Option<HostBlock> = None;
        // Directives inside a Match block belong to that block, not to the Host
        // block above it. Without this they were merged into the preceding Host —
        // so `Match user root` followed by `User root` silently rewrote the user
        // of an unrelated host.
        let mut in_match = false;

        for (idx, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let line_no = (idx as u32).saturating_add(1);
            let (keyword, rest) = split_keyword(line);
            let key = keyword.to_ascii_lowercase();

            if key == "host" {
                if let Some(b) = current.take() {
                    self.blocks.push(b);
                }
                in_match = false;
                let patterns = rest.split_whitespace().map(|s| s.to_string()).collect();
                current = Some(HostBlock {
                    patterns,
                    settings: HostSettings::default(),
                    origin: origin.map(str::to_string),
                });
                continue;
            }

            if key == "match" {
                if let Some(b) = current.take() {
                    self.blocks.push(b);
                }
                in_match = true;
                self.skipped.push(SkippedDirective {
                    line: line_no,
                    keyword: keyword.to_string(),
                    reason: SkipReason::InsideMatch,
                    origin: origin.map(str::to_string),
                });
                continue;
            }

            if key == "include" {
                // One `Include` line may name several files — `Include
                // project1/config project2/config` is an ordinary layout — and
                // OpenSSH treats each as its own include. Splitting here rather
                // than in the loader is what lets one missing path be reported
                // while its neighbours on the same line are still followed.
                let paths = split_include_paths(rest);
                // Inside a Match block the include shares that block's fate.
                if in_match {
                    self.skipped.push(SkippedDirective {
                        line: line_no,
                        keyword: keyword.to_string(),
                        reason: SkipReason::InsideMatch,
                        origin: origin.map(str::to_string),
                    });
                    continue;
                }
                if load.is_none() {
                    // No loader: record every path and follow none of them.
                    self.includes.extend(paths);
                } else if depth >= MAX_INCLUDE_DEPTH {
                    // A cycle (a includes b includes a) has to stop somewhere;
                    // OpenSSH's own limit is 16. Reported, not silently cut.
                    self.skipped.push(SkippedDirective {
                        line: line_no,
                        keyword: keyword.to_string(),
                        reason: SkipReason::Unsupported,
                        origin: origin.map(str::to_string),
                    });
                } else {
                    // Close the open Host block so included blocks land after
                    // it and before whatever follows.
                    let reopen = current.take().map(|b| {
                        let patterns = b.patterns.clone();
                        self.blocks.push(b);
                        patterns
                    });
                    for spec in paths {
                        // Re-borrow the loader per path: the recursion below
                        // needs it too, so the borrow cannot outlive this call.
                        let files = match load.as_mut() {
                            Some(loader) => loader(&spec),
                            None => Vec::new(),
                        };
                        // Nothing behind it (missing, unreadable, a glob that
                        // matched nothing). OpenSSH ignores that; ignoring it in
                        // silence costs the user the one clue for why a host they
                        // expected is not in the import.
                        if files.is_empty() {
                            self.includes.push(spec);
                            continue;
                        }
                        for inc in files {
                            self.parse_into(&inc.text, Some(&inc.path), load, depth + 1)?;
                        }
                    }
                    // Reopen the same Host block: in OpenSSH an Include in the
                    // middle of a Host block does not end it, and the directives
                    // after it still belong to that host.
                    current = reopen.map(|patterns| HostBlock {
                        patterns,
                        settings: HostSettings::default(),
                        origin: origin.map(str::to_string),
                    });
                }
                continue;
            }

            if in_match {
                self.skipped.push(SkippedDirective {
                    line: line_no,
                    keyword: keyword.to_string(),
                    reason: SkipReason::InsideMatch,
                    origin: origin.map(str::to_string),
                });
                continue;
            }

            let block = match current.as_mut() {
                Some(b) => b,
                // A directive before any Host block is a global default in
                // OpenSSH. We do not model globals, so it is reported rather
                // than dropped.
                None => {
                    self.skipped.push(SkippedDirective {
                        line: line_no,
                        keyword: keyword.to_string(),
                        reason: SkipReason::Unsupported,
                        origin: origin.map(str::to_string),
                    });
                    continue;
                }
            };
            let value = rest.trim();
            let s = &mut block.settings;
            match key.as_str() {
                "hostname" => s.hostname = Some(value.to_string()),
                "port" => {
                    s.port = Some(
                        value
                            .parse()
                            .map_err(|_| TransportError::Config(format!("bad port: {value}")))?,
                    )
                }
                "user" => s.user = Some(value.to_string()),
                "identityfile" => s.identity_file = Some(value.to_string()),
                "proxyjump" => s.proxy_jump = Some(value.to_string()),
                "localforward" => s.local_forwards.push(value.to_string()),
                "remoteforward" => s.remote_forwards.push(value.to_string()),
                "dynamicforward" => s.dynamic_forwards.push(value.to_string()),
                "setenv" => s.set_env.push(value.to_string()),
                "serveraliveinterval" => s.server_alive_interval = value.parse().ok(),
                "connecttimeout" => s.connect_timeout = value.parse().ok(),
                "compression" => s.compression = Some(value.eq_ignore_ascii_case("yes")),
                _ => self.skipped.push(SkippedDirective {
                    line: line_no,
                    keyword: keyword.to_string(),
                    reason: SkipReason::Unsupported,
                    origin: origin.map(str::to_string),
                }),
            }
        }
        if let Some(b) = current.take() {
            self.blocks.push(b);
        }
        Ok(())
    }

    /// Directives that were present but not applied. An importer should show
    /// these: a config is mostly things we do not implement, and staying silent
    /// leaves the user believing their `ProxyCommand` came across.
    pub fn skipped(&self) -> &[SkippedDirective] {
        &self.skipped
    }

    /// `Include` paths that were seen but **not** followed: every one of them
    /// when parsed with [`Self::parse`], and with
    /// [`Self::parse_with_includes`] the ones the loader could not open — a
    /// missing file, one it may not read, or a glob that matched nothing.
    pub fn pending_includes(&self) -> &[String] {
        &self.includes
    }

    /// Concrete (non-pattern) host aliases in order of appearance — for importing
    /// into connection profiles. Patterns (`*`/`?`/`!`) and duplicates are skipped.
    pub fn host_aliases(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for block in &self.blocks {
            for p in &block.patterns {
                if !p.contains(['*', '?', '!']) && !out.contains(p) {
                    out.push(p.clone());
                }
            }
        }
        out
    }

    /// The same aliases as [`Self::host_aliases`], each with the file it was
    /// written in — `None` for the config text itself. An importer maps included
    /// files onto groups with this.
    pub fn host_aliases_with_origin(&self) -> Vec<HostOrigin> {
        let mut out: Vec<HostOrigin> = Vec::new();
        for block in &self.blocks {
            for p in &block.patterns {
                if !p.contains(['*', '?', '!']) && !out.iter().any(|h| &h.alias == p) {
                    out.push(HostOrigin {
                        alias: p.clone(),
                        origin: block.origin.clone(),
                    });
                }
            }
        }
        out
    }

    /// Resolves an alias into settings (the first value per key among the matching blocks).
    pub fn resolve(&self, alias: &str) -> HostSettings {
        let mut out = HostSettings::default();
        for block in &self.blocks {
            if block_matches(&block.patterns, alias) {
                merge(&mut out, &block.settings);
            }
        }
        out
    }
}

/// OpenSSH semantics for matching a `Host` block's pattern list against an alias:
/// the block applies ⇔ at least one NON-negative pattern matched AND NO negative
/// pattern (`!pat`) matched. Negation takes priority regardless of position.
/// Previously `!` tokens were treated as literals (never matching), because of which
/// an excluded host still received the block's settings (e.g. an unintended
/// ProxyJump) — a divergence from OpenSSH in a security-relevant directive.
fn block_matches(patterns: &[String], alias: &str) -> bool {
    let mut positive_hit = false;
    for p in patterns {
        if let Some(neg) = p.strip_prefix('!') {
            if glob_match(neg, alias) {
                return false; // explicit exclusion — the block does not apply
            }
        } else if glob_match(p, alias) {
            positive_hit = true;
        }
    }
    positive_hit
}

/// The paths on one `Include` line. Whitespace-separated, with double quotes
/// around a path that contains spaces — the same shape OpenSSH's own tokeniser
/// accepts, minus the escapes nobody writes in a config.
fn split_include_paths(rest: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    for c in rest.chars() {
        match c {
            '"' => quoted = !quoted,
            c if c.is_whitespace() && !quoted => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn split_keyword(line: &str) -> (&str, &str) {
    // support `Key value` and `Key=value`
    if let Some(idx) = line.find(['=', ' ', '\t']) {
        let (k, v) = line.split_at(idx);
        (k.trim(), v[1..].trim_start_matches(['=', ' ', '\t']))
    } else {
        (line, "")
    }
}

fn merge(into: &mut HostSettings, from: &HostSettings) {
    if into.hostname.is_none() {
        into.hostname = from.hostname.clone();
    }
    if into.port.is_none() {
        into.port = from.port;
    }
    if into.user.is_none() {
        into.user = from.user.clone();
    }
    if into.identity_file.is_none() {
        into.identity_file = from.identity_file.clone();
    }
    if into.proxy_jump.is_none() {
        into.proxy_jump = from.proxy_jump.clone();
    }
    if into.server_alive_interval.is_none() {
        into.server_alive_interval = from.server_alive_interval;
    }
    if into.connect_timeout.is_none() {
        into.connect_timeout = from.connect_timeout;
    }
    if into.compression.is_none() {
        into.compression = from.compression;
    }
    // Forwards and SetEnv accumulate rather than first-wins: OpenSSH applies
    // *every* matching LocalForward, and a `Host *` block adding one tunnel to
    // all hosts is a normal way to write a config. Taking only the first would
    // silently drop the rest.
    into.local_forwards
        .extend(from.local_forwards.iter().cloned());
    into.remote_forwards
        .extend(from.remote_forwards.iter().cloned());
    into.dynamic_forwards
        .extend(from.dynamic_forwards.iter().cloned());
    into.set_env.extend(from.set_env.iter().cloned());
}

/// Simple glob: `*` (any number of characters) and `?` (a single character). An
/// iterative two-pointer approach with backtracking only over the last `*` — linear,
/// without recursion and without catastrophic backtracking on patterns like `*a*a*…`.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();

    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star: Option<usize> = None; // position of the last '*' in the pattern
    let mut star_ti = 0usize; // position in the text at the moment of that '*'

    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            star_ti = ti;
            pi += 1;
        } else if let Some(s) = star {
            // backtrack: '*' consumes one more character of the text
            pi = s + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }
    // the remaining tail of the pattern must consist only of '*'
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}
