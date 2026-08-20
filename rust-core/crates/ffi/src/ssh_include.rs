//! Resolving `Include` in an `~/.ssh/config` against a real filesystem.
//!
//! [`SshConfig::parse_with_includes`] knows OpenSSH's *rules* — where an
//! included block splices in, how deep the recursion may go, that an unreadable
//! include is skipped rather than fatal — and deliberately knows nothing about
//! files. This is the other half: the loader it asks for a path, which needs a
//! home directory, a filesystem, and a policy about which files it may open.
//!
//! Everything it reads is recorded ([`IncludeLoader::files_read`]) and shown to
//! the user before an import writes anything. Following includes means reading
//! files the user did not name one by one, and full disclosure is the condition
//! on which that is acceptable.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use unissh_ssh_transport::{glob_match, IncludedFile};

/// A file the loader read, and the file whose `Include` line pulled it in.
///
/// The chain, not just the list: an importer that maps included files onto
/// groups needs to know that `project1/hosts.conf`, reached through
/// `project1/config`, belongs to whatever group `project1/config` stands for —
/// one level of grouping, however deep the includes go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadFile {
    /// Where it was read from.
    pub path: String,
    /// The file the `Include` line sits in.
    pub included_by: String,
}

/// Reads the files an `Include` names.
///
/// Resolution follows OpenSSH: `~` is the home directory, an absolute path is
/// itself, and a relative path is resolved against the directory of the config
/// the user picked — which for the ordinary `~/.ssh/config` *is* `~/.ssh`, the
/// base OpenSSH documents, and for a config kept anywhere else is the answer
/// that agrees with where the user actually put their files. One base for every
/// depth, as in OpenSSH, rather than one per including file.
pub struct IncludeLoader {
    /// Directory relative includes resolve against.
    base: PathBuf,
    home: Option<PathBuf>,
    /// The config the user picked — what an `Include` at the top level is
    /// attributed to.
    root: String,
    /// Every file actually read, in the order it was read.
    read: Vec<ReadFile>,
    /// Canonical paths already read, so a symlink loop cannot outlive the
    /// parser's depth cap.
    visited: HashSet<PathBuf>,
}

impl IncludeLoader {
    /// A loader for the config at `config_path`, which is treated as already
    /// read: it is the file the user picked, and an include pointing back at it
    /// is a cycle, not a second copy.
    pub fn new(config_path: &Path) -> Self {
        Self::with_home(config_path, unissh_local_pty::home_dir())
    }

    /// [`Self::new`] with the home directory supplied rather than read from the
    /// environment — the seam the tests use, because mutating `$HOME` in a
    /// process running tests in parallel is not something a test may do.
    pub fn with_home(config_path: &Path, home: Option<PathBuf>) -> Self {
        let base = config_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        let mut visited = HashSet::new();
        visited.insert(canonical(config_path));
        Self {
            base,
            home,
            root: display(config_path),
            read: Vec::new(),
            visited,
        }
    }

    /// Every file this loader has read, in order, as the importer should show
    /// them. Does not include the config the user picked — the caller names that
    /// one itself, because it named it to us.
    pub fn files_read(&self) -> &[ReadFile] {
        &self.read
    }

    /// The files one `Include` path expands to, in a stable order. `including`
    /// is the file the `Include` line sits in, `None` at the top level. An empty
    /// result means nothing was readable behind it, which the parser records as
    /// an include seen but not followed.
    pub fn load(&mut self, spec: &str, including: Option<&str>) -> Vec<IncludedFile> {
        let included_by = including.unwrap_or(&self.root).to_string();
        let mut out = Vec::new();
        for path in self.expand(spec) {
            // A file reached twice contributes once. Re-parsing it would change
            // nothing (resolution is first-match-wins, so the second copy always
            // loses) but a config that includes itself would never terminate.
            // The empty text keeps the include *followed* rather than reported
            // as missing, which it is not.
            let key = canonical(&path);
            let text = if self.visited.contains(&key) {
                String::new()
            } else {
                match fs::read_to_string(&path) {
                    Ok(t) => {
                        self.visited.insert(key);
                        self.read.push(ReadFile {
                            path: display(&path),
                            included_by: included_by.clone(),
                        });
                        t
                    }
                    // Missing, or ours to see but not to read. OpenSSH ignores
                    // it; we drop it here and the parser reports it.
                    Err(_) => continue,
                }
            };
            out.push(IncludedFile {
                path: display(&path),
                text,
            });
        }
        out
    }

    /// The concrete file paths a path-as-written names: `~` expanded, relative
    /// resolved, globs matched against what is actually on disk.
    fn expand(&self, spec: &str) -> Vec<PathBuf> {
        let spec = spec.trim();
        if spec.is_empty() {
            return Vec::new();
        }
        let resolved = match spec.strip_prefix("~/").or(spec.strip_prefix("~\\")) {
            // `~user/...` is not resolved: it needs the passwd database, and
            // guessing a sibling of $HOME would read the wrong person's files.
            Some(rest) => match &self.home {
                Some(h) => h.join(rest),
                None => return Vec::new(),
            },
            None if spec == "~" => return Vec::new(),
            None => {
                let p = Path::new(spec);
                if p.is_absolute() {
                    p.to_path_buf()
                } else {
                    self.base.join(p)
                }
            }
        };
        if !has_glob(&resolved) {
            return if resolved.is_file() {
                vec![resolved]
            } else {
                Vec::new()
            };
        }
        expand_glob(&resolved)
    }
}

/// `*` or `?` anywhere in the path, i.e. it has to be matched against the
/// filesystem rather than opened directly.
fn has_glob(path: &Path) -> bool {
    path.components()
        .any(|c| c.as_os_str().to_string_lossy().contains(['*', '?']))
}

/// Expands a path with globs one component at a time. `*` matches within a
/// single name and never across a separator, and each directory's matches are
/// sorted, so the same directory always imports in the same order.
fn expand_glob(path: &Path) -> Vec<PathBuf> {
    let mut heads: Vec<PathBuf> = Vec::new();
    let mut components = path.components();
    // Everything up to the first globbed component is a literal prefix.
    let mut prefix = PathBuf::new();
    for c in components.by_ref() {
        let name = c.as_os_str().to_string_lossy().to_string();
        if name.contains(['*', '?']) {
            heads = read_dir_matching(&prefix, &name);
            break;
        }
        prefix.push(c);
    }
    if heads.is_empty() {
        return Vec::new();
    }
    for c in components {
        let name = c.as_os_str().to_string_lossy().to_string();
        let mut next = Vec::new();
        for h in &heads {
            if name.contains(['*', '?']) {
                next.extend(read_dir_matching(h, &name));
            } else {
                let p = h.join(&name);
                if p.exists() {
                    next.push(p);
                }
            }
        }
        heads = next;
    }
    heads.retain(|p| p.is_file());
    heads
}

/// The entries of `dir` whose name matches `pattern`, sorted by name. A name
/// starting with `.` is skipped unless the pattern asks for one, as globs
/// conventionally do — `conf.d/*` should not pull in editor backups.
fn read_dir_matching(dir: &Path, pattern: &str) -> Vec<PathBuf> {
    let dir = if dir.as_os_str().is_empty() {
        Path::new(".")
    } else {
        dir
    };
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out: Vec<PathBuf> = entries
        .flatten()
        .filter(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            if name.starts_with('.') && !pattern.starts_with('.') {
                return false;
            }
            glob_match(pattern, &name)
        })
        .map(|e| e.path())
        .collect();
    out.sort();
    out
}

/// The identity of a file for the visited set. Falls back to the path as given
/// when it cannot be canonicalised, which is the honest answer for a file that
/// is not there.
fn canonical(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

/// How a path is shown to the user and grouped by.
fn display(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Writes `text` to `dir/rel`, creating parent directories.
    fn write(dir: &Path, rel: &str, text: &str) -> PathBuf {
        let p = dir.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, text).unwrap();
        p
    }

    fn loader(cfg: &Path, home: Option<PathBuf>) -> IncludeLoader {
        IncludeLoader::with_home(cfg, home)
    }

    #[test]
    fn a_tilde_path_resolves_against_the_home_directory() {
        // `Include ~/.ssh/work/config` is a path ssh accepts, so it is one we
        // accept — including when the config itself lives somewhere else.
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        write(&home, ".ssh/work/config", "Host work\n");
        let cfg = write(dir.path(), "elsewhere/config", "");

        let mut l = loader(&cfg, Some(home.clone()));
        let got = l.load("~/.ssh/work/config", None);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].text, "Host work\n");
        assert_eq!(got[0].path, home.join(".ssh/work/config").to_string_lossy());
        assert_eq!(l.files_read().len(), 1);
        assert_eq!(l.files_read()[0].included_by, cfg.to_string_lossy());
    }

    #[test]
    fn a_bare_tilde_and_a_tilde_user_path_are_not_followed() {
        // `~user/...` needs the passwd database; guessing a sibling of $HOME
        // would read a different person's files. Not followed, so it is
        // reported as an include that went nowhere.
        let dir = tempfile::tempdir().unwrap();
        let cfg = write(dir.path(), "config", "");
        let mut l = loader(&cfg, Some(dir.path().to_path_buf()));
        assert!(l.load("~", None).is_empty());
        assert!(l.load("~other/config", None).is_empty());
    }

    #[test]
    fn a_relative_path_resolves_against_the_configs_directory() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "conf.d/one", "Host one\n");
        let cfg = write(dir.path(), "config", "");
        let mut l = loader(&cfg, None);
        let got = l.load("conf.d/one", None);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].text, "Host one\n");
    }

    #[test]
    fn a_glob_matches_within_one_name_and_never_across_a_separator() {
        // `conf.d/*` is the directory's files, not everything beneath it.
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "conf.d/b", "Host b\n");
        write(dir.path(), "conf.d/a", "Host a\n");
        write(dir.path(), "conf.d/nested/deep", "Host deep\n");
        write(dir.path(), "conf.d/.bak", "Host hidden\n");
        let cfg = write(dir.path(), "config", "");

        let mut l = loader(&cfg, None);
        let got = l.load("conf.d/*", None);
        let texts: Vec<&str> = got.iter().map(|f| f.text.as_str()).collect();
        assert_eq!(
            texts,
            ["Host a\n", "Host b\n"],
            "sorted, directories dropped, dotfiles left alone"
        );
    }

    #[test]
    fn a_glob_may_sit_in_the_middle_of_the_path() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "projects/one/config", "Host one\n");
        write(dir.path(), "projects/two/config", "Host two\n");
        write(dir.path(), "projects/three/notconfig", "Host three\n");
        let cfg = write(dir.path(), "config", "");

        let mut l = loader(&cfg, None);
        let got = l.load("projects/*/config", None);
        let texts: Vec<&str> = got.iter().map(|f| f.text.as_str()).collect();
        assert_eq!(texts, ["Host one\n", "Host two\n"]);
    }

    #[test]
    fn nothing_readable_behind_a_path_yields_nothing() {
        // Which is how the parser learns to report it as seen-but-not-followed.
        let dir = tempfile::tempdir().unwrap();
        let cfg = write(dir.path(), "config", "");
        fs::create_dir_all(dir.path().join("adir")).unwrap();
        let mut l = loader(&cfg, None);
        assert!(l.load("gone", None).is_empty());
        assert!(
            l.load("conf.d/*", None).is_empty(),
            "a glob matching nothing"
        );
        assert!(
            l.load("adir", None).is_empty(),
            "a directory is not a config"
        );
        assert!(l.files_read().is_empty());
    }

    #[test]
    fn a_nested_include_records_the_file_that_pulled_it_in() {
        // One level of grouping however deep the includes go: the importer walks
        // this chain up to the file the picked config included directly.
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a/config", "");
        write(dir.path(), "b/config", "");
        let cfg = write(dir.path(), "config", "");
        let mut l = loader(&cfg, None);
        l.load("a/config", None);
        l.load("b/config", Some(&display(&dir.path().join("a/config"))));
        let read = l.files_read();
        assert_eq!(read[0].included_by, cfg.to_string_lossy());
        assert_eq!(read[1].included_by, display(&dir.path().join("a/config")));
    }

    #[test]
    fn a_file_reached_twice_is_read_once_and_contributes_once() {
        // The visited guard: a symlink loop must not outlive the parser's depth
        // cap, and a file included twice would only ever lose the second time
        // (resolution is first-match-wins), so contributing nothing is exact.
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "conf.d/one", "Host one\n");
        let cfg = write(dir.path(), "config", "");
        let mut l = loader(&cfg, None);

        assert_eq!(l.load("conf.d/one", None)[0].text, "Host one\n");
        let again = l.load("conf.d/one", None);
        assert_eq!(
            again.len(),
            1,
            "still followed, so it is not reported missing"
        );
        assert_eq!(
            again[0].text, "",
            "but it contributes nothing the second time"
        );
        assert_eq!(l.files_read().len(), 1, "and is disclosed once");
    }

    #[test]
    fn the_picked_config_counts_as_already_read() {
        // An include pointing back at the config the user picked is a cycle.
        let dir = tempfile::tempdir().unwrap();
        let cfg = write(dir.path(), "config", "Include config\n");
        let mut l = loader(&cfg, None);
        assert_eq!(l.load("config", None)[0].text, "");
        assert!(l.files_read().is_empty());
    }
}
