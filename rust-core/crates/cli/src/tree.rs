//! Recursive copy, `unissh cp -r`: a directory tree on one side, its files
//! copied over one SFTP session, several at a time.
//!
//! The walk does not follow symbolic links inside the tree; they are named and
//! skipped, as are sockets, pipes and devices. A file or directory that fails
//! is reported and the rest go on; the copy fails at the end if anything was
//! not copied. Each file goes the way a single-file `cp` sends it: a download
//! through a temporary file renamed into place, an upload written in place. An
//! existing file is replaced only with `--force`; existing directories are
//! merged into.
//!
//! A remote name becomes a local path only when it is one plain name on this
//! system; one that is not, or (on the case-insensitive systems) one that
//! would land on the same file as another in its directory, is skipped.

use std::collections::{BTreeSet, VecDeque};
use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use unissh_ffi::{SftpFfi, SftpProgressObserver};

use crate::connect::{download, exists, human, join_remote};
use crate::failure::{best_effort, Failure, Res};
use crate::pool;
use crate::tty;

/// How many files go at once when `--parallel` is not given: the app's default.
pub const PARALLEL: u32 = 4;

const S_IFMT: u32 = 0o170_000;
const S_IFREG: u32 = 0o100_000;
const S_IFLNK: u32 = 0o120_000;

/// What a directory entry is, as far as copying it goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Dir,
    File,
    Link,
    /// A socket, pipe or device: nothing a copy can carry.
    Special,
    /// A local name that is not UTF-8, which an SFTP path here cannot carry.
    BadName,
}

impl Kind {
    /// A remote listing entry. Listings carry `lstat` attributes, so a link
    /// shows as a link. A server that sends no mode gets the benefit of the
    /// doubt as a file; the download checks it again.
    const fn of_remote(is_dir: bool, mode: u32) -> Self {
        if is_dir {
            return Self::Dir;
        }
        match mode & S_IFMT {
            0 | S_IFREG => Self::File,
            S_IFLNK => Self::Link,
            _ => Self::Special,
        }
    }

    /// A local entry, without following a link.
    fn of_local(file_type: fs::FileType) -> Self {
        if file_type.is_symlink() {
            Self::Link
        } else if file_type.is_dir() {
            Self::Dir
        } else if special(file_type) {
            Self::Special
        } else {
            Self::File
        }
    }

    /// Why an entry of this kind is skipped, or `None` when it is copied.
    const fn skipped(self) -> Option<&'static str> {
        match self {
            Self::Dir | Self::File => None,
            Self::Link => Some("a symbolic link, not followed"),
            Self::Special => Some("not a regular file"),
            Self::BadName => Some("the name is not UTF-8"),
        }
    }
}

#[cfg(unix)]
fn special(file_type: fs::FileType) -> bool {
    use std::os::unix::fs::FileTypeExt;
    file_type.is_fifo()
        || file_type.is_socket()
        || file_type.is_block_device()
        || file_type.is_char_device()
}

#[cfg(not(unix))]
const fn special(_file_type: fs::FileType) -> bool {
    false
}

/// What a walk checks before a listed name becomes a local path.
#[derive(Debug, Clone, Copy)]
struct Names {
    /// Refuse what Windows reads into a name: `\` between names, `:` for a
    /// drive or an alternate data stream, a trailing dot or space (dropped, so
    /// `a.` is `a`), and the device names (`CON`, `NUL`, `COM1`, …).
    windows: bool,
    /// Refuse a name that differs from another in its directory only in case,
    /// which a case-insensitive file system would merge into one file.
    fold_case: bool,
}

impl Names {
    /// Names that go to this system's disk, from a remote listing. macOS and
    /// Windows file systems are case-insensitive by default.
    const HERE: Self = Self {
        windows: cfg!(windows),
        fold_case: cfg!(not(target_os = "linux")),
    };
    /// Names read from this system's own disk, which it can hold already.
    const OWN: Self = Self {
        windows: false,
        fold_case: false,
    };

    /// Whether `name` is one plain name, nothing a path join could read as a
    /// root, a drive, a parent or a second component.
    fn holds(self, name: &str) -> bool {
        let mut parts = Path::new(name).components();
        let single = matches!(
            (parts.next(), parts.next()),
            (Some(Component::Normal(part)), None) if part == name
        );
        single && (!self.windows || windows_holds(name))
    }
}

/// Whether Windows keeps `name` as the name it is.
fn windows_holds(name: &str) -> bool {
    const DEVICES: [&str; 4] = ["CON", "PRN", "AUX", "NUL"];
    let stem = name.split('.').next().unwrap_or(name).trim_end();
    let numbered = |prefix: &str| match stem.as_bytes() {
        [a, b, c, b'1'..=b'9'] => [*a, *b, *c].eq_ignore_ascii_case(prefix.as_bytes()),
        _ => false,
    };
    !name.contains(['\\', ':'])
        && !name.ends_with(['.', ' '])
        && !DEVICES.iter().any(|d| stem.eq_ignore_ascii_case(d))
        && !numbered("COM")
        && !numbered("LPT")
}

/// One entry of a directory listing.
struct Entry {
    name: String,
    kind: Kind,
    size: Option<u64>,
}

/// What a walk found. Paths are relative to the root, with `/` between names.
#[derive(Debug, Default, PartialEq, Eq)]
struct Tree {
    /// Directories, each after its parent.
    dirs: Vec<String>,
    /// Regular files, with the size the listing gave when it gave one.
    files: Vec<(String, Option<u64>)>,
    /// What is not copied, and why.
    skipped: Vec<(String, &'static str)>,
    /// Entries that could not be read or represented (`""` is the root), and why.
    unread: Vec<(String, String)>,
}

/// Walks the tree breadth-first from its root; `list` reads one directory,
/// given by its relative path. A directory that cannot be read is noted and
/// the walk goes on. A name `names` refuses is skipped, never joined.
fn walk(names: Names, mut list: impl FnMut(&str) -> Result<Vec<Entry>, String>) -> Tree {
    let mut tree = Tree::default();
    let mut queue = VecDeque::from([String::new()]);
    while let Some(dir) = queue.pop_front() {
        let mut entries = match list(&dir) {
            Ok(entries) => entries,
            Err(why) => {
                tree.unread.push((dir, why));
                continue;
            }
        };
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        // The names this directory holds so far, case-folded.
        let mut folded = BTreeSet::new();
        for entry in entries {
            // Servers list these two; they are not entries to copy.
            if entry.name == "." || entry.name == ".." {
                continue;
            }
            let rel = rel_join(&dir, &entry.name);
            if let Some(why) = entry.kind.skipped() {
                if entry.kind == Kind::BadName {
                    tree.unread.push((rel, why.to_owned()));
                } else {
                    tree.skipped.push((rel, why));
                }
            } else if !names.holds(&entry.name) {
                tree.unread
                    .push((rel, "a name this system cannot hold".to_owned()));
            } else if names.fold_case && !folded.insert(entry.name.to_lowercase()) {
                tree.unread.push((
                    rel,
                    "differs only in case from another name here".to_owned(),
                ));
            } else if entry.kind == Kind::Dir {
                tree.dirs.push(rel.clone());
                queue.push_back(rel);
            } else {
                tree.files.push((rel, entry.size));
            }
        }
    }
    tree
}

fn rel_join(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        name.to_owned()
    } else {
        format!("{dir}/{name}")
    }
}

/// The directory a relative path is in (`""` for the root).
fn parent_rel(rel: &str) -> &str {
    rel.rsplit_once('/').map_or("", |(parent, _)| parent)
}

/// Whether `rel` lies inside one of the directories in `cut`.
fn under(cut: &BTreeSet<String>, rel: &str) -> bool {
    let mut dir = parent_rel(rel);
    while !dir.is_empty() {
        if cut.contains(dir) {
            return true;
        }
        dir = parent_rel(dir);
    }
    false
}

/// `rel` under the remote `root`; `""` for both is the login directory.
pub fn remote_path(root: &str, rel: &str) -> String {
    match (root.is_empty(), rel.is_empty()) {
        (true, true) => ".".to_owned(),
        (false, true) => root.to_owned(),
        (_, false) => join_remote(root, rel),
    }
}

/// `rel` under the local `root`.
fn local_path(root: &Path, rel: &str) -> PathBuf {
    rel.split('/')
        .filter(|name| !name.is_empty())
        .fold(root.to_path_buf(), |path, name| path.join(name))
}

fn list_remote(sftp: &SftpFfi, path: String) -> Result<Vec<Entry>, String> {
    let listed = sftp.list_dir(path).map_err(|e| Failure::from(e).message)?;
    Ok(listed
        .into_iter()
        .map(|e| Entry {
            name: e.filename,
            kind: Kind::of_remote(e.is_dir, e.mode),
            size: e.size_known.then_some(e.size),
        })
        .collect())
}

fn list_local(dir: &Path) -> Result<Vec<Entry>, String> {
    let mut out = Vec::new();
    for entry in fs::read_dir(dir).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let kind = Kind::of_local(entry.file_type().map_err(|e| e.to_string())?);
        let (name, kind) = match entry.file_name().into_string() {
            Ok(name) => (name, kind),
            Err(name) => (name.to_string_lossy().into_owned(), Kind::BadName),
        };
        let size = (kind == Kind::File)
            .then(|| entry.metadata().ok().map(|m| m.len()))
            .flatten();
        out.push(Entry { name, kind, size });
    }
    Ok(out)
}

/// Makes the local directory `path`, or accepts it when it is one already.
/// A link there is refused rather than written through.
fn make_local_dir(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path).map_err(|e| e.to_string())?;
    match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => {
            Err("is a symbolic link; not copying through it".to_owned())
        }
        Ok(m) if m.is_dir() => Ok(()),
        Ok(_) => Err("exists and is not a directory".to_owned()),
        Err(e) => Err(e.to_string()),
    }
}

/// Makes the remote directory `path`: `true` when this made it, `false` when
/// it was a directory already.
fn make_remote_dir(sftp: &SftpFfi, path: &str) -> Result<bool, String> {
    match sftp.mkdir(path.to_owned()) {
        Ok(()) => Ok(true),
        // `lstat`: a link to a directory is not one here.
        Err(e) => match sftp.lstat(path.to_owned()) {
            Ok(stat) if stat.is_dir => Ok(false),
            Ok(_) => Err("exists and is not a directory".to_owned()),
            Err(_) => Err(Failure::from(e).message),
        },
    }
}

/// The final line of a copy.
fn summary(copied: usize, files: usize, skipped: usize, into: &str) -> String {
    let plural = |n: usize| if n == 1 { "" } else { "s" };
    let mut line = format!("copied {copied} of {files} file{} to {into}", plural(files));
    if skipped > 0 {
        line.push_str(&format!(
            "; skipped {skipped} entr{} that {} not a regular file or directory",
            if skipped == 1 { "y" } else { "ies" },
            if skipped == 1 { "is" } else { "are" }
        ));
    }
    line
}

/// The copy's state on the terminal: what is done so far, and each problem as
/// it happens.
struct Board {
    tty: bool,
    files: usize,
    bytes: u64,
    copied: AtomicUsize,
    moved: AtomicU64,
    failed: AtomicUsize,
}

impl Board {
    fn new(tree: &Tree) -> Self {
        Self {
            tty: io::stderr().is_terminal(),
            files: tree.files.len(),
            bytes: tree.files.iter().filter_map(|(_, size)| *size).sum(),
            copied: AtomicUsize::new(0),
            moved: AtomicU64::new(0),
            failed: AtomicUsize::new(0),
        }
    }

    fn line(&self) -> String {
        format!(
            "\r  {} of {} files, {} / {}",
            self.copied.load(Ordering::Relaxed),
            self.files,
            human(self.moved.load(Ordering::Relaxed)),
            human(self.bytes)
        )
    }

    fn draw(&self) {
        if self.tty {
            let mut err = io::stderr().lock();
            best_effort(
                err.write_all(self.line().as_bytes())
                    .and_then(|()| err.flush()),
            );
        }
    }

    /// A line of its own, above the progress.
    fn say(&self, text: &str) {
        let clear = if self.tty { "\r\x1b[2K" } else { "" };
        let progress = if self.tty { self.line() } else { String::new() };
        let mut err = io::stderr().lock();
        best_effort(write!(err, "{clear}unissh: {text}\n{progress}").and_then(|()| err.flush()));
    }

    fn fail(&self, path: &str, why: &str) {
        self.failed.fetch_add(1, Ordering::Relaxed);
        self.say(&format!("{}: {}", tty::one_line(path), tty::one_line(why)));
    }

    /// What a walk could not copy, before anything is copied.
    fn preface(&self, tree: &Tree, source: impl Fn(&str) -> String) {
        for (rel, why) in &tree.skipped {
            self.say(&format!("skipped {}: {why}", tty::one_line(&source(rel))));
        }
        for (rel, why) in &tree.unread {
            self.fail(&source(rel), why);
        }
    }

    /// One file's outcome; `sent` is what its leg moved, taken back off the
    /// total when the file did not make it.
    fn settle(&self, path: &str, outcome: Res<bool>, sent: u64) {
        if !matches!(outcome, Ok(true)) {
            self.moved.fetch_sub(sent, Ordering::Relaxed);
        }
        match outcome {
            Ok(true) => {
                self.copied.fetch_add(1, Ordering::Relaxed);
                self.draw();
            }
            Ok(false) => self.fail(path, "the copy was interrupted"),
            Err(failure) => self.fail(path, &failure.message),
        }
    }

    /// The summary; a failure when anything was not copied.
    fn finish(&self, skipped: usize, into: &str) -> Res<()> {
        if self.tty {
            eprint!("\r\x1b[2K");
        }
        let line = summary(
            self.copied.load(Ordering::Relaxed),
            self.files,
            skipped,
            &tty::one_line(into),
        );
        match self.failed.load(Ordering::Relaxed) {
            0 => {
                eprintln!("unissh: {line}");
                Ok(())
            }
            failed => Err(Failure::msg(format!(
                "{line}; {failed} could not be copied (see above)"
            ))),
        }
    }
}

/// One file's progress, added to the board's.
struct Leg {
    board: Arc<Board>,
    sent: AtomicU64,
}

impl Leg {
    fn new(board: &Arc<Board>) -> Arc<Self> {
        Arc::new(Self {
            board: Arc::clone(board),
            sent: AtomicU64::new(0),
        })
    }

    fn observer(self: &Arc<Self>) -> Arc<dyn SftpProgressObserver> {
        Arc::<Self>::clone(self)
    }

    fn sent(&self) -> u64 {
        self.sent.load(Ordering::Relaxed)
    }
}

impl SftpProgressObserver for Leg {
    fn on_progress(&self, transferred: u64, _total: u64) {
        let before = self.sent.swap(transferred, Ordering::Relaxed);
        self.board
            .moved
            .fetch_add(transferred.saturating_sub(before), Ordering::Relaxed);
        self.board.draw();
    }
}

/// A root that could not be read stops the copy before anything is made.
fn readable_root(tree: &Tree, root: &str) -> Res<()> {
    match tree.unread.iter().find(|(rel, _)| rel.is_empty()) {
        Some((_, why)) => Err(Failure::msg(format!("{}: {why}", tty::one_line(root)))),
        None => Ok(()),
    }
}

/// Copies the remote directory `remote` to the local directory `local`.
pub fn download_tree(
    sftp: &SftpFfi,
    remote: &str,
    local: &Path,
    force: bool,
    parallel: u32,
) -> Res<()> {
    let tree = walk(Names::HERE, |rel| {
        list_remote(sftp, remote_path(remote, rel))
    });
    readable_root(&tree, remote)?;
    make_local_dir(local).map_err(|why| Failure::msg(format!("{}: {why}", local.display())))?;
    let board = Arc::new(Board::new(&tree));
    board.preface(&tree, |rel| remote_path(remote, rel));
    let mut cut = BTreeSet::new();
    for rel in &tree.dirs {
        if under(&cut, rel) {
            continue;
        }
        let path = local_path(local, rel);
        if let Err(why) = make_local_dir(&path) {
            board.fail(&path.display().to_string(), &why);
            cut.insert(rel.clone());
        }
    }
    let files: Vec<_> = tree
        .files
        .iter()
        .filter(|(rel, _)| !under(&cut, rel))
        .collect();
    pool::each(&files, parallel, |(rel, _)| {
        let to = local_path(local, rel);
        let shown = to.display().to_string();
        let leg = Leg::new(&board);
        // A failed download is named by the remote file it reads, as a failed
        // upload is by the remote file it writes; a local refusal by its path.
        let (named, outcome) = if !force && fs::symlink_metadata(&to).is_ok() {
            let refused = exists(&shown);
            (shown, Err(refused))
        } else {
            let from = remote_path(remote, rel);
            let outcome = download(sftp, from.clone(), &to, force, Some(leg.observer()));
            (from, outcome)
        };
        board.settle(&named, outcome, leg.sent());
    });
    board.finish(tree.skipped.len(), &local.display().to_string())
}

/// Copies the local directory `local` to the remote directory `remote`.
pub fn upload_tree(
    sftp: &SftpFfi,
    local: &Path,
    remote: &str,
    force: bool,
    parallel: u32,
) -> Res<()> {
    let tree = walk(Names::OWN, |rel| list_local(&local_path(local, rel)));
    readable_root(&tree, &local.display().to_string())?;
    let root_made = make_remote_dir(sftp, &remote_path(remote, ""))
        .map_err(|why| Failure::msg(format!("{}: {why}", tty::one_line(remote))))?;
    let board = Arc::new(Board::new(&tree));
    board.preface(&tree, |rel| local_path(local, rel).display().to_string());
    let mut cut = BTreeSet::new();
    // Directories this copy made: nothing in them can be in the way.
    let mut fresh = BTreeSet::new();
    if root_made {
        fresh.insert(String::new());
    }
    for rel in &tree.dirs {
        if under(&cut, rel) {
            continue;
        }
        let path = remote_path(remote, rel);
        match make_remote_dir(sftp, &path) {
            Ok(true) => {
                fresh.insert(rel.clone());
            }
            Ok(false) => {}
            Err(why) => {
                board.fail(&path, &why);
                cut.insert(rel.clone());
            }
        }
    }
    let files: Vec<_> = tree
        .files
        .iter()
        .filter(|(rel, _)| !under(&cut, rel))
        .collect();
    pool::each(&files, parallel, |(rel, _)| {
        let to = remote_path(remote, rel);
        let taken = !force && !fresh.contains(parent_rel(rel)) && sftp.lstat(to.clone()).is_ok();
        let leg = Leg::new(&board);
        let outcome = if taken {
            Err(exists(&to))
        } else {
            sftp.sftp_upload(
                local_path(local, rel).to_string_lossy().into_owned(),
                to.clone(),
                0,
                Some(leg.observer()),
                None,
            )
            .map_err(Failure::from)
        };
        board.settle(&to, outcome, leg.sent());
    });
    board.finish(tree.skipped.len(), remote)
}

#[cfg(test)]
mod tests {
    use super::{local_path, remote_path, summary, under, walk, Board, Entry, Kind, Names, Tree};
    use crate::failure::{Failure, EXIT_FAILURE};
    use std::collections::BTreeSet;
    use std::path::Path;

    fn entry(name: &str, kind: Kind) -> Entry {
        Entry {
            name: name.to_owned(),
            kind,
            size: (kind == Kind::File).then_some(3),
        }
    }

    #[test]
    fn remote_modes_classify_links_and_special_files() {
        assert_eq!(Kind::of_remote(true, 0o040_755), Kind::Dir);
        assert_eq!(Kind::of_remote(false, 0o100_644), Kind::File);
        assert_eq!(Kind::of_remote(false, 0), Kind::File, "no mode: a file");
        assert_eq!(Kind::of_remote(false, 0o120_777), Kind::Link);
        assert_eq!(Kind::of_remote(false, 0o010_644), Kind::Special, "a fifo");
    }

    /// Links and special files are skipped with the reason, `.`/`..` ignored,
    /// directories listed parents first, and an unreadable directory noted
    /// without stopping the walk.
    #[test]
    fn walk_skips_links_and_goes_on_past_an_unreadable_directory() {
        let tree = walk(Names::OWN, |dir| match dir {
            "" => Ok(vec![
                entry(".", Kind::Dir),
                entry("..", Kind::Dir),
                entry("b", Kind::Dir),
                entry("a.txt", Kind::File),
                entry("link", Kind::Link),
                entry("locked", Kind::Dir),
            ]),
            "b" => Ok(vec![entry("c", Kind::Dir), entry("fifo", Kind::Special)]),
            "b/c" => Ok(vec![entry("d.txt", Kind::File)]),
            "locked" => Err("permission denied".to_owned()),
            other => panic!("listed {other}"),
        });
        assert_eq!(
            tree,
            Tree {
                dirs: vec!["b".into(), "locked".into(), "b/c".into()],
                files: vec![("a.txt".into(), Some(3)), ("b/c/d.txt".into(), Some(3))],
                skipped: vec![
                    ("link".into(), "a symbolic link, not followed"),
                    ("b/fifo".into(), "not a regular file"),
                ],
                unread: vec![("locked".into(), "permission denied".into())],
            }
        );
    }

    /// A listed name joins a local path only as one plain name: the Windows
    /// rules are checked here on any host through the flag, the path syntax
    /// of the host itself through `Path`.
    #[test]
    fn a_name_that_is_not_one_plain_name_is_skipped_never_joined() {
        let windows = Names {
            windows: true,
            fold_case: false,
        };
        assert!(Names::OWN.holds("..."));
        for names in [Names::OWN, windows] {
            assert!(names.holds("a.txt"), "{names:?}");
            assert!(names.holds("console.log"), "{names:?}");
            for bad in ["", ".", "..", "a/b", "/etc", "a/", "./a"] {
                assert!(!names.holds(bad), "{bad:?} with {names:?}");
            }
        }
        for bad in [
            r"..\x",
            r"a\b",
            "C:x",
            "C:",
            "f.txt:stream",
            "...",
            "a.",
            "a ",
            "CON",
            "nul.txt",
            "com1",
            "LPT9.log",
        ] {
            assert!(!windows.holds(bad), "{bad:?}");
        }
        #[cfg(unix)]
        assert!(Names::OWN.holds(r"a\b"), "a plain name on unix");
        #[cfg(windows)]
        assert!(!Names::OWN.holds("C:x"), "a drive prefix on windows");
        let tree = walk(windows, |_| {
            Ok(vec![entry(r"..\up", Kind::File), entry("ok", Kind::File)])
        });
        assert_eq!(tree.files, vec![("ok".into(), Some(3))]);
        assert_eq!(
            tree.unread,
            vec![(r"..\up".into(), "a name this system cannot hold".into())]
        );
    }

    /// On a case-insensitive disk two names that differ only in case would be
    /// one file (and two downloads racing on one part file): the first, in
    /// name order, is copied and the other skipped, directories and files
    /// alike.
    #[test]
    fn names_that_differ_only_in_case_are_copied_once() {
        let names = Names {
            windows: false,
            fold_case: true,
        };
        let tree = walk(names, |dir| match dir {
            "" => Ok(vec![
                entry("a", Kind::File),
                entry("A", Kind::Dir),
                entry("b.txt", Kind::File),
                entry("B.TXT", Kind::File),
            ]),
            "A" => Ok(vec![entry("a", Kind::File)]),
            other => panic!("listed {other}"),
        });
        let why = "differs only in case from another name here";
        assert_eq!(
            tree,
            Tree {
                dirs: vec!["A".into()],
                files: vec![("B.TXT".into(), Some(3)), ("A/a".into(), Some(3))],
                skipped: vec![],
                unread: vec![("a".into(), why.into()), ("b.txt".into(), why.into())],
            }
        );
    }

    #[test]
    fn a_file_that_fails_lets_the_rest_go_on_and_fails_the_copy() {
        let board = Board::new(&Tree {
            files: vec![("a".into(), Some(3)), ("b".into(), Some(3))],
            ..Tree::default()
        });
        board.settle("out/a", Ok(true), 0);
        board.settle("out/b", Err(Failure::msg("permission denied")), 0);
        let failure = board.finish(0, "out").unwrap_err();
        assert_eq!(failure.exit, EXIT_FAILURE, "exit code");
        assert_eq!(
            failure.message,
            "copied 1 of 2 files to out; 1 could not be copied (see above)"
        );
    }

    #[test]
    fn incompatible_names_fail_the_copy_but_links_do_not() {
        for entries in [
            vec![entry("A.txt", Kind::File), entry("a.txt", Kind::File)],
            vec![entry("A", Kind::Dir), entry("a", Kind::Dir)],
            vec![entry("NUL", Kind::File)],
            vec![entry("bad-name", Kind::BadName)],
        ] {
            let mut root = Some(entries);
            let tree = walk(
                Names {
                    windows: true,
                    fold_case: true,
                },
                |dir| {
                    Ok(if dir.is_empty() {
                        root.take().unwrap()
                    } else {
                        vec![]
                    })
                },
            );
            let board = Board::new(&tree);
            board.preface(&tree, str::to_owned);
            let error = board.finish(tree.skipped.len(), "out").unwrap_err();
            assert_eq!(error.exit, EXIT_FAILURE);
        }
        let tree = walk(
            Names {
                windows: true,
                fold_case: true,
            },
            |_| Ok(vec![entry("A.txt", Kind::Link), entry("a.txt", Kind::File)]),
        );
        assert_eq!(
            tree.files.len(),
            1,
            "a skipped link must not hide a regular file"
        );
        let board = Board::new(&tree);
        board.preface(&tree, str::to_owned);
        board.settle("a.txt", Ok(true), 0);
        assert!(board.finish(tree.skipped.len(), "out").is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn local_listing_does_not_follow_links() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("file"), b"abc").unwrap();
        std::fs::create_dir_all(dir.path().join("sub")).unwrap();
        std::os::unix::fs::symlink(dir.path().join("sub"), dir.path().join("to-sub")).unwrap();
        let mut listed: Vec<_> = super::list_local(dir.path())
            .unwrap()
            .into_iter()
            .map(|e| (e.name, e.kind, e.size))
            .collect();
        listed.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(
            listed,
            vec![
                ("file".into(), Kind::File, Some(3)),
                ("sub".into(), Kind::Dir, None),
                ("to-sub".into(), Kind::Link, None),
            ]
        );
    }

    #[test]
    fn a_directory_not_made_cuts_off_everything_inside_it() {
        let cut = BTreeSet::from(["a/b".to_owned()]);
        assert!(under(&cut, "a/b/c.txt"));
        assert!(under(&cut, "a/b/c/d.txt"));
        assert!(!under(&cut, "a/b"), "the directory itself is reported once");
        assert!(!under(&cut, "a/bc.txt"));
    }

    #[test]
    fn relative_paths_land_under_their_roots() {
        assert_eq!(remote_path("/srv/www", ""), "/srv/www");
        assert_eq!(remote_path("", ""), ".", "the login directory");
        assert_eq!(remote_path("/srv/www/", "a/b.txt"), "/srv/www/a/b.txt");
        assert_eq!(
            local_path(Path::new("out"), "a/b.txt"),
            Path::new("out").join("a").join("b.txt")
        );
        assert_eq!(local_path(Path::new("out"), ""), Path::new("out"));
    }

    #[test]
    fn summary_counts_files_and_skipped_entries() {
        assert_eq!(summary(1, 1, 0, "out"), "copied 1 of 1 file to out");
        assert_eq!(
            summary(2, 3, 2, "out"),
            "copied 2 of 3 files to out; skipped 2 entries that are not a regular file or directory"
        );
    }
}
