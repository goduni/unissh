# unissh-local-pty

A local terminal for UniSSH: an interactive shell on the user's own machine,
behind the same shape of API as a remote SSH session.

Built on [`portable-pty`](https://crates.io/crates/portable-pty) (wezterm's, MIT),
which is one interface over unix `openpty` and Windows ConPTY. What this crate
adds is the lifecycle around it.

## API

```rust
use std::sync::Arc;
use unissh_local_pty::{LocalPty, LocalSpec, PtySink, resolve_default_shell};

struct Echo;
impl PtySink for Echo {
    fn on_data(&self, data: Vec<u8>) { print!("{}", String::from_utf8_lossy(&data)); }
    fn on_close(&self, exit_status: i32) { println!("exit {exit_status}"); }
}

let shell = resolve_default_shell();
let pty = LocalPty::spawn(
    LocalSpec { program: shell.program, args: shell.args, cwd: None, cols: 80, rows: 24 },
    Arc::new(Echo),
)?;
pty.write(b"echo hi\n")?;
pty.resize(120, 40)?;
pty.close();
# Ok::<(), unissh_local_pty::LocalPtyError>(())
```

## Decisions worth knowing

- **`close()` is synchronous, and so is `Drop`.** Auto-lock drops every live
  session and then locks the vault. If close returned early, the shell would
  outlive the app that started it — invisible from the UI and unkillable from it
  — and a session recording would never reach storage. Bounded (1.5 s) so a
  process that keeps the pty open cannot wedge the thread closing the tab.
- **The exit code is never negative.** A negative code means "the link dropped"
  to the UI, which then offers to reconnect. A local shell has no link to drop:
  it exits, and the pane offers **Restart** instead.
- **Two threads per session.** A reader (pty → sink) and a waiter
  (`child.wait()` → exit code → sink, and the zombie reaped). The waiter reports
  the close only after the reader has run dry, so the last line the shell printed
  is not lost from the recording.
- **The default working directory is the user's home**, not the process's — that
  would be wherever the bundle was launched from.
- **The environment is inherited as-is**, with `TERM=xterm-256color` and
  `COLORTERM=truecolor` set on top. Nothing else is injected.

## Known limitation (Windows)

`child.kill()` terminates the shell, and ConPTY signals the processes attached to
the console, which in practice is enough. But there is no `SIGHUP` on Windows and
no Job Object here, so a grandchild that detached itself can outlive the tab.
Verified by hand rather than by a test; revisited if it turns out to bite.

## Testing

`cargo test -p unissh-local-pty` runs real shells in real ptys — output, exit
codes, `resize` (checked through `stty size` inside the pty itself), input, `cwd`,
and that `close` really kills the child. The integration tests are unix-only:
CI runs `cargo test --workspace` on ubuntu, so a Windows-named test would be a
test nobody runs.
