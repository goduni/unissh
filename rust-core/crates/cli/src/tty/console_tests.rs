//! The actual prompt/raw terminal under an OS PTY (ConPTY on Windows).

use std::io::{Read, Write};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use portable_pty::{native_pty_system, CommandBuilder, PtySize};

const CHILD: &str = "tty::console_tests::console_child";
const SECRET: &str = "sëcret🔑";

/// Re-entered in a separate OS terminal by `native_console_contract`.
#[test]
#[ignore = "PTY child; native_console_contract launches it with a controlling terminal"]
fn console_child() {
    #[cfg(windows)]
    let original_console = console_state();
    let case = std::env::var("UNISSH_TTY_TEST_CASE").unwrap();
    if case == "pipe_parent" {
        // Native pipes with an explicitly closed producer avoid shell-specific
        // handle inheritance (including emulated Windows PowerShell on ARM).
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", CHILD, "--ignored", "--nocapture"])
            .env("UNISSH_TTY_TEST_CASE", "pipe")
            .stdin(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut input = child.stdin.take().unwrap();
        input.write_all(b"PIPE_SENTINEL\n").unwrap();
        drop(input);
        assert!(
            child.wait().unwrap().success(),
            "piped console child failed"
        );
        return;
    }
    let mut tty = super::Tty::open().unwrap();
    match case.as_str() {
        "secret" | "pipe" => {
            if case == "secret" {
                assert!(
                    super::stdin_is_foreground(),
                    "an exclusive native terminal can authorize approvals"
                );
            }
            let value = tty.secret("CLI_PASSWORD: ").unwrap();
            assert_eq!(&*value, SECRET);
            if case == "pipe" {
                let mut pipe = Vec::new();
                let mut buffer = [0_u8; 64];
                loop {
                    let n = super::read_stdin(&mut buffer).unwrap();
                    if n == 0 {
                        break;
                    }
                    pipe.extend_from_slice(&buffer[..n]);
                }
                assert_eq!(String::from_utf8(pipe).unwrap().trim(), "PIPE_SENTINEL");
                assert!(
                    !super::stdin_is_foreground(),
                    "a pipe never authorizes an MCP confirmation"
                );
            }
        }
        "cancel" => {
            assert_eq!(
                tty.secret("CLI_PASSWORD: ").unwrap_err().kind(),
                std::io::ErrorKind::Interrupted
            );
            // A cancelled hidden prompt must leave a usable visible prompt.
            assert_eq!(tty.line("CLI_VISIBLE: ").unwrap(), "visible");
        }
        "paste" => {
            tty.say("CLI_PASTE: ").unwrap();
            let value = tty.pasted_secret(|text| text.ends_with("END\n")).unwrap();
            assert_eq!(&*value, "first\nsecond\nEND\n");
        }
        "raw" => {
            {
                let _raw = super::RawMode::enter().unwrap();
                tty.say("CLI_RAW: ").unwrap();
                let mut text = Vec::new();
                let mut buf = [0_u8; 128];
                let end = Instant::now() + Duration::from_secs(10);
                while !text.ends_with(b"\r") && Instant::now() < end {
                    if super::wait_for_input(Duration::from_millis(100)).unwrap() {
                        let count = super::read_stdin(&mut buf).unwrap();
                        text.extend_from_slice(&buf[..count]);
                    }
                }
                assert_eq!(text, "\x1b[A\x03ё\r".as_bytes());
                assert_eq!(super::window_size(), Some((100, 36)));
            }
            assert_eq!(tty.line("CLI_VISIBLE: ").unwrap(), "visible");
        }
        "timeout" => {
            let answer = tty
                .line_until(
                    "CLI_TIMEOUT: ",
                    false,
                    Instant::now() + Duration::from_millis(250),
                    &|| false,
                )
                .unwrap();
            assert!(answer.is_none());
        }
        other => panic!("unexpected terminal case {other}"),
    }
    #[cfg(windows)]
    assert_eq!(
        console_state(),
        original_console,
        "console modes and code pages must be restored"
    );
    tty.say("\r\nCLI_TTY_OK\r\n").unwrap();
}

/// Prompts never consume piped stdin or echo a secret, Ctrl-C and Unicode
/// survive, VT keys pass unchanged, resize works, and prompts can time out.
#[test]
fn native_console_contract() {
    for case in ["secret", "pipe", "cancel", "paste", "raw", "timeout"] {
        run_case(case);
    }
}

fn run_case(case: &str) {
    let pty = native_pty_system()
        .openpty(PtySize {
            rows: 28,
            cols: 88,
            pixel_width: 0,
            pixel_height: 0,
        })
        .unwrap();
    let exe = std::env::current_exe().unwrap();
    let mut command = CommandBuilder::new(&exe);
    command.args(["--exact", CHILD, "--ignored", "--nocapture"]);
    command.env(
        "UNISSH_TTY_TEST_CASE",
        if case == "pipe" { "pipe_parent" } else { case },
    );
    let mut child = pty.slave.spawn_command(command).unwrap();
    drop(pty.slave);
    let mut input = pty.master.take_writer().unwrap();
    let mut reader = pty.master.try_clone_reader().unwrap();
    let (send, receive) = mpsc::channel();
    let reading = std::thread::spawn(move || {
        let mut bytes = [0_u8; 1024];
        while let Ok(n) = reader.read(&mut bytes) {
            if n == 0 || send.send(bytes[..n].to_vec()).is_err() {
                break;
            }
        }
    });
    let mut output = String::new();
    let mut sent = false;
    let mut visible = false;
    let mut cursor_reported = false;
    let end = Instant::now() + Duration::from_secs(30);
    while Instant::now() < end && !output.contains("CLI_TTY_OK") {
        if let Ok(bytes) = receive.recv_timeout(Duration::from_millis(100)) {
            output.push_str(&String::from_utf8_lossy(&bytes));
        } else if child.try_wait().unwrap().is_some() {
            break;
        }
        // ConPTY starts with PSEUDOCONSOLE_INHERIT_CURSOR and waits for the
        // terminal emulator's cursor report before it launches the child.
        if !cursor_reported && output.contains("\x1b[6n") {
            input.write_all(b"\x1b[1;1R").unwrap();
            input.flush().unwrap();
            cursor_reported = true;
        }
        if !sent
            && output.contains(if case == "raw" {
                "CLI_RAW: "
            } else {
                "CLI_PASSWORD: "
            })
        {
            // Prompt text is written just before its input guard flushes any
            // typeahead. Wait for that transition before simulating a user.
            std::thread::sleep(Duration::from_millis(50));
            let bytes = match case {
                "cancel" => "\x03",
                "raw" => "\x1b[A\x03ё\r",
                _ => "sëcret🔑\r",
            };
            if case == "raw" {
                pty.master
                    .resize(PtySize {
                        rows: 36,
                        cols: 100,
                        pixel_width: 0,
                        pixel_height: 0,
                    })
                    .unwrap();
            }
            input.write_all(bytes.as_bytes()).unwrap();
            input.flush().unwrap();
            sent = true;
        }
        if !sent && case == "paste" && output.contains("CLI_PASTE: ") {
            // The child enters its no-echo paste reader before input arrives.
            std::thread::sleep(Duration::from_millis(100));
            input.write_all(b"first\r\nsecond\r\nEND\r\n").unwrap();
            input.flush().unwrap();
            sent = true;
        }
        if !visible && output.contains("CLI_VISIBLE: ") {
            std::thread::sleep(Duration::from_millis(50));
            input.write_all(b"visible\r").unwrap();
            input.flush().unwrap();
            visible = true;
        }
    }
    if !output.contains("CLI_TTY_OK") {
        child.kill().unwrap();
    }
    let status = child.wait().unwrap();
    drop(input);
    drop(pty.master);
    drop(receive);
    reading.join().unwrap();
    assert!(
        output.contains("CLI_TTY_OK"),
        "terminal case {case} did not finish: {output}"
    );
    assert!(status.success(), "terminal case {case} failed: {output}");
    assert!(
        !output.contains(SECRET),
        "a secret was echoed in case {case}"
    );
    if case == "paste" {
        assert!(
            !output.contains("first") && !output.contains("second"),
            "pairing text was echoed: {output}"
        );
    }
}

#[cfg(windows)]
#[expect(
    unsafe_code,
    reason = "test observes the live console before and after the real guards"
)]
fn console_state() -> (u32, u32, u32, u32) {
    use windows_sys::Win32::System::Console::{
        GetConsoleCP, GetConsoleMode, GetConsoleOutputCP, GetStdHandle, STD_INPUT_HANDLE,
        STD_OUTPUT_HANDLE,
    };
    // SAFETY: GetStdHandle returns borrowed process console handles.
    let input = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
    // SAFETY: GetStdHandle returns a borrowed output handle.
    let output = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };
    let mut input_mode = 0;
    let mut output_mode = 0;
    // A pipe has no console mode; its unchanged zero value is compared instead.
    // SAFETY: the out-pointer is valid; the API safely rejects pipe handles.
    unsafe {
        GetConsoleMode(input, &mut input_mode);
    }
    // SAFETY: the out-pointer is valid for this borrowed output handle.
    unsafe {
        GetConsoleMode(output, &mut output_mode);
    }
    // SAFETY: these APIs return the attached console's current code pages.
    let input_cp = unsafe { GetConsoleCP() };
    // SAFETY: observing the attached console's output code page needs no buffer.
    let output_cp = unsafe { GetConsoleOutputCP() };
    (input_mode, output_mode, input_cp, output_cp)
}
