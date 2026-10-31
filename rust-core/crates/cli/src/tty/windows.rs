//! Native Windows console. Pipes remain separate from the controlling console:
//! prompts always use CONIN$/CONOUT$, including while stdin/stdout are redirected.
//! Input uses the console's VT translation (arrows, modifiers, function keys) and
//! UTF-8 code page. Every changed mode and code page is restored by its guard.

#![expect(
    unsafe_code,
    reason = "small Win32 console boundary; each call documents its handle and buffer lifetime"
)]

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::windows::io::AsRawHandle;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows_sys::Win32::System::Console::{
    FlushConsoleInputBuffer, GetConsoleCP, GetConsoleMode, GetConsoleOutputCP,
    GetConsoleProcessList, GetConsoleScreenBufferInfo, GetStdHandle, PeekConsoleInputW,
    ReadConsoleInputW, SetConsoleCP, SetConsoleMode, SetConsoleOutputCP, WriteConsoleW,
    CONSOLE_SCREEN_BUFFER_INFO, DISABLE_NEWLINE_AUTO_RETURN, ENABLE_ECHO_INPUT,
    ENABLE_EXTENDED_FLAGS, ENABLE_LINE_INPUT, ENABLE_MOUSE_INPUT, ENABLE_PROCESSED_INPUT,
    ENABLE_PROCESSED_OUTPUT, ENABLE_QUICK_EDIT_MODE, ENABLE_VIRTUAL_TERMINAL_INPUT,
    ENABLE_VIRTUAL_TERMINAL_PROCESSING, ENABLE_WINDOW_INPUT, INPUT_RECORD, KEY_EVENT,
    STD_INPUT_HANDLE,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcessId, WaitForSingleObject};
use zeroize::{Zeroize, Zeroizing};

use super::{cancelled, ended, Key, QuietLine, STOP_TICK};
use crate::failure::best_effort;

pub const SUPPORTED: bool = true;

fn console(name: &str) -> io::Result<File> {
    OpenOptions::new().read(true).write(true).open(name)
}

fn mode(file: &File) -> io::Result<u32> {
    let mut value = 0;
    // SAFETY: File owns a live handle; value is writable for this call.
    if unsafe { GetConsoleMode(file.as_raw_handle(), &mut value) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(value)
}

fn set_mode(file: &File, value: u32) -> io::Result<()> {
    // SAFETY: File owns a live console handle, borrowed only for the call.
    if unsafe { SetConsoleMode(file.as_raw_handle(), value) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn flush(file: &File) -> io::Result<()> {
    // SAFETY: File owns the input console handle.
    if unsafe { FlushConsoleInputBuffer(file.as_raw_handle()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Raw UTF-8 input, restored even if configuring a later setting fails.
struct InputMode {
    file: File,
    saved: u32,
    code_page: u32,
}

impl InputMode {
    fn enter(file: &File, discard: bool) -> io::Result<Self> {
        let saved = mode(file)?;
        // SAFETY: GetConsoleCP takes no pointers and queries this process's console.
        let code_page = unsafe { GetConsoleCP() };
        if code_page == 0 {
            return Err(io::Error::last_os_error());
        }
        let guard = Self {
            file: file.try_clone()?,
            saved,
            code_page,
        };
        let raw = (saved | ENABLE_EXTENDED_FLAGS | ENABLE_VIRTUAL_TERMINAL_INPUT)
            & !(ENABLE_LINE_INPUT
                | ENABLE_ECHO_INPUT
                | ENABLE_PROCESSED_INPUT
                | ENABLE_QUICK_EDIT_MODE
                | ENABLE_MOUSE_INPUT
                | ENABLE_WINDOW_INPUT);
        set_mode(file, raw)?;
        // SAFETY: 65001 is the documented UTF-8 console code page.
        if unsafe { SetConsoleCP(65001) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if discard {
            flush(file)?;
        }
        Ok(guard)
    }
}

impl Drop for InputMode {
    fn drop(&mut self) {
        best_effort(flush(&self.file));
        // SAFETY: the code page was returned by GetConsoleCP on this console.
        unsafe {
            SetConsoleCP(self.code_page);
        }
        best_effort(set_mode(&self.file, self.saved));
    }
}

// ReadFile needs room for a complete UTF-8 character (up to four bytes).
// Reading one byte at a time can report zero for a non-ASCII console key.
// Keep typeahead between pasted lines, and wipe both consumed and pending input.
struct ConsoleKeys {
    bytes: Zeroizing<[u8; 128]>,
    position: usize,
    used: usize,
}

impl ConsoleKeys {
    fn new() -> Self {
        Self {
            bytes: Zeroizing::new([0; 128]),
            position: 0,
            used: 0,
        }
    }

    const fn pending(&self) -> bool {
        self.position < self.used
    }

    fn next(&mut self, mut input: &File) -> io::Result<u8> {
        if !self.pending() {
            self.bytes.zeroize();
            self.used = input.read(self.bytes.as_mut())?;
            self.position = 0;
            if self.used == 0 {
                return Err(ended());
            }
        }
        let byte = self.bytes.get(self.position).copied().ok_or_else(ended)?;
        self.position += 1;
        Ok(byte)
    }
}

/// Prompts address the console even when a command has redirected standard I/O.
pub struct Tty {
    input: File,
    output: File,
}

impl Tty {
    pub fn open() -> io::Result<Self> {
        Ok(Self {
            input: console("CONIN$")?,
            output: console("CONOUT$")?,
        })
    }

    pub fn say(&mut self, text: &str) -> io::Result<()> {
        write_console(&self.output, text)
    }

    pub fn wait(&self, timeout: Duration) -> io::Result<bool> {
        ready(self.input.as_raw_handle(), timeout)
    }

    pub(super) fn read_line(&self, quiet: bool) -> io::Result<Zeroizing<Vec<u8>>> {
        let _mode = InputMode::enter(&self.input, true)?;
        self.read_edited(
            &mut QuietLine::new(),
            &mut ConsoleKeys::new(),
            !quiet,
            None,
            &|| false,
        )?
        .ok_or_else(ended)
    }

    pub(super) fn read_quiet_lines(
        &self,
        complete: &mut dyn FnMut(&[u8]) -> bool,
    ) -> io::Result<Zeroizing<Vec<u8>>> {
        let _mode = InputMode::enter(&self.input, true)?;
        let mut editor = QuietLine::new();
        let mut text = Zeroizing::new(Vec::with_capacity(1024));
        let mut keys = ConsoleKeys::new();
        loop {
            let line = match self.read_edited(&mut editor, &mut keys, false, None, &|| false) {
                Ok(Some(line)) => line,
                Ok(None) => return Ok(text),
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(text),
                Err(e) => return Err(e),
            };
            if line.is_empty() {
                if text.is_empty() {
                    continue;
                }
                return Ok(text);
            }
            text.extend_from_slice(&line);
            text.push(b'\n');
            write_console(&self.output, ".")?;
            if complete(&text) {
                return Ok(text);
            }
        }
    }

    pub(super) fn read_line_until(
        &self,
        echo: bool,
        deadline: Instant,
        stop: &dyn Fn() -> bool,
    ) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
        let _mode = InputMode::enter(&self.input, true)?;
        self.read_edited(
            &mut QuietLine::new(),
            &mut ConsoleKeys::new(),
            echo,
            Some(deadline),
            stop,
        )
    }

    fn read_edited(
        &self,
        editor: &mut QuietLine,
        keys: &mut ConsoleKeys,
        echo: bool,
        deadline: Option<Instant>,
        stop: &dyn Fn() -> bool,
    ) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
        loop {
            let left = deadline.map_or(STOP_TICK, |d| d.saturating_duration_since(Instant::now()));
            if stop() || left.is_zero() {
                return Ok(None);
            }
            if !keys.pending() && !ready(self.input.as_raw_handle(), left.min(STOP_TICK))? {
                continue;
            }
            let byte = keys.next(&self.input)?;
            let bytes = editor.text.len();
            let chars = editor.chars();
            match editor.key(byte) {
                Key::Enter => {
                    if echo {
                        write_console(&self.output, "\r\n")?;
                    }
                    return Ok(Some(editor.take()));
                }
                Key::Cancel => return Err(cancelled()),
                Key::End => return Err(ended()),
                Key::More if echo => {
                    if editor.text.len() > bytes {
                        echo_character(&self.output, &editor.text)?;
                    }
                    for _ in editor.chars()..chars {
                        write_console(&self.output, "\x08 \x08")?;
                    }
                }
                Key::More => {}
            }
        }
    }
}

// Wait for a complete UTF-8 character, never echo partial bytes.
fn echo_character(output: &File, bytes: &[u8]) -> io::Result<()> {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Ok(());
    };
    if let Some(c) = text.chars().next_back() {
        write_console(output, c.encode_utf8(&mut [0; 4]))?;
    }
    Ok(())
}

fn write_console(file: &File, text: &str) -> io::Result<()> {
    let wide: Vec<u16> = text.encode_utf16().collect();
    let mut rest = wide.as_slice();
    while !rest.is_empty() {
        let length = u32::try_from(rest.len()).map_err(io::Error::other)?;
        let mut written = 0;
        // SAFETY: rest is an initialized UTF-16 slice; length is its checked
        // size. File owns the console handle; written is a valid out-pointer.
        if unsafe {
            WriteConsoleW(
                file.as_raw_handle(),
                rest.as_ptr().cast(),
                length,
                &mut written,
                std::ptr::null(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if written == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        rest = rest
            .get(usize::try_from(written).map_err(io::Error::other)?..)
            .ok_or_else(|| io::Error::other("console wrote an invalid length"))?;
    }
    Ok(())
}

/// SSH sessions pass the console's VT/UTF-8 stream through unchanged.
pub struct RawMode {
    _input: InputMode,
    output: File,
    saved_output: u32,
    output_code_page: u32,
}

impl RawMode {
    pub fn enter() -> io::Result<Self> {
        let output = console("CONOUT$")?;
        let saved_output = mode(&output)?;
        let input = InputMode::enter(&console("CONIN$")?, false)?;
        // SAFETY: queries this process's console without taking ownership.
        let output_code_page = unsafe { GetConsoleOutputCP() };
        if output_code_page == 0 {
            return Err(io::Error::last_os_error());
        }
        let guard = Self {
            _input: input,
            output,
            saved_output,
            output_code_page,
        };
        set_mode(
            &guard.output,
            saved_output
                | ENABLE_PROCESSED_OUTPUT
                | ENABLE_VIRTUAL_TERMINAL_PROCESSING
                | DISABLE_NEWLINE_AUTO_RETURN,
        )?;
        // SAFETY: 65001 is the documented UTF-8 code page for replay bytes.
        if unsafe { SetConsoleOutputCP(65001) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(guard)
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        // SAFETY: restored from GetConsoleOutputCP for the same console.
        unsafe {
            SetConsoleOutputCP(self.output_code_page);
        }
        best_effort(set_mode(&self.output, self.saved_output));
    }
}

pub struct ReplayTerminal {
    tty: Tty,
    _raw: RawMode,
}

impl ReplayTerminal {
    pub fn open() -> io::Result<Self> {
        Ok(Self {
            tty: Tty::open()?,
            _raw: RawMode::enter()?,
        })
    }

    pub fn keys(&self, timeout: Duration, buf: &mut [u8]) -> io::Result<Option<usize>> {
        if !self.tty.wait(timeout)? {
            return Ok(Some(0));
        }
        match (&self.tty.input).read(buf)? {
            0 => Ok(None),
            n => Ok(Some(n)),
        }
    }
}

impl Write for ReplayTerminal {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        (&self.tty.output).write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        (&self.tty.output).flush()
    }
}

pub fn window_size() -> Option<(u32, u32)> {
    let output = console("CONOUT$").ok()?;
    let mut info = CONSOLE_SCREEN_BUFFER_INFO::default();
    // SAFETY: output owns the handle; info is a valid initialized out-buffer.
    if unsafe { GetConsoleScreenBufferInfo(output.as_raw_handle(), &mut info) } == 0 {
        return None;
    }
    let cols = i32::from(info.srWindow.Right)
        .checked_sub(i32::from(info.srWindow.Left))?
        .checked_add(1)?;
    let rows = i32::from(info.srWindow.Bottom)
        .checked_sub(i32::from(info.srWindow.Top))?
        .checked_add(1)?;
    Some((u32::try_from(cols).ok()?, u32::try_from(rows).ok()?))
}

fn stdin_handle() -> HANDLE {
    // SAFETY: GetStdHandle borrows this process's standard handle.
    unsafe { GetStdHandle(STD_INPUT_HANDLE) }
}

pub fn wait_for_input(timeout: Duration) -> io::Result<bool> {
    ready(stdin_handle(), timeout)
}

pub fn read_stdin(buf: &mut [u8]) -> io::Result<usize> {
    // Read the console directly: std::Stdin's cooked buffer must not retain
    // bytes across the raw/cooked transitions of the host picker.
    (&console("CONIN$")?).read(buf)
}

/// Windows has no foreground process groups. Terminal approvals require a
/// dedicated console owned by this process; a shared shell/agent console is
/// never accepted as an approval surface. Redirected stdin is always refused.
pub fn stdin_is_foreground() -> bool {
    use std::io::IsTerminal;
    if !io::stdin().is_terminal() {
        return false;
    }
    let mut process = 0;
    // SAFETY: process has space for exactly the one entry requested. A return
    // greater than one means more processes are attached; no buffer is read then.
    let count = unsafe { GetConsoleProcessList(&mut process, 1) };
    // SAFETY: GetCurrentProcessId has no arguments or ownership requirements.
    count == 1 && process == unsafe { GetCurrentProcessId() }
}

fn ready(input: HANDLE, timeout: Duration) -> io::Result<bool> {
    let start = Instant::now();
    loop {
        let left = timeout.saturating_sub(start.elapsed());
        if left.is_zero() {
            return Ok(false);
        }
        let millis = u32::try_from(left.as_millis().max(1)).unwrap_or(u32::MAX - 1);
        // SAFETY: input is a borrowed live console handle; no ownership changes.
        match unsafe { WaitForSingleObject(input, millis) } {
            WAIT_TIMEOUT => return Ok(false),
            WAIT_OBJECT_0 => {}
            _ => return Err(io::Error::last_os_error()),
        }
        let mut record = INPUT_RECORD::default();
        let mut count = 0;
        // SAFETY: record has capacity for the single record requested; count is writable.
        if unsafe { PeekConsoleInputW(input, &mut record, 1, &mut count) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if count == 0 {
            continue;
        }
        if u32::from(record.EventType) == KEY_EVENT {
            // SAFETY: KEY_EVENT identifies the initialized KeyEvent union arm.
            let key = unsafe { record.Event.KeyEvent };
            // SAFETY: Unicode console APIs initialize the UnicodeChar arm.
            let character = unsafe { key.uChar.UnicodeChar };
            if key.bKeyDown != 0
                && (character != 0 || matches!(key.wVirtualKeyCode, 0x20..=0x2e | 0x70..=0x87))
            {
                return Ok(true);
            }
        }
        // Key-up, focus and resize records must not make a later ReadFile
        // block while a session is closing or a prompt deadline has elapsed.
        // SAFETY: record/count are valid out-buffers for one input record.
        if unsafe { ReadConsoleInputW(input, &mut record, 1, &mut count) } == 0 {
            return Err(io::Error::last_os_error());
        }
    }
}
