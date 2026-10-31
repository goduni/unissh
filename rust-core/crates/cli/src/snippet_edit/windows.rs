//! Launch trusted editor configuration, including arguments and .cmd launchers.

use std::io;
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::{Command, ExitStatus};

pub(super) fn launch(editor: &str, path: &Path) -> io::Result<ExitStatus> {
    // The editor is trusted user configuration. Pass the document through a
    // quoted environment variable, never as shell source. Expansion is not
    // recursive, and /v:off keeps ! in the document's path literal.
    Command::new("cmd.exe")
        .args(["/d", "/v:off", "/s", "/c"])
        .raw_arg(format!("\"{editor} \"%UNISSH_CLI_EDIT_FILE%\"\""))
        .env("UNISSH_CLI_EDIT_FILE", path)
        .status()
}

#[cfg(test)]
mod tests {
    #[test]
    fn editor_arguments_and_document_metacharacters_survive() {
        let tmp = tempfile::tempdir().unwrap();
        let directory = tmp.path().join("editor tools");
        std::fs::create_dir_all(&directory).unwrap();
        let editor = directory.join("fake editor.cmd");
        std::fs::write(
            &editor,
            b"@echo off\r\nif not \"%~1\"==\"--wait\" exit /b 2\r\n> \"%~2\" echo changed\r\n",
        )
        .unwrap();
        let document = tmp.path().join("notes & %PATH% !.txt");
        std::fs::write(&document, b"original").unwrap();
        let command = format!("\"{}\" --wait", editor.display());
        assert!(super::launch(&command, &document).unwrap().success());
        assert_eq!(
            std::fs::read_to_string(&document).unwrap().trim(),
            "changed"
        );
    }
}
