use zeroize::Zeroizing;

/// SSH exec has no portable cwd field. For POSIX remote shells, quote the
/// absolute directory literally and fail before the command if cd fails.
pub(super) fn command(command: &str, cwd: Option<&str>) -> Zeroizing<String> {
    match cwd {
        None => Zeroizing::new(command.to_owned()),
        Some(cwd) => Zeroizing::new(format!(
            "cd '{}' || exit\n{command}",
            cwd.replace('\'', "'\\''")
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directory_is_literal_and_failure_prevents_every_command() {
        let path = "/tmp/space ' $(touch should-not-exist); directory";
        let wrapped = command("printf ran; printf twice", Some(path));
        assert_eq!(&*wrapped, "cd '/tmp/space '\\'' $(touch should-not-exist); directory' || exit\nprintf ran; printf twice");
        assert_eq!(&*command("pwd", None), "pwd");
    }

    #[cfg(unix)]
    #[test]
    fn real_shell_uses_literal_directory_and_does_not_keep_cwd() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("space ' $(touch injected); $HOME");
        std::fs::create_dir(&dir).unwrap();
        let source = command("pwd", dir.to_str());
        let result = std::process::Command::new("sh")
            .arg("-c")
            .arg(&*source)
            .output()
            .unwrap();
        assert!(result.status.success());
        assert_eq!(
            String::from_utf8(result.stdout).unwrap().trim(),
            dir.to_str().unwrap()
        );
        let marker = root.path().join("should-not-run");
        let body = format!("touch '{}'; touch '{}'", marker.display(), marker.display());
        let source = command(&body, root.path().join("missing").to_str());
        let result = std::process::Command::new("sh")
            .arg("-c")
            .arg(&*source)
            .output()
            .unwrap();
        assert!(!result.status.success());
        assert!(!marker.exists());
        assert_ne!(std::env::current_dir().unwrap(), dir);
    }
}
