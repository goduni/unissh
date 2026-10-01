//! Device-local terminal layouts. SQLCipher protects labels and local shell paths;
//! this metadata is never synced or included in portable vault exports.
use super::{Core, FfiError};

// Keep the storage slot stable across schema migrations; JSON carries its version.
const KEY: &str = "terminal.workspace.v1";

impl Core {
    /// Load the opaque UI layout and the unlock epoch required by its next save.
    pub fn terminal_workspace_load(&self) -> Result<(u64, Option<String>), FfiError> {
        self.with_state(|s| {
            let document = s
                .storage
                .get_meta(KEY)
                .map_err(FfiError::other)?
                .map(String::from_utf8)
                .transpose()
                .map_err(FfiError::other)?;
            Ok((
                self.sftp_epoch.load(std::sync::atomic::Ordering::SeqCst),
                document,
            ))
        })
    }

    /// Save only within the unlock lifetime that supplied the layout.
    pub fn terminal_workspace_save(&self, epoch: u64, document: String) -> Result<(), FfiError> {
        self.with_state(|s| {
            // A queued UI write from a previous unlock must not replace the new
            // session's layout. Core::lock increments this epoch under the same lock.
            if epoch != self.sftp_epoch.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(FfiError::Locked);
            }
            let value: serde_json::Value =
                serde_json::from_str(&document).map_err(|_| FfiError::Other {
                    msg: "Invalid terminal workspace".into(),
                })?;
            if !matches!(
                value.get("version").and_then(serde_json::Value::as_u64),
                Some(1 | 2)
            ) {
                return Err(FfiError::Other {
                    msg: "Unsupported terminal workspace version".into(),
                });
            }
            s.storage
                .set_meta(KEY, document.as_bytes())
                .map_err(FfiError::other)
        })
    }
}
