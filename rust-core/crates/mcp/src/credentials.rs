//! Versioned, local-only integration credentials. Persist digests, never bearer tokens.
use crate::{Authenticator, IntegrationId};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{self, Write},
    path::PathBuf,
    sync::Mutex,
};
use subtle::ConstantTimeEq;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    id: String,
    label: String,
    digest: [u8; 32],
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    version: u32,
    enabled: bool,
    port: u16,
    integrations: Vec<Record>,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            version: 1,
            enabled: false,
            port: 0,
            integrations: Vec::new(),
        }
    }
}
#[derive(Serialize)]
pub struct Integration {
    pub id: String,
    pub label: String,
}
pub struct Credentials {
    path: PathBuf,
    config: Mutex<Config>,
}

impl Credentials {
    pub fn load(path: PathBuf) -> io::Result<Self> {
        let config = match fs::metadata(&path) {
            Ok(meta) => {
                if meta.len() > 64 * 1024 {
                    return Err(invalid());
                }
                let c: Config = serde_json::from_slice(&fs::read(&path)?).map_err(|_| invalid())?;
                if c.version != 1
                    || c.integrations.len() > 32
                    || c.integrations
                        .iter()
                        .any(|r| r.id.is_empty() || r.label.len() > 120)
                {
                    return Err(invalid());
                }
                c
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Config::default(),
            Err(e) => return Err(e),
        };
        Ok(Self {
            path,
            config: Mutex::new(config),
        })
    }
    fn mutate<T>(&self, f: impl FnOnce(&mut Config) -> io::Result<T>) -> io::Result<T> {
        let mut guard = self.config.lock().map_err(|_| invalid())?;
        let mut config = guard.clone();
        let result = f(&mut config)?;
        let parent = self.path.parent().ok_or_else(invalid)?;
        let mut temp = tempfile::NamedTempFile::new_in(parent)?;
        // NamedTempFile is 0600 on Unix; Windows inherits the user's app-data ACL.
        temp.write_all(&serde_json::to_vec(&config).map_err(|_| invalid())?)?;
        temp.as_file().sync_all()?;
        temp.persist(&self.path).map_err(|e| e.error)?;
        *guard = config;
        Ok(result)
    }
    pub fn settings(&self) -> (bool, u16) {
        let c = self.config.lock().unwrap_or_else(|e| e.into_inner());
        (c.enabled, c.port)
    }
    pub fn set_enabled(&self, enabled: bool, port: u16) -> io::Result<()> {
        self.mutate(|c| {
            c.enabled = enabled;
            c.port = port;
            Ok(())
        })
    }
    pub fn list(&self) -> Vec<Integration> {
        self.config
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .integrations
            .iter()
            .map(|r| Integration {
                id: r.id.clone(),
                label: r.label.clone(),
            })
            .collect()
    }
    /// Returned bearer text is shown once through trusted native UI only.
    pub fn create(&self, label: String) -> io::Result<(String, String)> {
        if label.trim().is_empty() || label.len() > 120 {
            return Err(invalid());
        }
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).map_err(|_| invalid())?;
        let token = format!("unissh_mcp_{}", URL_SAFE_NO_PAD.encode(bytes));
        let digest = Sha256::digest(token.as_bytes()).into();
        getrandom::fill(&mut bytes).map_err(|_| invalid())?;
        let id = URL_SAFE_NO_PAD.encode(bytes);
        self.mutate(|c| {
            if c.integrations.len() >= 32 {
                return Err(invalid());
            }
            c.integrations.push(Record {
                id: id.clone(),
                label,
                digest,
            });
            Ok(())
        })?;
        Ok((id, token))
    }
    pub fn delete(&self, id: &str) -> io::Result<()> {
        self.mutate(|c| {
            c.integrations.retain(|r| r.id != id);
            Ok(())
        })
    }
    /// Rotation changes the authenticated identity, so an already admitted HTTP
    /// request using the old token cannot acquire a newly created grant.
    pub fn rotate(&self, id: &str) -> io::Result<(String, String)> {
        let label = self
            .list()
            .into_iter()
            .find(|r| r.id == id)
            .ok_or_else(invalid)?
            .label;
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).map_err(|_| invalid())?;
        let token = format!("unissh_mcp_{}", URL_SAFE_NO_PAD.encode(bytes));
        let digest = Sha256::digest(token.as_bytes()).into();
        getrandom::fill(&mut bytes).map_err(|_| invalid())?;
        let new_id = URL_SAFE_NO_PAD.encode(bytes);
        self.mutate(|c| {
            c.integrations.retain(|r| r.id != id);
            c.integrations.push(Record {
                id: new_id.clone(),
                label,
                digest,
            });
            Ok(())
        })?;
        Ok((new_id, token))
    }
}
impl Authenticator for Credentials {
    fn authenticate(&self, token: &str) -> Option<IntegrationId> {
        if token.len() > 128 {
            return None;
        }
        let digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        self.config
            .lock()
            .ok()?
            .integrations
            .iter()
            .find(|r| bool::from(r.digest.ct_eq(&digest)))
            .map(|r| IntegrationId(r.id.clone()))
    }
}
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "Invalid local MCP integration configuration",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tokens_are_not_persisted_and_rotation_invalidates_old_identity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp.json");
        let store = Credentials::load(path.clone()).unwrap();
        let (id, token) = store.create("test".into()).unwrap();
        assert_eq!(store.authenticate(&token), Some(IntegrationId(id.clone())));
        assert!(!fs::read_to_string(&path).unwrap().contains(&token));
        let (new_id, new_token) = store.rotate(&id).unwrap();
        assert_ne!(id, new_id);
        assert!(store.authenticate(&token).is_none());
        let reopened = Credentials::load(path.clone()).unwrap();
        assert_eq!(
            reopened.authenticate(&new_token),
            Some(IntegrationId(new_id.clone()))
        );
        reopened.delete(&new_id).unwrap();
        assert!(reopened.authenticate(&new_token).is_none());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
    #[test]
    fn corrupt_or_future_configuration_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp.json");
        fs::write(
            &path,
            br#"{"version":2,"enabled":true,"port":22,"integrations":[]}"#,
        )
        .unwrap();
        assert!(Credentials::load(path.clone()).is_err());
        fs::write(&path, b"corrupt").unwrap();
        assert!(Credentials::load(path).is_err());
    }
}
