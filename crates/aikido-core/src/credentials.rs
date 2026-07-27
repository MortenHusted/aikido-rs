//! Credential storage, wire-compatible with the Go CLI it replaces.
//!
//! The keyring entry (`service: aikido-cli`, `user: default`) holds a JSON
//! blob `{client_id, client_secret, access_token, expires_at}`; the plaintext
//! fallback is `~/.config/aikido/credentials.json` with mode 0600. Existing
//! credentials written by the Go CLI keep working unchanged.
//!
//! Backend selection (so tests never touch the real keychain):
//! - `AIKIDO_TOKEN_STORE=file`      → file only
//! - `AIKIDO_TOKEN_STORE=keychain`  → keychain only
//! - unset (default)                → keychain first, file fallback (Go parity)
//!
//! `AIKIDO_CONFIG_DIR` overrides the config directory for the file backend.

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[cfg(any(target_os = "macos", target_os = "windows"))]
const KEYRING_SERVICE: &str = "aikido-cli";
#[cfg(any(target_os = "macos", target_os = "windows"))]
const KEYRING_USER: &str = "default";

pub const STORE_ENV: &str = "AIKIDO_TOKEN_STORE";
pub const CONFIG_DIR_ENV: &str = "AIKIDO_CONFIG_DIR";

/// OAuth client credentials plus the current access token, as persisted.
/// Field names are the wire format shared with the Go CLI — do not rename.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Credentials {
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub client_secret: String,
    #[serde(default)]
    pub access_token: String,
    /// RFC3339 timestamp; empty when unknown.
    #[serde(default)]
    pub expires_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Backend {
    /// Keychain first, file fallback — the Go CLI's behaviour.
    Auto,
    Keychain,
    File,
}

fn backend_from_env() -> Backend {
    match std::env::var(STORE_ENV).unwrap_or_default().as_str() {
        "file" => Backend::File,
        "keychain" => Backend::Keychain,
        _ => Backend::Auto,
    }
}

/// Handle to the credential store. The default store resolves the config
/// directory and backend from the environment at call time; `file_at`
/// builds a store pinned to the file backend in an explicit directory so
/// tests stay hermetic without mutating process-global env.
#[derive(Debug, Clone, Default)]
pub struct CredentialStore {
    forced_backend: Option<Backend>,
    dir_override: Option<PathBuf>,
}

impl CredentialStore {
    /// File-backend store rooted at `dir`. Never touches the OS keychain.
    pub fn file_at(dir: impl Into<PathBuf>) -> Self {
        Self {
            forced_backend: Some(Backend::File),
            dir_override: Some(dir.into()),
        }
    }

    fn backend(&self) -> Backend {
        self.forced_backend.unwrap_or_else(backend_from_env)
    }

    pub fn config_dir(&self) -> PathBuf {
        if let Some(dir) = &self.dir_override {
            return dir.clone();
        }
        if let Ok(dir) = std::env::var(CONFIG_DIR_ENV) {
            return PathBuf::from(dir);
        }
        dirs::config_dir()
            .unwrap_or_else(|| dirs::home_dir().unwrap_or_default().join(".config"))
            .join("aikido")
    }

    pub fn credentials_path(&self) -> PathBuf {
        self.config_dir().join("credentials.json")
    }

    /// Load stored credentials. `Ok(None)` when nothing is stored.
    pub fn load(&self) -> Result<Option<Credentials>> {
        match self.backend() {
            Backend::Keychain => keyring_get(),
            Backend::File => self.file_get(),
            Backend::Auto => match keyring_get() {
                Ok(Some(creds)) => Ok(Some(creds)),
                _ => self.file_get(),
            },
        }
    }

    /// Persist credentials to the selected backend.
    pub fn save(&self, creds: &Credentials) -> Result<()> {
        let data = serde_json::to_string(creds).context("serializing credentials")?;
        match self.backend() {
            Backend::Keychain => keyring_set(&data),
            Backend::File => self.file_set(&data),
            Backend::Auto => keyring_set(&data).or_else(|_| self.file_set(&data)),
        }
    }

    /// Remove credentials from both backends. Missing entries are not errors.
    pub fn clear(&self) -> Result<()> {
        if self.backend() != Backend::File {
            let _ = keyring_delete();
        }
        match fs::remove_file(self.credentials_path()) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err).context("removing credentials file"),
        }
    }

    /// True when the file backend holds the credentials (used by `auth status`
    /// to report the source).
    pub fn file_exists(&self) -> bool {
        self.credentials_path().exists()
    }

    fn file_get(&self) -> Result<Option<Credentials>> {
        let path = self.credentials_path();
        match fs::read_to_string(&path) {
            Ok(contents) => {
                let creds = serde_json::from_str(&contents)
                    .with_context(|| format!("parsing {}", path.display()))?;
                Ok(Some(creds))
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err).context(format!("reading {}", path.display())),
        }
    }

    fn file_set(&self, data: &str) -> Result<()> {
        let dir = self.config_dir();
        fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        let path = self.credentials_path();
        fs::write(&path, data).with_context(|| format!("writing {}", path.display()))?;
        chmod_600(&path)
    }
}

#[cfg(unix)]
fn chmod_600(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(path)
        .with_context(|| format!("reading metadata of {}", path.display()))?
        .permissions();
    perms.set_mode(0o600);
    fs::set_permissions(path, perms).with_context(|| format!("chmod 600 {}", path.display()))
}

#[cfg(not(unix))]
fn chmod_600(_path: &std::path::Path) -> Result<()> {
    Ok(())
}

// ---------------------------------------------------------------------------
// Keychain backend
// ---------------------------------------------------------------------------

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn keyring_entry() -> Result<keyring::Entry> {
    keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER).context("opening keyring entry aikido-cli")
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn keyring_get() -> Result<Option<Credentials>> {
    let entry = keyring_entry()?;
    match entry.get_password() {
        Ok(data) => Ok(Some(
            serde_json::from_str(&data).context("parsing keyring credentials")?,
        )),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(err) => Err(anyhow::Error::new(err).context("reading keyring entry aikido-cli")),
    }
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn keyring_set(data: &str) -> Result<()> {
    keyring_entry()?
        .set_password(data)
        .context("writing keyring entry aikido-cli")
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn keyring_delete() -> Result<()> {
    match keyring_entry()?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(err) => Err(anyhow::Error::new(err).context("deleting keyring entry aikido-cli")),
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn keyring_get() -> Result<Option<Credentials>> {
    anyhow::bail!("OS keychain backend is not available in this build")
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn keyring_set(_data: &str) -> Result<()> {
    anyhow::bail!("OS keychain backend is not available in this build")
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn keyring_delete() -> Result<()> {
    Ok(())
}
