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
    /// Keyring service override — interop tests use a throwaway service so
    /// they never touch the real `aikido-cli` entry.
    service_override: Option<String>,
}

impl CredentialStore {
    /// File-backend store rooted at `dir`. Never touches the OS keychain.
    pub fn file_at(dir: impl Into<PathBuf>) -> Self {
        Self {
            forced_backend: Some(Backend::File),
            dir_override: Some(dir.into()),
            service_override: None,
        }
    }

    /// Keychain-backend store under a non-default service name. For interop
    /// tests only — production always uses the `aikido-cli` service.
    pub fn keychain_at_service(service: impl Into<String>) -> Self {
        Self {
            forced_backend: Some(Backend::Keychain),
            dir_override: None,
            service_override: Some(service.into()),
        }
    }

    fn backend(&self) -> Backend {
        self.forced_backend.unwrap_or_else(backend_from_env)
    }

    fn keyring_service(&self) -> &str {
        self.service_override.as_deref().unwrap_or(KEYRING_SERVICE)
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
            Backend::Keychain => keyring_get(self.keyring_service()),
            Backend::File => self.file_get(),
            Backend::Auto => match keyring_get(self.keyring_service()) {
                Ok(Some(creds)) => Ok(Some(creds)),
                _ => self.file_get(),
            },
        }
    }

    /// Persist credentials to the selected backend.
    pub fn save(&self, creds: &Credentials) -> Result<()> {
        let data = serde_json::to_string(creds).context("serializing credentials")?;
        match self.backend() {
            Backend::Keychain => keyring_set(self.keyring_service(), &data),
            Backend::File => self.file_set(&data),
            Backend::Auto => {
                keyring_set(self.keyring_service(), &data).or_else(|_| self.file_set(&data))
            }
        }
    }

    /// Remove credentials from both backends. Missing entries are not errors.
    pub fn clear(&self) -> Result<()> {
        if self.backend() != Backend::File {
            let _ = keyring_delete(self.keyring_service());
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
// go-keyring payload codec
// ---------------------------------------------------------------------------
//
// The Go CLI stores keychain values through zalando/go-keyring, whose macOS
// backend unconditionally writes `go-keyring-base64:` + base64(payload)
// (it shells out to `security`, whose output hex-mangles non-trivial data,
// so it encodes everything defensively). Its reader also accepts a legacy
// `go-keyring-encoded:` + hex(payload) form, and raw values.
//
// To interoperate in both directions we mirror that exactly: decode all
// three forms on read, and write the base64-prefixed form so the Go binary
// (and `security find-generic-password -w`) read our entries back cleanly.

const GO_KEYRING_BASE64_PREFIX: &str = "go-keyring-base64:";
const GO_KEYRING_HEX_PREFIX: &str = "go-keyring-encoded:";

/// Encode a keychain payload the way go-keyring's macOS backend writes it.
pub fn encode_go_keyring_payload(payload: &str) -> String {
    use base64::Engine as _;
    format!(
        "{GO_KEYRING_BASE64_PREFIX}{}",
        base64::engine::general_purpose::STANDARD.encode(payload)
    )
}

/// Decode a keychain value that may carry a go-keyring encoding prefix.
/// Unprefixed values pass through unchanged (go-keyring's reader does the
/// same, and entries written by other tools stay readable).
pub fn decode_go_keyring_payload(raw: &str) -> Result<String> {
    use base64::Engine as _;
    let trimmed = raw.trim();
    if let Some(encoded) = trimmed.strip_prefix(GO_KEYRING_BASE64_PREFIX) {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .context("decoding go-keyring base64 keychain payload")?;
        return String::from_utf8(bytes).context("go-keyring keychain payload is not UTF-8");
    }
    if let Some(encoded) = trimmed.strip_prefix(GO_KEYRING_HEX_PREFIX) {
        let bytes = decode_hex(encoded).context("decoding go-keyring hex keychain payload")?;
        return String::from_utf8(bytes).context("go-keyring keychain payload is not UTF-8");
    }
    Ok(trimmed.to_string())
}

fn decode_hex(input: &str) -> Result<Vec<u8>> {
    if !input.len().is_multiple_of(2) {
        anyhow::bail!("odd-length hex string");
    }
    (0..input.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&input[i..i + 2], 16).context("invalid hex digit"))
        .collect()
}

// ---------------------------------------------------------------------------
// Keychain backend
// ---------------------------------------------------------------------------

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn keyring_entry(service: &str) -> Result<keyring::Entry> {
    keyring::Entry::new(service, KEYRING_USER)
        .with_context(|| format!("opening keyring entry {service}"))
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn keyring_get(service: &str) -> Result<Option<Credentials>> {
    let entry = keyring_entry(service)?;
    match entry.get_password() {
        Ok(data) => {
            let json = decode_go_keyring_payload(&data)?;
            Ok(Some(
                serde_json::from_str(&json).context("parsing keyring credentials")?,
            ))
        }
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(err) => {
            Err(anyhow::Error::new(err).context(format!("reading keyring entry {service}")))
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn keyring_set(service: &str, data: &str) -> Result<()> {
    keyring_entry(service)?
        .set_password(&encode_go_keyring_payload(data))
        .with_context(|| format!("writing keyring entry {service}"))
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn keyring_delete(service: &str) -> Result<()> {
    match keyring_entry(service)?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(err) => {
            Err(anyhow::Error::new(err).context(format!("deleting keyring entry {service}")))
        }
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn keyring_get(_service: &str) -> Result<Option<Credentials>> {
    anyhow::bail!("OS keychain backend is not available in this build")
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn keyring_set(_service: &str, _data: &str) -> Result<()> {
    anyhow::bail!("OS keychain backend is not available in this build")
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn keyring_delete(_service: &str) -> Result<()> {
    Ok(())
}
