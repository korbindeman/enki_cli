//! Configuration and credential storage

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

const CONFIG_DIR: &str = ".enki";
const CREDENTIALS_FILE: &str = "credentials.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credentials {
    pub refresh_token: String,
    pub user_id: String,
    pub email: String,
}

/// Get the Enki config directory (~/.enki)
pub fn config_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().context("Could not determine home directory")?;
    Ok(home.join(CONFIG_DIR))
}

/// Get the credentials file path
fn credentials_path() -> Result<PathBuf> {
    Ok(config_dir()?.join(CREDENTIALS_FILE))
}

/// Load stored credentials
pub fn load_credentials() -> Result<Option<Credentials>> {
    let path = credentials_path()?;

    if !path.exists() {
        return Ok(None);
    }

    let contents = fs::read_to_string(&path).context("Failed to read credentials file")?;

    let creds: Credentials =
        serde_json::from_str(&contents).context("Failed to parse credentials")?;

    Ok(Some(creds))
}

/// Save credentials to disk
pub fn save_credentials(creds: &Credentials) -> Result<()> {
    let dir = config_dir()?;
    fs::create_dir_all(&dir).context("Failed to create config directory")?;

    let path = credentials_path()?;
    let contents = serde_json::to_string_pretty(creds)?;

    fs::write(&path, contents).context("Failed to write credentials file")?;

    // Set file permissions to owner-only
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&path, perms)?;
    }

    #[cfg(windows)]
    {
        // Remove inherited permissions, grant only current user full control
        let username = std::env::var("USERNAME").context("Could not determine Windows username")?;
        let output = std::process::Command::new("icacls")
            .arg(&path)
            .arg("/inheritance:r")
            .arg("/grant:r")
            .arg(format!("{}:F", username))
            .output()
            .context("Failed to set file permissions")?;
        if !output.status.success() {
            anyhow::bail!("Failed to restrict credentials file permissions");
        }
    }

    Ok(())
}

/// Delete stored credentials
pub fn delete_credentials() -> Result<()> {
    let path = credentials_path()?;

    if path.exists() {
        fs::remove_file(&path).context("Failed to delete credentials file")?;
    }

    Ok(())
}

/// Get the Enki server URL
pub fn server_url() -> String {
    std::env::var("ENKI_SERVER_URL").unwrap_or_else(|_| default_server_url().to_string())
}

/// Get the Enki web app URL (for auth)
pub fn web_url() -> String {
    std::env::var("ENKI_WEB_URL").unwrap_or_else(|_| default_web_url().to_string())
}

#[cfg(debug_assertions)]
fn default_server_url() -> &'static str {
    "http://localhost:8080"
}

#[cfg(not(debug_assertions))]
fn default_server_url() -> &'static str {
    "https://enki.works"
}

#[cfg(debug_assertions)]
fn default_web_url() -> &'static str {
    "http://localhost:3000"
}

#[cfg(not(debug_assertions))]
fn default_web_url() -> &'static str {
    "https://enki.works"
}
