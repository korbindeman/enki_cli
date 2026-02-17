//! Update check against GitHub releases

use anyhow::Result;
use colored::Colorize;

const REPO: &str = "korbindeman/enki_cli";
const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Fetch the latest version tag from GitHub releases.
/// Returns None on network errors (with a warning printed).
async fn fetch_latest_version() -> Option<String> {
    let url = format!("https://api.github.com/repos/{}/releases/latest", REPO);

    let client = reqwest::Client::new();
    let resp = match client
        .get(&url)
        .header("User-Agent", format!("enki-cli/{}", CURRENT_VERSION))
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => r,
        Ok(r) => {
            eprintln!(
                "  {} Could not check for updates (HTTP {})",
                "✗".red(),
                r.status()
            );
            return None;
        }
        Err(e) => {
            eprintln!("  {} Could not check for updates ({})", "✗".red(), e);
            return None;
        }
    };

    let body: serde_json::Value = match resp.json().await {
        Ok(b) => b,
        Err(e) => {
            eprintln!("  {} Could not parse update response ({})", "✗".red(), e);
            return None;
        }
    };

    let tag = body["tag_name"].as_str()?;
    let version = tag.strip_prefix('v').unwrap_or(tag);
    Some(version.to_string())
}

/// Compare semver strings. Returns true if `a` is newer than `b`.
fn is_newer(a: &str, b: &str) -> bool {
    let parse =
        |v: &str| -> Vec<u64> { v.split('.').filter_map(|s| s.parse::<u64>().ok()).collect() };
    parse(a) > parse(b)
}

/// Download and install the given version. Replaces the current binary.
async fn install_version(version: &str) -> Result<()> {
    use anyhow::Context;

    let target = detect_target()?;
    let asset_name = format!("enki-{}.tar.gz", target);
    let download_url = format!(
        "https://github.com/{}/releases/download/v{}/{}",
        REPO, version, asset_name
    );

    println!("  {} Downloading {}...", "▸".cyan(), asset_name.dimmed());

    let client = reqwest::Client::new();
    let resp = client
        .get(&download_url)
        .header("User-Agent", format!("enki-cli/{}", CURRENT_VERSION))
        .send()
        .await
        .context("Failed to download update")?;

    if !resp.status().is_success() {
        anyhow::bail!("Download failed: HTTP {}", resp.status());
    }

    let bytes = resp.bytes().await.context("Failed to read download")?;

    // Extract the binary from the tarball
    let decoder = flate2::read::GzDecoder::new(&bytes[..]);
    let mut archive = tar::Archive::new(decoder);
    let mut new_binary = None;

    for entry in archive.entries().context("Failed to read archive")? {
        let mut entry = entry.context("Failed to read archive entry")?;
        let path = entry.path().context("Failed to read entry path")?;
        if path.file_name().and_then(|n| n.to_str()) == Some("enki") {
            let mut buf = Vec::new();
            std::io::Read::read_to_end(&mut entry, &mut buf)
                .context("Failed to read binary from archive")?;
            new_binary = Some(buf);
            break;
        }
    }

    let new_binary = new_binary.context("Binary not found in archive")?;

    // Replace the current executable
    let current_exe = std::env::current_exe().context("Failed to determine current executable")?;
    let backup = current_exe.with_extension("bak");

    std::fs::rename(&current_exe, &backup).context("Failed to back up current binary")?;
    std::fs::write(&current_exe, &new_binary).context("Failed to write new binary")?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&current_exe)?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&current_exe, perms)?;
    }

    let _ = std::fs::remove_file(&backup);

    Ok(())
}

fn detect_target() -> Result<&'static str> {
    match (cfg!(target_arch = "x86_64"), cfg!(target_arch = "aarch64")) {
        (true, _) => match cfg!(target_os = "macos") {
            true => Ok("x86_64-apple-darwin"),
            false => Ok("x86_64-unknown-linux-gnu"),
        },
        (_, true) => match cfg!(target_os = "macos") {
            true => Ok("aarch64-apple-darwin"),
            false => Ok("aarch64-unknown-linux-gnu"),
        },
        _ => anyhow::bail!("Unsupported platform for auto-update"),
    }
}

/// Explicit `enki update` command. Always checks, no prompt.
pub async fn run() -> Result<()> {
    println!("{} Checking for updates...", "●".yellow());
    println!("  Current version: {}", CURRENT_VERSION.bold());

    let latest = match fetch_latest_version().await {
        Some(v) => v,
        None => anyhow::bail!("Could not check for updates"),
    };

    if !is_newer(&latest, CURRENT_VERSION) {
        println!("{} Already up to date", "●".green());
        return Ok(());
    }

    println!(
        "{} Updating {} -> {}",
        "●".yellow(),
        CURRENT_VERSION.dimmed(),
        latest.green().bold()
    );

    install_version(&latest).await?;

    println!("{} Updated to {}", "●".green(), latest.green().bold());
    Ok(())
}

/// Auto-check on startup: prompt user before updating. No-op in debug builds.
#[cfg(not(debug_assertions))]
pub async fn check_and_prompt() -> Result<()> {
    use anyhow::Context;

    let latest = match fetch_latest_version().await {
        Some(v) => v,
        None => return Ok(()),
    };

    if !is_newer(&latest, CURRENT_VERSION) {
        return Ok(());
    }

    println!(
        "{} Update available: {} -> {}",
        "●".yellow(),
        CURRENT_VERSION.dimmed(),
        latest.green().bold()
    );
    print!("Update? [Y/n] ");

    use std::io::Write;
    std::io::stdout()
        .flush()
        .context("Failed to flush stdout")?;

    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .context("Failed to read input")?;

    let input = input.trim().to_lowercase();
    if !input.is_empty() && input != "y" && input != "yes" {
        return Ok(());
    }

    install_version(&latest).await?;

    println!(
        "\n{} Updated to {}. Please re-run the command.",
        "●".green(),
        latest.green().bold()
    );
    std::process::exit(0);
}

#[cfg(debug_assertions)]
pub async fn check_and_prompt() -> Result<()> {
    Ok(())
}
