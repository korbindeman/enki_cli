//! Auto-update check against GitHub releases

use anyhow::Result;

/// Check for a newer release on GitHub and prompt the user to update.
/// No-op in debug builds. On network errors, prints a warning and continues.
#[cfg(not(debug_assertions))]
pub async fn check_and_prompt() -> Result<()> {
    use anyhow::Context;

    const REPO: &str = "korbindeman/enki_cli";
    const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

    // Fetch latest version from GitHub
    let latest = match async {
        let url = format!("https://api.github.com/repos/{}/releases/latest", REPO);

        let client = reqwest::Client::new();
        let resp = client
            .get(&url)
            .header("User-Agent", format!("enki-cli/{}", CURRENT_VERSION))
            .send()
            .await
            .context("Failed to reach GitHub API")?;

        if !resp.status().is_success() {
            anyhow::bail!("GitHub API returned {}", resp.status());
        }

        let body: serde_json::Value = resp.json().await?;
        let tag = body["tag_name"]
            .as_str()
            .context("Missing tag_name in release")?;

        let version = tag.strip_prefix('v').unwrap_or(tag);
        Ok::<String, anyhow::Error>(version.to_string())
    }
    .await
    {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Warning: could not check for updates ({})", e);
            return Ok(());
        }
    };

    // Compare versions (simple semver: split on '.', compare numerically)
    let parse =
        |v: &str| -> Vec<u64> { v.split('.').filter_map(|s| s.parse::<u64>().ok()).collect() };
    if parse(&latest) <= parse(CURRENT_VERSION) {
        return Ok(());
    }

    println!("Update available: {} -> {}", CURRENT_VERSION, latest);
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

    // Detect target triple
    let target = match (cfg!(target_arch = "x86_64"), cfg!(target_arch = "aarch64")) {
        (true, _) => match cfg!(target_os = "macos") {
            true => "x86_64-apple-darwin",
            false => "x86_64-unknown-linux-gnu",
        },
        (_, true) => match cfg!(target_os = "macos") {
            true => "aarch64-apple-darwin",
            false => "aarch64-unknown-linux-gnu",
        },
        _ => anyhow::bail!("Unsupported platform for auto-update"),
    };

    let asset_name = format!("enki-{}.tar.gz", target);
    let download_url = format!(
        "https://github.com/{}/releases/download/v{}/{}",
        REPO, latest, asset_name
    );

    println!("Downloading {}...", asset_name);

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

    println!("\nUpdated to {}. Please re-run the command.", latest);
    std::process::exit(0);
}

#[cfg(debug_assertions)]
pub async fn check_and_prompt() -> Result<()> {
    Ok(())
}
