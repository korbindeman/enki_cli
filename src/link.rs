//! Link command - connect this machine to Enki

use anyhow::{bail, Context, Result};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::sync::mpsc;
use tokio_tungstenite::{connect_async, tungstenite::Message};

use crate::claude_code::ClaudeCodeManager;
use crate::config;

/// Lock file guard - ensures only one `enki link` per machine.
/// Removes the lock file when dropped.
struct LinkLock {
    path: PathBuf,
}

impl LinkLock {
    fn acquire() -> Result<Self> {
        let path = config::config_dir()?.join("link.lock");

        if path.exists() {
            let contents = std::fs::read_to_string(&path).unwrap_or_default();
            if let Ok(pid) = contents.trim().parse::<u32>() {
                if process_exists(pid) {
                    bail!(
                        "Another enki link is already running (PID {}). Only one link per machine is allowed.",
                        pid
                    );
                }
            }
            // Stale lock from a crashed process, remove it
            let _ = std::fs::remove_file(&path);
        }

        std::fs::write(&path, std::process::id().to_string())
            .context("Failed to write lock file")?;

        Ok(LinkLock { path })
    }
}

impl Drop for LinkLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(unix)]
fn process_exists(pid: u32) -> bool {
    std::process::Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(windows)]
fn process_exists(pid: u32) -> bool {
    std::process::Command::new("tasklist")
        .args(["/FI", &format!("PID eq {}", pid), "/NH"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains(&pid.to_string()))
        .unwrap_or(false)
}

/// Messages sent from CLI to server
#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ClientMessage {
    /// Announce capabilities on connect
    Announce { capabilities: Vec<Capability> },
    /// Result of capability execution
    Result {
        request_id: String,
        status: String,
        data: Option<String>,
        error: Option<String>,
    },
    /// Heartbeat
    Ping,
}

/// Messages sent from server to CLI
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ServerMessage {
    /// Execute a capability
    Execute {
        request_id: String,
        capability: String,
        params: serde_json::Value,
    },
    /// Heartbeat response
    Pong,
    /// Error
    Error { message: String },

    // Claude Code session messages
    /// Start a new Claude Code session
    CcStart {
        request_id: String,
        cwd: String,
        prompt: String,
    },
    /// Send a follow-up prompt to an existing session
    CcPrompt { session_id: String, prompt: String },
    /// Respond to a permission request
    CcPermissionResponse {
        session_id: String,
        permission_id: String,
        approved: bool,
    },
    /// Cancel a session
    CcCancel { session_id: String },
    /// Interrupt current prompt (cancel without destroying session)
    CcInterrupt { session_id: String },
}

/// A capability this machine can provide
#[derive(Debug, Clone, Serialize)]
pub struct Capability {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paths: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<Tool>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Tool {
    pub name: String,
    pub version: String,
}

/// Try to get dev credentials from the server (only works in dev mode)
#[cfg(debug_assertions)]
async fn try_dev_credentials() -> Result<config::Credentials> {
    let url = format!("{}/api/auth/dev", config::server_url());
    let resp = reqwest::get(&url).await?;

    if !resp.status().is_success() {
        anyhow::bail!("Dev mode not available");
    }

    let body: serde_json::Value = resp.json().await?;
    let refresh_token = body["refresh_token"]
        .as_str()
        .context("Missing refresh_token")?
        .to_string();
    let user_id = body["user"]["id"]
        .as_str()
        .context("Missing user id")?
        .to_string();
    let email = body["user"]["email"]
        .as_str()
        .context("Missing email")?
        .to_string();

    Ok(config::Credentials {
        refresh_token,
        user_id,
        email,
    })
}

/// Start the link connection
pub async fn start(capabilities_filter: Option<String>, persistent: bool) -> Result<()> {
    // Check for updates before anything else (no-op in debug builds)
    crate::update::check_and_prompt().await?;

    let _lock = LinkLock::acquire()?;

    // In debug builds, always use dev credentials
    #[cfg(debug_assertions)]
    let creds = match try_dev_credentials().await {
        Ok(creds) => {
            println!("Using dev credentials");
            creds
        }
        Err(_) => match config::load_credentials()? {
            Some(creds) => creds,
            None => {
                println!("Not authenticated. Starting login...\n");
                crate::auth::login_flow().await?
            }
        },
    };
    #[cfg(not(debug_assertions))]
    let creds = match config::load_credentials()? {
        Some(creds) => creds,
        None => {
            println!("Not authenticated. Starting login...\n");
            crate::auth::login_flow().await?
        }
    };

    println!("Connecting as {}...", creds.email);

    // Detect capabilities
    let capabilities = detect_capabilities(capabilities_filter)?;

    println!("Advertising {} capabilities:", capabilities.len());
    for cap in &capabilities {
        println!("  - {}", cap.name);
    }

    // Prevent system sleep if --persistent is set (held until dropped)
    let _awake_guard = if persistent {
        let guard = keepawake::Builder::default()
            .reason("Enki link active")
            .app_name("enki")
            .create()
            .context("Failed to inhibit system sleep")?;
        println!("Persistent mode: system sleep inhibited");
        Some(guard)
    } else {
        None
    };

    // Exchange refresh token for a JWT to use for WS auth
    let jwt = crate::auth::get_jwt(&creds.refresh_token)
        .await
        .context("Failed to get JWT. Try 'enki login' to re-authenticate.")?;

    // Connect to server (pass JWT as query param since WS headers are tricky)
    let ws_url = format!(
        "{}/ws/link?token={}",
        config::server_url()
            .replace("http://", "ws://")
            .replace("https://", "wss://"),
        urlencoding::encode(&jwt)
    );

    let (ws_stream, _response) = connect_async(&ws_url)
        .await
        .context("Failed to connect to Enki server")?;

    println!("Connected!\n");

    let (mut write, mut read) = ws_stream.split();

    // Send announce message
    let announce = ClientMessage::Announce {
        capabilities: capabilities.clone(),
    };
    write
        .send(Message::Text(serde_json::to_string(&announce)?))
        .await?;

    println!("Link active. Press Ctrl+C to disconnect.\n");

    // Channel for outgoing messages from ClaudeCodeManager
    let (cc_tx, mut cc_rx) = mpsc::unbounded_channel::<String>();
    let cc_manager = ClaudeCodeManager::new(cc_tx);

    // Wrap in LocalSet since ACP futures are !Send
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async move {
            loop {
                tokio::select! {
                    msg = read.next() => {
                        match msg {
                            Some(Ok(Message::Text(text))) => {
                                match serde_json::from_str::<ServerMessage>(&text) {
                                    Ok(ServerMessage::Execute { request_id, capability, params }) => {
                                        println!("[execute] {} with {:?}", capability, params);

                                        let result = execute_capability(&capability, &params).await;

                                        let response = match result {
                                            Ok(data) => ClientMessage::Result {
                                                request_id,
                                                status: "success".to_string(),
                                                data: Some(data),
                                                error: None,
                                            },
                                            Err(e) => ClientMessage::Result {
                                                request_id,
                                                status: "error".to_string(),
                                                data: None,
                                                error: Some(e.to_string()),
                                            },
                                        };

                                        write.send(Message::Text(serde_json::to_string(&response)?)).await?;
                                    }
                                    Ok(ServerMessage::Pong) => {}
                                    Ok(ServerMessage::Error { message }) => {
                                        eprintln!("[error] {}", message);
                                    }

                                    // Claude Code session messages
                                    Ok(ServerMessage::CcStart { request_id, cwd, prompt }) => {
                                        println!("[claude_code] Starting session: {}", &prompt[..prompt.len().min(60)]);
                                        if let Err(e) = cc_manager.start_session(request_id, cwd, prompt).await {
                                            eprintln!("[claude_code] Failed to start session: {}", e);
                                        }
                                    }
                                    Ok(ServerMessage::CcPrompt { session_id, prompt }) => {
                                        println!("[claude_code] Follow-up prompt for {}", session_id);
                                        if let Err(e) = cc_manager.send_prompt(&session_id, prompt).await {
                                            eprintln!("[claude_code] Failed to send prompt: {}", e);
                                        }
                                    }
                                    Ok(ServerMessage::CcPermissionResponse { session_id: _, permission_id, approved }) => {
                                        cc_manager.handle_permission_response(&permission_id, approved);
                                    }
                                    Ok(ServerMessage::CcCancel { session_id }) => {
                                        println!("[claude_code] Cancelling session {}", session_id);
                                        if let Err(e) = cc_manager.cancel_session(&session_id).await {
                                            eprintln!("[claude_code] Failed to cancel: {}", e);
                                        }
                                    }
                                    Ok(ServerMessage::CcInterrupt { session_id }) => {
                                        println!("[claude_code] Interrupting session {}", session_id);
                                        if let Err(e) = cc_manager.interrupt_session(&session_id).await {
                                            eprintln!("[claude_code] Failed to interrupt: {}", e);
                                        }
                                    }

                                    Err(e) => {
                                        eprintln!("[parse error] {}: {}", e, text);
                                    }
                                }
                            }
                            Some(Ok(Message::Close(_))) => {
                                println!("Connection closed by server");
                                break;
                            }
                            Some(Err(e)) => {
                                eprintln!("WebSocket error: {}", e);
                                break;
                            }
                            None => {
                                println!("Connection closed");
                                break;
                            }
                            _ => {}
                        }
                    }

                    // Outgoing messages from ClaudeCodeManager
                    Some(msg) = cc_rx.recv() => {
                        write.send(Message::Text(msg)).await?;
                    }

                    // Send periodic ping
                    _ = tokio::time::sleep(tokio::time::Duration::from_secs(30)) => {
                        write.send(Message::Text(serde_json::to_string(&ClientMessage::Ping)?)).await?;
                    }
                }
            }

            Ok::<_, anyhow::Error>(())
        })
        .await?;

    Ok(())
}

/// Detect capabilities this machine can provide
pub fn detect_capabilities(filter: Option<String>) -> Result<Vec<Capability>> {
    let filter_set: Option<std::collections::HashSet<&str>> = filter
        .as_ref()
        .map(|f| f.split(',').map(|s| s.trim()).collect());

    let mut capabilities = Vec::new();

    // File system access
    if filter_set.as_ref().map_or(true, |f| f.contains("fs")) {
        if let Some(home) = dirs::home_dir() {
            capabilities.push(Capability {
                name: "fs_read".to_string(),
                paths: Some(vec![home.to_string_lossy().to_string()]),
                tools: None,
            });
            capabilities.push(Capability {
                name: "fs_write".to_string(),
                paths: Some(vec![home.to_string_lossy().to_string()]),
                tools: None,
            });
            capabilities.push(Capability {
                name: "fs_list".to_string(),
                paths: Some(vec![home.to_string_lossy().to_string()]),
                tools: None,
            });
            capabilities.push(Capability {
                name: "fs_trash".to_string(),
                paths: Some(vec![home.to_string_lossy().to_string()]),
                tools: None,
            });
            capabilities.push(Capability {
                name: "fs_move".to_string(),
                paths: Some(vec![home.to_string_lossy().to_string()]),
                tools: None,
            });
            capabilities.push(Capability {
                name: "fs_rename".to_string(),
                paths: Some(vec![home.to_string_lossy().to_string()]),
                tools: None,
            });
            capabilities.push(Capability {
                name: "fs_search".to_string(),
                paths: Some(vec![home.to_string_lossy().to_string()]),
                tools: None,
            });
            capabilities.push(Capability {
                name: "fs_grep".to_string(),
                paths: Some(vec![home.to_string_lossy().to_string()]),
                tools: None,
            });
            capabilities.push(Capability {
                name: "fs_mkdir".to_string(),
                paths: Some(vec![home.to_string_lossy().to_string()]),
                tools: None,
            });
            capabilities.push(Capability {
                name: "fs_copy".to_string(),
                paths: Some(vec![home.to_string_lossy().to_string()]),
                tools: None,
            });
            capabilities.push(Capability {
                name: "fs_open".to_string(),
                paths: Some(vec![home.to_string_lossy().to_string()]),
                tools: None,
            });
            capabilities.push(Capability {
                name: "fs_reveal".to_string(),
                paths: Some(vec![home.to_string_lossy().to_string()]),
                tools: None,
            });
            capabilities.push(Capability {
                name: "fs_edit".to_string(),
                paths: Some(vec![home.to_string_lossy().to_string()]),
                tools: None,
            });
        }
    }

    // Shell access
    if filter_set.as_ref().map_or(true, |f| f.contains("shell")) {
        capabilities.push(Capability {
            name: "shell".to_string(),
            paths: None,
            tools: None,
        });
    }

    // Toolchain detection
    if filter_set
        .as_ref()
        .map_or(true, |f| f.contains("toolchain"))
    {
        let mut tools = Vec::new();

        // Detect common toolchains
        let python_cmd = if cfg!(windows) { "python" } else { "python3" };

        for (cmd, name) in [
            ("rustc", "rustc"),
            ("cargo", "cargo"),
            ("node", "node"),
            ("npm", "npm"),
            (python_cmd, "python"),
            ("go", "go"),
        ] {
            if let Ok(output) = std::process::Command::new(cmd).arg("--version").output() {
                if output.status.success() {
                    let version = String::from_utf8_lossy(&output.stdout)
                        .lines()
                        .next()
                        .unwrap_or("unknown")
                        .to_string();
                    tools.push(Tool {
                        name: name.to_string(),
                        version,
                    });
                }
            }
        }

        if !tools.is_empty() {
            capabilities.push(Capability {
                name: "toolchain".to_string(),
                paths: None,
                tools: Some(tools),
            });
        }
    }

    // PDF conversion
    if filter_set.as_ref().map_or(true, |f| f.contains("pdf")) {
        capabilities.push(Capability {
            name: "md_file_to_pdf".to_string(),
            paths: None,
            tools: None,
        });
        capabilities.push(Capability {
            name: "md_to_pdf".to_string(),
            paths: None,
            tools: None,
        });
        capabilities.push(Capability {
            name: "artifact_to_pdf".to_string(),
            paths: None,
            tools: None,
        });
    }

    // Claude Code (via ACP adapter)
    if filter_set
        .as_ref()
        .map_or(true, |f| f.contains("claude_code"))
    {
        if ClaudeCodeManager::is_available() {
            capabilities.push(Capability {
                name: "claude_code".to_string(),
                paths: None,
                tools: None,
            });
        }
    }

    Ok(capabilities)
}

/// Expand ~ to the user's home directory.
/// Also handles common cross-platform shortcuts like ~/Desktop on all platforms.
pub fn expand_tilde(path: &str) -> std::path::PathBuf {
    let path = path.trim();

    if path.starts_with("~/") || path.starts_with("~\\") {
        if let Some(home) = dirs::home_dir() {
            return home.join(&path[2..]);
        }
    } else if path == "~" {
        if let Some(home) = dirs::home_dir() {
            return home;
        }
    }
    std::path::PathBuf::from(path)
}

/// Extract path(s) from params. Accepts either "path" (string) or "paths" (array of strings).
fn get_paths(params: &serde_json::Value) -> Result<Vec<PathBuf>> {
    if let Some(paths) = params.get("paths").and_then(|v| v.as_array()) {
        let result: Vec<PathBuf> = paths
            .iter()
            .filter_map(|v| v.as_str())
            .map(|p| expand_tilde(p))
            .collect();
        if result.is_empty() {
            anyhow::bail!("paths array is empty");
        }
        Ok(result)
    } else if let Some(path) = params.get("path").and_then(|v| v.as_str()) {
        Ok(vec![expand_tilde(path)])
    } else {
        anyhow::bail!("Missing path or paths parameter")
    }
}

/// Check if a command exists on PATH.
fn which_exists(cmd: &str) -> bool {
    std::process::Command::new("which")
        .arg(cmd)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Recursively copy a directory.
async fn copy_dir_recursive(src: &std::path::Path, dst: &std::path::Path) -> Result<()> {
    tokio::fs::create_dir_all(dst).await?;
    let mut entries = tokio::fs::read_dir(src).await?;
    while let Some(entry) = entries.next_entry().await? {
        let target = dst.join(entry.file_name());
        if entry.metadata().await?.is_dir() {
            Box::pin(copy_dir_recursive(&entry.path(), &target)).await?;
        } else {
            tokio::fs::copy(entry.path(), &target).await?;
        }
    }
    Ok(())
}

/// Execute a capability request
async fn execute_capability(capability: &str, params: &serde_json::Value) -> Result<String> {
    match capability {
        "fs_read" => {
            let path = params
                .get("path")
                .and_then(|v| v.as_str())
                .context("Missing path parameter")?;
            let path = expand_tilde(path);

            let content = tokio::fs::read_to_string(&path)
                .await
                .context("Failed to read file")?;

            Ok(content)
        }
        "fs_write" => {
            let path = params
                .get("path")
                .and_then(|v| v.as_str())
                .context("Missing path parameter")?;
            let content = params
                .get("content")
                .and_then(|v| v.as_str())
                .context("Missing content parameter")?;

            let path = expand_tilde(path);

            // Create parent directories if they don't exist
            if let Some(parent) = path.parent() {
                tokio::fs::create_dir_all(parent)
                    .await
                    .context("Failed to create parent directories")?;
            }

            tokio::fs::write(&path, content)
                .await
                .context("Failed to write file")?;

            Ok("OK".to_string())
        }
        "fs_edit" => {
            let path = params
                .get("path")
                .and_then(|v| v.as_str())
                .context("Missing path parameter")?;
            let old_string = params
                .get("old_string")
                .and_then(|v| v.as_str())
                .context("Missing old_string parameter")?;
            let new_string = params
                .get("new_string")
                .and_then(|v| v.as_str())
                .context("Missing new_string parameter")?;
            let replace_all = params
                .get("replace_all")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            let path = expand_tilde(path);
            let content = tokio::fs::read_to_string(&path)
                .await
                .context("Failed to read file")?;

            // Exact match
            let exact_count = content.matches(old_string).count();

            if exact_count == 1 || (exact_count > 0 && replace_all) {
                let result = if replace_all {
                    content.replace(old_string, new_string)
                } else {
                    content.replacen(old_string, new_string, 1)
                };
                tokio::fs::write(&path, &result)
                    .await
                    .context("Failed to write file")?;
                return Ok(format!(
                    "Edited {}. {} occurrence(s) replaced.",
                    path.display(),
                    if replace_all { exact_count } else { 1 }
                ));
            }

            if exact_count > 1 && !replace_all {
                bail!(
                    "old_string matches {} locations. Use replace_all or provide more context to make it unique.",
                    exact_count
                );
            }

            // Whitespace-normalized fallback
            let normalize = |s: &str| -> String {
                s.lines()
                    .map(|line| line.split_whitespace().collect::<Vec<_>>().join(" "))
                    .collect::<Vec<_>>()
                    .join("\n")
            };

            let norm_old = normalize(old_string);
            let norm_content = normalize(&content);
            let norm_count = norm_content.matches(&norm_old).count();

            if norm_count == 1 {
                // Find the position in normalized content, then map back to original
                let norm_pos = norm_content.find(&norm_old).unwrap();

                // Map normalized position to original position by walking both strings
                let mut orig_idx = 0;
                let mut norm_idx = 0;
                let content_bytes = content.as_bytes();
                let norm_bytes = norm_content.as_bytes();

                // Advance to the start position in both strings
                while norm_idx < norm_pos {
                    // Skip extra whitespace in original that was collapsed
                    if content_bytes[orig_idx] == b'\n' && norm_bytes[norm_idx] == b'\n' {
                        orig_idx += 1;
                        norm_idx += 1;
                    } else if content_bytes[orig_idx].is_ascii_whitespace()
                        && norm_bytes[norm_idx] == b' '
                    {
                        // Consume all whitespace in original for one space in normalized
                        norm_idx += 1;
                        while orig_idx < content.len()
                            && content_bytes[orig_idx].is_ascii_whitespace()
                            && content_bytes[orig_idx] != b'\n'
                        {
                            orig_idx += 1;
                        }
                    } else {
                        orig_idx += 1;
                        norm_idx += 1;
                    }
                }
                let orig_start = orig_idx;

                // Now advance through the matched region
                let norm_end = norm_pos + norm_old.len();
                while norm_idx < norm_end {
                    if content_bytes[orig_idx] == b'\n' && norm_bytes[norm_idx] == b'\n' {
                        orig_idx += 1;
                        norm_idx += 1;
                    } else if content_bytes[orig_idx].is_ascii_whitespace()
                        && norm_bytes[norm_idx] == b' '
                    {
                        norm_idx += 1;
                        while orig_idx < content.len()
                            && content_bytes[orig_idx].is_ascii_whitespace()
                            && content_bytes[orig_idx] != b'\n'
                        {
                            orig_idx += 1;
                        }
                    } else {
                        orig_idx += 1;
                        norm_idx += 1;
                    }
                }
                let orig_end = orig_idx;

                let mut result = String::with_capacity(content.len());
                result.push_str(&content[..orig_start]);
                result.push_str(new_string);
                result.push_str(&content[orig_end..]);

                tokio::fs::write(&path, &result)
                    .await
                    .context("Failed to write file")?;
                return Ok(format!(
                    "Edited {} (matched with whitespace normalization).",
                    path.display()
                ));
            }

            // No match — find closest match for error hint
            let first_line = old_string
                .lines()
                .find(|l| !l.trim().is_empty())
                .unwrap_or(old_string);
            let old_line_count = old_string.lines().count();

            let content_lines: Vec<&str> = content.lines().collect();
            for (i, line) in content_lines.iter().enumerate() {
                if line.contains(first_line.trim()) {
                    let start = i;
                    let end = (i + old_line_count).min(content_lines.len());
                    let context_snippet = content_lines[start..end].join("\n");
                    bail!(
                        "old_string not found. Closest match near line {}:\n{}",
                        i + 1,
                        context_snippet
                    );
                }
            }

            bail!("old_string not found in {}", path.display());
        }
        "fs_list" => {
            let path = params
                .get("path")
                .and_then(|v| v.as_str())
                .context("Missing path parameter")?;
            let path = expand_tilde(path);

            let mut entries = tokio::fs::read_dir(&path)
                .await
                .context("Failed to read directory")?;

            let mut items = Vec::new();
            while let Some(entry) = entries.next_entry().await? {
                let metadata = entry.metadata().await?;
                items.push(serde_json::json!({
                    "name": entry.file_name().to_string_lossy(),
                    "is_dir": metadata.is_dir(),
                    "size": metadata.len(),
                }));
            }

            Ok(serde_json::to_string(&items)?)
        }
        "fs_trash" => {
            let paths = get_paths(params)?;
            for path in &paths {
                trash::delete(path)
                    .with_context(|| format!("Failed to trash {}", path.display()))?;
            }
            Ok(serde_json::to_string(&serde_json::json!({
                "trashed": paths.iter().map(|p| p.to_string_lossy()).collect::<Vec<_>>()
            }))?)
        }
        "fs_move" => {
            let destination = params
                .get("destination")
                .and_then(|v| v.as_str())
                .context("Missing destination parameter")?;
            let destination = expand_tilde(destination);
            let paths = get_paths(params)?;

            // If multiple sources, destination must be a directory
            if paths.len() > 1 {
                tokio::fs::create_dir_all(&destination)
                    .await
                    .context("Failed to create destination directory")?;
            }

            let mut moved = Vec::new();
            for source in &paths {
                let target = if destination.is_dir() || paths.len() > 1 {
                    let name = source.file_name().context("Source has no filename")?;
                    destination.join(name)
                } else {
                    // Single source, destination is the full target path
                    if let Some(parent) = destination.parent() {
                        tokio::fs::create_dir_all(parent)
                            .await
                            .context("Failed to create parent directories")?;
                    }
                    destination.clone()
                };
                tokio::fs::rename(source, &target).await.with_context(|| {
                    format!(
                        "Failed to move {} to {}",
                        source.display(),
                        target.display()
                    )
                })?;
                moved.push(serde_json::json!({
                    "from": source.to_string_lossy(),
                    "to": target.to_string_lossy(),
                }));
            }
            Ok(serde_json::to_string(&moved)?)
        }
        "fs_rename" => {
            let items = params
                .get("items")
                .and_then(|v| v.as_array())
                .context("Missing items parameter (expected array of {from, to})")?;

            let mut renamed = Vec::new();
            for item in items {
                let from = item
                    .get("from")
                    .and_then(|v| v.as_str())
                    .context("Missing 'from' in rename item")?;
                let to = item
                    .get("to")
                    .and_then(|v| v.as_str())
                    .context("Missing 'to' in rename item")?;
                let from = expand_tilde(from);
                let to = expand_tilde(to);

                if let Some(parent) = to.parent() {
                    tokio::fs::create_dir_all(parent)
                        .await
                        .context("Failed to create parent directories")?;
                }

                tokio::fs::rename(&from, &to).await.with_context(|| {
                    format!("Failed to rename {} to {}", from.display(), to.display())
                })?;
                renamed.push(serde_json::json!({
                    "from": from.to_string_lossy(),
                    "to": to.to_string_lossy(),
                }));
            }
            Ok(serde_json::to_string(&renamed)?)
        }
        "fs_search" => {
            let path = params.get("path").and_then(|v| v.as_str()).unwrap_or(".");
            let path = expand_tilde(path);
            let pattern = params
                .get("pattern")
                .and_then(|v| v.as_str())
                .context("Missing pattern parameter")?;
            let max_results: usize = params
                .get("max_results")
                .and_then(|v| v.as_u64())
                .unwrap_or(100) as usize;

            let glob_pattern = glob::Pattern::new(pattern)
                .with_context(|| format!("Invalid glob pattern: {}", pattern))?;

            let mut results = Vec::new();
            let walker = ignore::WalkBuilder::new(&path).hidden(false).build();

            for entry in walker {
                if results.len() >= max_results {
                    break;
                }
                let entry = match entry {
                    Ok(e) => e,
                    Err(_) => continue,
                };
                let name = entry.file_name().to_string_lossy();
                if glob_pattern.matches(&name) {
                    let metadata = entry.metadata();
                    results.push(serde_json::json!({
                        "path": entry.path().to_string_lossy(),
                        "is_dir": metadata.as_ref().map(|m| m.is_dir()).unwrap_or(false),
                        "size": metadata.as_ref().map(|m| m.len()).unwrap_or(0),
                    }));
                }
            }

            Ok(serde_json::to_string(&results)?)
        }
        "fs_grep" => {
            let pattern = params
                .get("pattern")
                .and_then(|v| v.as_str())
                .context("Missing pattern parameter")?;
            let path = params.get("path").and_then(|v| v.as_str()).unwrap_or(".");
            let path = expand_tilde(path);
            let max_results: usize = params
                .get("max_results")
                .and_then(|v| v.as_u64())
                .unwrap_or(200) as usize;
            let glob_filter = params.get("glob").and_then(|v| v.as_str());

            // Use rg if available, fall back to grep
            let mut cmd = if which_exists("rg") {
                let mut c = tokio::process::Command::new("rg");
                c.args(["--no-heading", "--line-number", "--color", "never"]);
                c.arg("--max-count").arg(max_results.to_string());
                if let Some(g) = glob_filter {
                    c.arg("--glob").arg(g);
                }
                c.arg(pattern).arg(&path);
                c
            } else {
                let mut c = tokio::process::Command::new("grep");
                c.args(["-rn", "--color=never"]);
                if let Some(g) = glob_filter {
                    c.arg("--include").arg(g);
                }
                c.arg(pattern).arg(&path);
                c
            };

            let output = cmd.output().await.context("Failed to run grep")?;
            let stdout = String::from_utf8_lossy(&output.stdout);

            let matches: Vec<&str> = stdout.lines().take(max_results).collect();
            Ok(serde_json::to_string(&serde_json::json!({
                "matches": matches,
                "count": matches.len(),
                "truncated": stdout.lines().count() > max_results,
            }))?)
        }
        "fs_mkdir" => {
            let paths = get_paths(params)?;
            for path in &paths {
                tokio::fs::create_dir_all(path)
                    .await
                    .with_context(|| format!("Failed to create directory {}", path.display()))?;
            }
            Ok(serde_json::to_string(&serde_json::json!({
                "created": paths.iter().map(|p| p.to_string_lossy()).collect::<Vec<_>>()
            }))?)
        }
        "fs_copy" => {
            let destination = params
                .get("destination")
                .and_then(|v| v.as_str())
                .context("Missing destination parameter")?;
            let destination = expand_tilde(destination);
            let paths = get_paths(params)?;

            if paths.len() > 1 {
                tokio::fs::create_dir_all(&destination)
                    .await
                    .context("Failed to create destination directory")?;
            }

            let mut copied = Vec::new();
            for source in &paths {
                let target = if destination.is_dir() || paths.len() > 1 {
                    let name = source.file_name().context("Source has no filename")?;
                    destination.join(name)
                } else {
                    if let Some(parent) = destination.parent() {
                        tokio::fs::create_dir_all(parent)
                            .await
                            .context("Failed to create parent directories")?;
                    }
                    destination.clone()
                };

                let metadata = tokio::fs::metadata(source)
                    .await
                    .with_context(|| format!("Failed to read {}", source.display()))?;

                if metadata.is_dir() {
                    copy_dir_recursive(source, &target).await.with_context(|| {
                        format!(
                            "Failed to copy directory {} to {}",
                            source.display(),
                            target.display()
                        )
                    })?;
                } else {
                    tokio::fs::copy(source, &target).await.with_context(|| {
                        format!(
                            "Failed to copy {} to {}",
                            source.display(),
                            target.display()
                        )
                    })?;
                }

                copied.push(serde_json::json!({
                    "from": source.to_string_lossy(),
                    "to": target.to_string_lossy(),
                }));
            }
            Ok(serde_json::to_string(&copied)?)
        }
        "fs_open" => {
            let path = params
                .get("path")
                .and_then(|v| v.as_str())
                .context("Missing path parameter")?;
            let path = expand_tilde(path);
            let app = params.get("app").and_then(|v| v.as_str());

            match app {
                Some(app_name) => {
                    #[cfg(target_os = "macos")]
                    {
                        let status = tokio::process::Command::new("open")
                            .arg("-a")
                            .arg(app_name)
                            .arg(&path)
                            .status()
                            .await
                            .context("Failed to run open")?;
                        if !status.success() {
                            anyhow::bail!("open -a '{}' failed", app_name);
                        }
                    }
                    #[cfg(target_os = "windows")]
                    {
                        let status = tokio::process::Command::new("cmd")
                            .args(["/C", "start", "", app_name, &path.to_string_lossy()])
                            .status()
                            .await
                            .context("Failed to run start")?;
                        if !status.success() {
                            anyhow::bail!("start with '{}' failed", app_name);
                        }
                    }
                    #[cfg(target_os = "linux")]
                    {
                        let status = tokio::process::Command::new(app_name)
                            .arg(&path)
                            .status()
                            .await
                            .with_context(|| format!("Failed to run '{}'", app_name))?;
                        if !status.success() {
                            anyhow::bail!("'{}' exited with error", app_name);
                        }
                    }
                }
                None => {
                    open::that(&path)
                        .with_context(|| format!("Failed to open {}", path.display()))?;
                }
            }

            Ok(serde_json::json!({"opened": path.to_string_lossy()}).to_string())
        }
        "fs_reveal" => {
            let path = params
                .get("path")
                .and_then(|v| v.as_str())
                .context("Missing path parameter")?;
            let path = expand_tilde(path);

            #[cfg(target_os = "macos")]
            {
                let status = tokio::process::Command::new("open")
                    .arg("-R")
                    .arg(&path)
                    .status()
                    .await
                    .context("Failed to reveal in Finder")?;
                if !status.success() {
                    anyhow::bail!("open -R failed");
                }
            }
            #[cfg(target_os = "windows")]
            {
                let status = tokio::process::Command::new("explorer")
                    .arg("/select,")
                    .arg(&path)
                    .status()
                    .await
                    .context("Failed to reveal in Explorer")?;
                if !status.success() {
                    anyhow::bail!("explorer /select failed");
                }
            }
            #[cfg(target_os = "linux")]
            {
                // Try dbus (works on most modern desktops), fall back to xdg-open on parent
                let dbus_result = tokio::process::Command::new("dbus-send")
                    .args([
                        "--dest=org.freedesktop.FileManager1",
                        "--type=method_call",
                        "/org/freedesktop/FileManager1",
                        "org.freedesktop.FileManager1.ShowItems",
                    ])
                    .arg(format!("array:string:file://{}", path.display()))
                    .arg("string:")
                    .status()
                    .await;

                match dbus_result {
                    Ok(s) if s.success() => {}
                    _ => {
                        // Fall back to opening the parent directory
                        let parent = path.parent().unwrap_or(&path);
                        open::that(parent)
                            .with_context(|| format!("Failed to open {}", parent.display()))?;
                    }
                }
            }

            Ok(serde_json::json!({"revealed": path.to_string_lossy()}).to_string())
        }
        "shell" => {
            let command = params
                .get("command")
                .and_then(|v| v.as_str())
                .context("Missing command parameter")?;
            let cwd = params.get("cwd").and_then(|v| v.as_str());

            let mut cmd = if cfg!(windows) {
                let mut c = tokio::process::Command::new("cmd");
                c.arg("/C").arg(command);
                c
            } else {
                let mut c = tokio::process::Command::new("sh");
                c.arg("-c").arg(command);
                c
            };

            if let Some(cwd) = cwd {
                cmd.current_dir(expand_tilde(cwd));
            }

            let output = cmd.output().await.context("Failed to execute command")?;

            let result = serde_json::json!({
                "stdout": String::from_utf8_lossy(&output.stdout),
                "stderr": String::from_utf8_lossy(&output.stderr),
                "exit_code": output.status.code(),
            });

            Ok(serde_json::to_string(&result)?)
        }
        "md_file_to_pdf" => {
            let path = params
                .get("path")
                .and_then(|v| v.as_str())
                .context("Missing path parameter")?;
            let output = params
                .get("output")
                .and_then(|v| v.as_str())
                .context("Missing output parameter")?;

            let path = expand_tilde(path);
            let output = expand_tilde(output);

            let content = tokio::fs::read_to_string(&path)
                .await
                .context("Failed to read markdown file")?;

            let sans = params
                .get("sans")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let pdf_bytes = convert_md_to_pdf(&content, sans)?;

            if let Some(parent) = output.parent() {
                tokio::fs::create_dir_all(parent)
                    .await
                    .context("Failed to create parent directories")?;
            }

            tokio::fs::write(&output, pdf_bytes)
                .await
                .context("Failed to write PDF")?;

            Ok(format!("PDF written to {}", output.display()))
        }
        "md_to_pdf" => {
            let markdown = params
                .get("markdown")
                .and_then(|v| v.as_str())
                .context("Missing markdown parameter")?;
            let output = params
                .get("output")
                .and_then(|v| v.as_str())
                .context("Missing output parameter")?;

            let output = expand_tilde(output);
            let sans = params
                .get("sans")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let pdf_bytes = convert_md_to_pdf(markdown, sans)?;

            if let Some(parent) = output.parent() {
                tokio::fs::create_dir_all(parent)
                    .await
                    .context("Failed to create parent directories")?;
            }

            tokio::fs::write(&output, pdf_bytes)
                .await
                .context("Failed to write PDF")?;

            Ok(format!("PDF written to {}", output.display()))
        }
        "artifact_to_pdf" => {
            let content = params
                .get("content")
                .and_then(|v| v.as_str())
                .context("Missing content parameter")?;
            let output = params
                .get("output")
                .and_then(|v| v.as_str())
                .context("Missing output parameter")?;

            let output = expand_tilde(output);
            let sans = params
                .get("sans")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let pdf_bytes = convert_md_to_pdf(content, sans)?;

            if let Some(parent) = output.parent() {
                tokio::fs::create_dir_all(parent)
                    .await
                    .context("Failed to create parent directories")?;
            }

            tokio::fs::write(&output, pdf_bytes)
                .await
                .context("Failed to write PDF")?;

            Ok(format!("PDF written to {}", output.display()))
        }
        _ => bail!("Unknown capability: {}", capability),
    }
}

fn convert_md_to_pdf(markdown: &str, sans: bool) -> Result<Vec<u8>> {
    if sans {
        let mut config = pdf_core::Config::compiled_default();
        config.font.sans = true;
        pdf_core::markdown_to_pdf_with_config(markdown, &config)
            .map_err(|e| anyhow::anyhow!("PDF conversion failed: {}", e))
    } else {
        pdf_core::markdown_to_pdf(markdown)
            .map_err(|e| anyhow::anyhow!("PDF conversion failed: {}", e))
    }
}
