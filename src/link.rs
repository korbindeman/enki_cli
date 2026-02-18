//! Link command - connect this machine to Enki

use anyhow::{bail, Context, Result};
use colored::Colorize;
use futures_util::StreamExt;
use serde::Deserialize;
use std::path::PathBuf;
use std::sync::Arc;

use crate::claude_code::ClaudeCodeManager;
use crate::config;

/// Lock file guard - ensures only one `enki link` per mode (dev/prod).
/// Dev and prod links use separate lock files so they can run simultaneously.
/// Removes the lock file when dropped.
struct LinkLock {
    path: PathBuf,
}

impl LinkLock {
    fn acquire(dev: bool) -> Result<Self> {
        let lock_name = if dev { "link.dev.lock" } else { "link.lock" };
        let path = config::config_dir()?.join(lock_name);

        if path.exists() {
            let contents = std::fs::read_to_string(&path).unwrap_or_default();
            if let Ok(pid) = contents.trim().parse::<u32>() {
                if process_exists(pid) {
                    let mode = if dev { "dev" } else { "prod" };
                    bail!(
                        "Another enki link ({}) is already running (PID {}). Only one link per mode is allowed.",
                        mode,
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

/// A capability this machine can provide
#[derive(Debug, Clone, serde::Serialize)]
pub struct Capability {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paths: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<Tool>>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Tool {
    pub name: String,
    pub version: String,
}

/// HTTP client for posting results back to the server.
#[derive(Clone)]
pub struct LinkClient {
    client: reqwest::Client,
    base_url: String,
    token: String,
}

impl LinkClient {
    fn new(token: &str) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: config::server_url(),
            token: token.to_string(),
        }
    }

    /// POST JSON to a link endpoint. Returns Ok(()) on success.
    pub async fn post(&self, path: &str, body: &serde_json::Value) -> Result<()> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self
            .client
            .post(&url)
            .bearer_auth(&self.token)
            .json(body)
            .send()
            .await
            .context("POST failed")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            bail!("POST {} failed ({}): {}", path, status, text);
        }

        Ok(())
    }

    async fn announce(&self, connection_id: &str, capabilities: &[Capability]) -> Result<()> {
        self.post(
            "/api/link/announce",
            &serde_json::json!({
                "connection_id": connection_id,
                "capabilities": capabilities,
            }),
        )
        .await
    }

    async fn send_result(
        &self,
        request_id: &str,
        status: &str,
        data: Option<String>,
        error: Option<String>,
    ) -> Result<()> {
        self.post(
            "/api/link/result",
            &serde_json::json!({
                "request_id": request_id,
                "status": status,
                "data": data,
                "error": error,
            }),
        )
        .await
    }
}

/// SSE event data types from the server

#[derive(Debug, Deserialize)]
struct ConnectedEvent {
    connection_id: String,
}

#[derive(Debug, Deserialize)]
struct ExecuteEvent {
    request_id: String,
    capability: String,
    params: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct CcStartEvent {
    request_id: String,
    cwd: String,
    prompt: String,
}

/// Try to get dev credentials from the server (only works when server is in dev mode)
async fn try_dev_credentials() -> Result<config::Credentials> {
    let url = format!("{}/api/auth/dev", config::server_url());
    let resp = reqwest::get(&url).await?;

    if !resp.status().is_success() {
        anyhow::bail!("Dev mode not available");
    }

    let body: serde_json::Value = resp.json().await?;
    let token = body["token"].as_str().context("Missing token")?.to_string();
    let user_id = body["user"]["id"]
        .as_str()
        .context("Missing user id")?
        .to_string();
    let email = body["user"]["email"]
        .as_str()
        .context("Missing email")?
        .to_string();

    Ok(config::Credentials {
        refresh_token: token,
        user_id,
        email,
    })
}

/// List detected capabilities and exit
pub fn list_capabilities(filter: Option<String>) -> Result<()> {
    let capabilities = detect_capabilities(filter)?;
    println!(
        "{} {} capabilities detected:\n",
        "●".green(),
        capabilities.len().to_string().bold()
    );
    for cap in &capabilities {
        let detail = match &cap.tools {
            Some(tools) => {
                let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
                format!(" ({})", names.join(", ").dimmed())
            }
            None => match &cap.paths {
                Some(paths) => format!(" ({})", paths.join(", ").dimmed()),
                None => String::new(),
            },
        };
        println!("  {} {}{}", "·".dimmed(), cap.name.cyan(), detail);
    }
    Ok(())
}

/// Format a brief description of a capability execution from its params
fn execution_summary(capability: &str, params: &serde_json::Value) -> String {
    match capability {
        "shell" => {
            if let Some(cmd) = params.get("command").and_then(|v| v.as_str()) {
                let truncated: String = cmd.chars().take(60).collect();
                if cmd.len() > 60 {
                    format!("{truncated}...")
                } else {
                    truncated
                }
            } else {
                String::new()
            }
        }
        cap if cap.starts_with("fs_") => {
            if let Some(path) = params.get("path").and_then(|v| v.as_str()) {
                path.to_string()
            } else {
                String::new()
            }
        }
        _ => String::new(),
    }
}

/// Start the link connection with automatic reconnection
pub async fn start(capabilities_filter: Option<String>, persistent: bool) -> Result<()> {
    // Try dev auth first (server decides if dev mode is active)
    let (creds, is_dev) = match try_dev_credentials().await {
        Ok(creds) => {
            println!("Using dev credentials");
            (creds, true)
        }
        Err(_) => {
            let creds = match config::load_credentials()? {
                Some(creds) => creds,
                None => {
                    println!("Not authenticated. Starting login...\n");
                    crate::auth::login_flow().await?
                }
            };
            (creds, false)
        }
    };

    // Dev and prod use separate lock files so both can run simultaneously
    let _lock = LinkLock::acquire(is_dev)?;

    println!("{} Connecting as {}...", "●".yellow(), creds.email.bold());

    // Detect capabilities
    let capabilities = detect_capabilities(capabilities_filter)?;

    println!(
        "{} Advertising {} capabilities",
        "●".green(),
        capabilities.len().to_string().bold()
    );

    // Prevent system sleep if --persistent is set (held until dropped)
    let _awake_guard = if persistent {
        let guard = keepawake::Builder::default()
            .reason("Enki link active")
            .app_name("enki")
            .create()
            .context("Failed to inhibit system sleep")?;
        println!("{} Persistent mode: system sleep inhibited", "●".cyan());
        Some(guard)
    } else {
        None
    };

    let mut backoff_secs = 1u64;
    const MAX_BACKOFF_SECS: u64 = 30;

    loop {
        // In dev mode, always use the dev credentials.
        // In prod mode, reload from disk (may have been rotated).
        let current_creds = if is_dev {
            creds.clone()
        } else {
            config::load_credentials()?.unwrap_or_else(|| creds.clone())
        };

        let was_connected = run_connection(&current_creds, &capabilities).await;

        match was_connected {
            Ok(true) => {
                // Was connected before disconnect — reset backoff
                eprintln!("{} Disconnected", "●".red());
                backoff_secs = 1;
            }
            Ok(false) => {
                eprintln!("{} Connection failed", "●".red());
            }
            Err(e) => {
                eprintln!("{} Connection error: {}", "●".red(), e);
            }
        }

        println!("{} Reconnecting in {}s...", "●".yellow(), backoff_secs);
        tokio::time::sleep(tokio::time::Duration::from_secs(backoff_secs)).await;
        backoff_secs = (backoff_secs * 2).min(MAX_BACKOFF_SECS);
    }
}

/// A parsed SSE event
struct SseEvent {
    event: String,
    data: String,
}

/// Run a single SSE connection. Returns Ok(true) if was connected before disconnect.
async fn run_connection(creds: &config::Credentials, capabilities: &[Capability]) -> Result<bool> {
    let sse_url = format!(
        "{}/api/link/stream?token={}",
        config::server_url(),
        urlencoding::encode(&creds.refresh_token)
    );

    let link_client = Arc::new(LinkClient::new(&creds.refresh_token));

    let resp = link_client
        .client
        .get(&sse_url)
        .header("Accept", "text/event-stream")
        .send()
        .await
        .context("Failed to connect to SSE endpoint")?;

    if !resp.status().is_success() {
        bail!("SSE connection failed with status {}", resp.status());
    }

    let mut was_connected = false;

    // Stream the response body line by line for SSE parsing
    let mut byte_stream = resp.bytes_stream();
    let mut buffer = String::new();
    let mut current_event = String::new();
    let mut current_data: Vec<String> = Vec::new();

    // Wrap in LocalSet since ACP futures are !Send
    let local = tokio::task::LocalSet::new();
    let result: Result<bool> = local
        .run_until(async {
            let mut cc_manager: Option<ClaudeCodeManager> = None;

            while let Some(chunk_result) = byte_stream.next().await {
                let chunk = match chunk_result {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("{} Stream error: {}", "✗".red(), e);
                        break;
                    }
                };
                buffer.push_str(&String::from_utf8_lossy(&chunk));

                // Process complete lines from the buffer
                while let Some(newline_pos) = buffer.find('\n') {
                    let line = buffer[..newline_pos].trim_end_matches('\r').to_string();
                    buffer = buffer[newline_pos + 1..].to_string();

                    if line.is_empty() {
                        // Empty line = event boundary
                        if !current_data.is_empty() {
                            let event = SseEvent {
                                event: if current_event.is_empty() {
                                    "message".to_string()
                                } else {
                                    std::mem::take(&mut current_event)
                                },
                                data: current_data.join("\n"),
                            };
                            current_data.clear();

                            if let Err(e) = handle_sse_event(
                                &event,
                                &link_client,
                                capabilities,
                                &mut cc_manager,
                                &mut was_connected,
                            )
                            .await
                            {
                                eprintln!("  {} Event error: {}", "✗".red(), e);
                            }
                        }
                    } else if let Some(value) = line.strip_prefix("event:") {
                        current_event = value.trim().to_string();
                    } else if let Some(value) = line.strip_prefix("data:") {
                        current_data.push(value.trim_start().to_string());
                    } else if line.starts_with(':') {
                        // Comment (keepalive), ignore
                    }
                    // id: lines ignored for now
                }
            }

            Ok(was_connected)
        })
        .await;

    result
}

/// Handle a single parsed SSE event
async fn handle_sse_event(
    event: &SseEvent,
    link_client: &Arc<LinkClient>,
    capabilities: &[Capability],
    cc_manager: &mut Option<ClaudeCodeManager>,
    was_connected: &mut bool,
) -> Result<()> {
    match event.event.as_str() {
        "connected" => {
            let data: ConnectedEvent =
                serde_json::from_str(&event.data).context("Bad connected event")?;

            *was_connected = true;
            println!("{} Connected", "●".green());

            link_client
                .announce(&data.connection_id, capabilities)
                .await?;

            *cc_manager = Some(ClaudeCodeManager::new(link_client.clone()));

            println!("{} Link active. Press Ctrl+C to disconnect.\n", "●".green());
        }
        "execute" => {
            let data: ExecuteEvent =
                serde_json::from_str(&event.data).context("Bad execute event")?;

            let summary = execution_summary(&data.capability, &data.params);
            if summary.is_empty() {
                println!("  {} {}", "▸".cyan(), data.capability.bold());
            } else {
                println!(
                    "  {} {} {}",
                    "▸".cyan(),
                    data.capability.bold(),
                    summary.dimmed()
                );
            }

            let client = link_client.clone();
            let request_id = data.request_id;
            let capability = data.capability;
            let params = data.params;

            tokio::task::spawn_local(async move {
                let result = execute_capability(&capability, &params).await;

                let post_result = match result {
                    Ok(result_data) => {
                        client
                            .send_result(&request_id, "success", Some(result_data), None)
                            .await
                    }
                    Err(e) => {
                        client
                            .send_result(&request_id, "error", None, Some(e.to_string()))
                            .await
                    }
                };

                if let Err(e) = post_result {
                    eprintln!("  {} Failed to post result: {}", "✗".red(), e);
                }
            });
        }
        "cc_start" => {
            let data: CcStartEvent =
                serde_json::from_str(&event.data).context("Bad cc_start event")?;

            let truncated: String = data.prompt.chars().take(60).collect();
            println!(
                "  {} {} {}",
                "▸".cyan(),
                "claude_code".bold(),
                truncated.dimmed()
            );

            if let Some(ref mgr) = cc_manager {
                if let Err(e) = mgr
                    .start_session(data.request_id, data.cwd, data.prompt)
                    .await
                {
                    eprintln!("  {} {}", "✗".red(), e);
                }
            }
        }
        "cc_message" => {
            let data: serde_json::Value =
                serde_json::from_str(&event.data).context("Bad cc_message event")?;

            if let Some(ref mgr) = cc_manager {
                handle_cc_message(mgr, &data).await;
            }
        }
        _ => {}
    }

    Ok(())
}

/// Handle incoming Claude Code messages from the server
async fn handle_cc_message(mgr: &ClaudeCodeManager, data: &serde_json::Value) {
    let msg_type = data.get("type").and_then(|v| v.as_str()).unwrap_or("");

    match msg_type {
        "cc_prompt" => {
            let session_id = data
                .get("session_id")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let prompt = data.get("prompt").and_then(|v| v.as_str()).unwrap_or("");

            println!(
                "  {} {} {}",
                "▸".cyan(),
                "claude_code".bold(),
                format!("follow-up {}", &session_id[..8.min(session_id.len())]).dimmed()
            );

            if let Err(e) = mgr.send_prompt(session_id, prompt.to_string()).await {
                eprintln!("  {} {}", "✗".red(), e);
            }
        }
        "cc_permission_response" => {
            let permission_id = data
                .get("permission_id")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let approved = data
                .get("approved")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            mgr.handle_permission_response(permission_id, approved);
        }
        "cc_cancel" => {
            let session_id = data
                .get("session_id")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            println!(
                "  {} {} {}",
                "▸".cyan(),
                "claude_code".bold(),
                "cancel".dimmed()
            );

            if let Err(e) = mgr.cancel_session(session_id).await {
                eprintln!("  {} {}", "✗".red(), e);
            }
        }
        "cc_interrupt" => {
            let session_id = data
                .get("session_id")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            println!(
                "  {} {} {}",
                "▸".cyan(),
                "claude_code".bold(),
                "interrupt".dimmed()
            );

            if let Err(e) = mgr.interrupt_session(session_id).await {
                eprintln!("  {} {}", "✗".red(), e);
            }
        }
        _ => {
            // Unknown cc message type
        }
    }
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
        "fs_read" => cap_fs_read(params).await,
        "fs_write" => cap_fs_write(params).await,
        "fs_edit" => cap_fs_edit(params).await,
        "fs_list" => cap_fs_list(params).await,
        "fs_trash" => cap_fs_trash(params).await,
        "fs_move" => cap_fs_move(params).await,
        "fs_rename" => cap_fs_rename(params).await,
        "fs_search" => cap_fs_search(params).await,
        "fs_grep" => cap_fs_grep(params).await,
        "fs_mkdir" => cap_fs_mkdir(params).await,
        "fs_copy" => cap_fs_copy(params).await,
        "fs_open" => cap_fs_open(params).await,
        "fs_reveal" => cap_fs_reveal(params).await,
        "shell" => cap_shell(params).await,
        "md_file_to_pdf" => cap_md_file_to_pdf(params).await,
        "md_to_pdf" => cap_md_to_pdf(params).await,
        "artifact_to_pdf" => cap_artifact_to_pdf(params).await,
        _ => bail!("Unknown capability: {}", capability),
    }
}

// ============================================================================
// File system capabilities
// ============================================================================

async fn cap_fs_read(params: &serde_json::Value) -> Result<String> {
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

async fn cap_fs_write(params: &serde_json::Value) -> Result<String> {
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

async fn cap_fs_edit(params: &serde_json::Value) -> Result<String> {
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
        let norm_pos = norm_content.find(&norm_old).unwrap_or(0);

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
            } else if content_bytes[orig_idx].is_ascii_whitespace() && norm_bytes[norm_idx] == b' '
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
            } else if content_bytes[orig_idx].is_ascii_whitespace() && norm_bytes[norm_idx] == b' '
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

async fn cap_fs_list(params: &serde_json::Value) -> Result<String> {
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

async fn cap_fs_trash(params: &serde_json::Value) -> Result<String> {
    let paths = get_paths(params)?;
    for path in &paths {
        trash::delete(path).with_context(|| format!("Failed to trash {}", path.display()))?;
    }
    Ok(serde_json::to_string(&serde_json::json!({
        "trashed": paths.iter().map(|p| p.to_string_lossy()).collect::<Vec<_>>()
    }))?)
}

async fn cap_fs_move(params: &serde_json::Value) -> Result<String> {
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

async fn cap_fs_rename(params: &serde_json::Value) -> Result<String> {
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

        tokio::fs::rename(&from, &to)
            .await
            .with_context(|| format!("Failed to rename {} to {}", from.display(), to.display()))?;
        renamed.push(serde_json::json!({
            "from": from.to_string_lossy(),
            "to": to.to_string_lossy(),
        }));
    }
    Ok(serde_json::to_string(&renamed)?)
}

async fn cap_fs_search(params: &serde_json::Value) -> Result<String> {
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

async fn cap_fs_grep(params: &serde_json::Value) -> Result<String> {
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

async fn cap_fs_mkdir(params: &serde_json::Value) -> Result<String> {
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

async fn cap_fs_copy(params: &serde_json::Value) -> Result<String> {
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

async fn cap_fs_open(params: &serde_json::Value) -> Result<String> {
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
            open::that(&path).with_context(|| format!("Failed to open {}", path.display()))?;
        }
    }

    Ok(serde_json::json!({"opened": path.to_string_lossy()}).to_string())
}

async fn cap_fs_reveal(params: &serde_json::Value) -> Result<String> {
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

// ============================================================================
// Shell capability
// ============================================================================

async fn cap_shell(params: &serde_json::Value) -> Result<String> {
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

// ============================================================================
// PDF conversion capabilities
// ============================================================================

async fn cap_md_file_to_pdf(params: &serde_json::Value) -> Result<String> {
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

    write_pdf(&output, pdf_bytes).await
}

async fn cap_md_to_pdf(params: &serde_json::Value) -> Result<String> {
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

    write_pdf(&output, pdf_bytes).await
}

async fn cap_artifact_to_pdf(params: &serde_json::Value) -> Result<String> {
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

    write_pdf(&output, pdf_bytes).await
}

async fn write_pdf(output: &std::path::Path, pdf_bytes: Vec<u8>) -> Result<String> {
    if let Some(parent) = output.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .context("Failed to create parent directories")?;
    }

    tokio::fs::write(output, pdf_bytes)
        .await
        .context("Failed to write PDF")?;

    Ok(format!("PDF written to {}", output.display()))
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
