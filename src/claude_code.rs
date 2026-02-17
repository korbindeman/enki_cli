//! Claude Code ACP integration.
//!
//! Manages ACP sessions with Claude Code via the `@zed-industries/claude-code-acp` adapter.
//! Each session is a subprocess with piped stdio, driven by the `agent-client-protocol` crate.

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::OnceLock;

use agent_client_protocol as acp;
use anyhow::{Context, Result};
use tokio::sync::{mpsc, oneshot};
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};

/// Supported package managers for installing/running the ACP adapter.
#[derive(Debug, Clone, Copy)]
enum PackageManager {
    Bun,
    Npm,
}

impl PackageManager {
    /// The command used to install packages (e.g. `bun`, `npm`).
    fn install_cmd(&self) -> &'static str {
        match self {
            Self::Bun => "bun",
            Self::Npm => "npm",
        }
    }

    /// The command used to run packages (e.g. `bunx`, `npx`).
    fn exec_cmd(&self) -> &'static str {
        match self {
            Self::Bun => "bunx",
            Self::Npm => "npx",
        }
    }

    /// Args for checking if a global package is installed.
    fn list_global_args(&self, package: &str) -> Vec<String> {
        match self {
            Self::Bun => vec!["pm".into(), "ls".into(), "-g".into()],
            Self::Npm => vec!["ls".into(), "-g".into(), package.into()],
        }
    }

    /// Args for installing a package globally.
    fn install_global_args(&self, package: &str) -> Vec<String> {
        match self {
            Self::Bun => vec!["install".into(), "-g".into(), package.into()],
            Self::Npm => vec!["install".into(), "-g".into(), package.into()],
        }
    }
}

/// Detect the best available package manager. Cached after first call.
fn package_manager() -> PackageManager {
    static PM: OnceLock<PackageManager> = OnceLock::new();
    *PM.get_or_init(|| {
        if std::process::Command::new("bun")
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            PackageManager::Bun
        } else {
            PackageManager::Npm
        }
    })
}

/// A handle to one running ACP session (subprocess + connection).
struct SessionHandle {
    session_id: String,
    conn: Rc<acp::ClientSideConnection>,
    _child: tokio::process::Child,
}

/// Manages all active Claude Code sessions on this CLI.
pub struct ClaudeCodeManager {
    sessions: Rc<RefCell<HashMap<String, SessionHandle>>>,
    /// Pending permission requests: permission_id → oneshot sender for the approved/denied response
    permission_channels: Rc<RefCell<HashMap<String, oneshot::Sender<bool>>>>,
    /// Channel to send messages back to the Enki server via WebSocket
    ws_tx: mpsc::UnboundedSender<String>,
}

impl ClaudeCodeManager {
    pub fn new(ws_tx: mpsc::UnboundedSender<String>) -> Self {
        Self {
            sessions: Rc::new(RefCell::new(HashMap::new())),
            permission_channels: Rc::new(RefCell::new(HashMap::new())),
            ws_tx,
        }
    }

    /// Start a new Claude Code session.
    ///
    /// Spawns the ACP adapter subprocess, initializes the connection,
    /// creates a session, and sends the initial prompt.
    pub async fn start_session(
        &self,
        request_id: String,
        cwd: String,
        prompt: String,
    ) -> Result<()> {
        let cwd_path = crate::link::expand_tilde(&cwd);

        // Create cwd if it doesn't exist
        if !cwd_path.exists() {
            tokio::fs::create_dir_all(&cwd_path)
                .await
                .with_context(|| {
                    format!("Failed to create working directory: {}", cwd_path.display())
                })?;
        }

        // Ensure the ACP adapter is installed, install if missing
        ensure_acp_adapter().await?;

        // Spawn the claude-code-acp adapter
        let pm = package_manager();
        let mut child = tokio::process::Command::new(pm.exec_cmd())
            .arg("@zed-industries/claude-code-acp")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .context("Failed to spawn claude-code-acp")?;

        let stdin = child.stdin.take().unwrap().compat_write();
        let stdout = child.stdout.take().unwrap().compat();

        // Create ACP client that forwards updates to the server
        let client = EnkiAcpClient {
            session_id: RefCell::new(String::new()), // Will be set after session creation
            ws_tx: self.ws_tx.clone(),
            permission_channels: self.permission_channels.clone(),
        };

        let (conn, handle_io) = acp::ClientSideConnection::new(client, stdin, stdout, |fut| {
            tokio::task::spawn_local(fut);
        });

        let conn = Rc::new(conn);

        // Run I/O handler in background
        tokio::task::spawn_local(async move {
            if let Err(e) = handle_io.await {
                eprintln!("[claude_code] I/O error: {}", e);
            }
        });

        // Initialize handshake
        let _init_resp = acp::Agent::initialize(
            conn.as_ref(),
            acp::InitializeRequest::new(acp::ProtocolVersion::V1)
                .client_capabilities(
                    acp::ClientCapabilities::new()
                        .fs(acp::FileSystemCapability::new()
                            .read_text_file(true)
                            .write_text_file(true))
                        .terminal(true),
                )
                .client_info(acp::Implementation::new("enki", "0.1.0").title("Enki CLI")),
        )
        .await
        .context("ACP initialize failed")?;

        // Create a session
        let session_resp =
            acp::Agent::new_session(conn.as_ref(), acp::NewSessionRequest::new(cwd_path))
                .await
                .context("ACP new_session failed")?;

        let session_id = session_resp.session_id.to_string();

        // Notify server that the session started
        send_to_server(
            &self.ws_tx,
            &serde_json::json!({
                "type": "cc_session_started",
                "request_id": request_id,
                "session_id": session_id,
            }),
        );

        // Store the session handle
        self.sessions.borrow_mut().insert(
            session_id.clone(),
            SessionHandle {
                session_id: session_id.clone(),
                conn: conn.clone(),
                _child: child,
            },
        );

        // Send initial prompt (async — updates stream via session_notification)
        let ws_tx = self.ws_tx.clone();
        let sid = session_id.clone();
        tokio::task::spawn_local(async move {
            match acp::Agent::prompt(
                conn.as_ref(),
                acp::PromptRequest::new(
                    acp::SessionId::from(sid.clone()),
                    vec![acp::ContentBlock::Text(acp::TextContent::new(prompt))],
                ),
            )
            .await
            {
                Ok(resp) => {
                    send_to_server(
                        &ws_tx,
                        &serde_json::json!({
                            "type": "cc_prompt_done",
                            "session_id": sid,
                            "stop_reason": format!("{:?}", resp.stop_reason),
                        }),
                    );
                }
                Err(e) => {
                    send_to_server(
                        &ws_tx,
                        &serde_json::json!({
                            "type": "cc_error",
                            "session_id": sid,
                            "request_id": request_id,
                            "error": e.to_string(),
                        }),
                    );
                }
            }
        });

        Ok(())
    }

    /// Send a follow-up prompt to an existing session.
    pub async fn send_prompt(&self, session_id: &str, prompt: String) -> Result<()> {
        let conn = {
            let sessions = self.sessions.borrow();
            let handle = sessions.get(session_id).context("Session not found")?;
            handle.conn.clone()
        };

        let ws_tx = self.ws_tx.clone();
        let sid = session_id.to_string();
        tokio::task::spawn_local(async move {
            match acp::Agent::prompt(
                conn.as_ref(),
                acp::PromptRequest::new(
                    acp::SessionId::from(sid.clone()),
                    vec![acp::ContentBlock::Text(acp::TextContent::new(prompt))],
                ),
            )
            .await
            {
                Ok(resp) => {
                    send_to_server(
                        &ws_tx,
                        &serde_json::json!({
                            "type": "cc_prompt_done",
                            "session_id": sid,
                            "stop_reason": format!("{:?}", resp.stop_reason),
                        }),
                    );
                }
                Err(e) => {
                    send_to_server(
                        &ws_tx,
                        &serde_json::json!({
                            "type": "cc_error",
                            "session_id": sid,
                            "error": e.to_string(),
                        }),
                    );
                }
            }
        });

        Ok(())
    }

    /// Respond to a permission request from the server.
    pub fn handle_permission_response(&self, permission_id: &str, approved: bool) {
        if let Some(tx) = self.permission_channels.borrow_mut().remove(permission_id) {
            let _ = tx.send(approved);
        }
    }

    /// Interrupt a session (cancel current prompt without destroying the session).
    pub async fn interrupt_session(&self, session_id: &str) -> Result<()> {
        let conn = {
            let sessions = self.sessions.borrow();
            let handle = sessions.get(session_id).context("Session not found")?;
            handle.conn.clone()
        };

        acp::Agent::cancel(
            conn.as_ref(),
            acp::CancelNotification::new(acp::SessionId::from(session_id.to_string())),
        )
        .await?;

        // Note: unlike cancel_session, we do NOT remove from the HashMap
        Ok(())
    }

    /// Cancel a session.
    pub async fn cancel_session(&self, session_id: &str) -> Result<()> {
        let conn = {
            let sessions = self.sessions.borrow();
            let handle = sessions.get(session_id).context("Session not found")?;
            handle.conn.clone()
        };

        acp::Agent::cancel(
            conn.as_ref(),
            acp::CancelNotification::new(acp::SessionId::from(session_id.to_string())),
        )
        .await?;

        self.sessions.borrow_mut().remove(session_id);
        Ok(())
    }

    /// Check if Claude Code is available (the real prerequisite).
    /// The ACP adapter is installed separately via npm.
    pub fn is_available() -> bool {
        std::process::Command::new("claude")
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
}

/// ACP Client implementation that forwards updates and permission requests to the Enki server.
///
/// File/terminal operations execute locally — the code lives on this machine.
/// Permission requests and streaming updates go to the server for mediation.
struct EnkiAcpClient {
    session_id: RefCell<String>,
    ws_tx: mpsc::UnboundedSender<String>,
    permission_channels: Rc<RefCell<HashMap<String, oneshot::Sender<bool>>>>,
}

#[async_trait::async_trait(?Send)]
impl acp::Client for EnkiAcpClient {
    // Required: forward permission requests to server for mediation
    async fn request_permission(
        &self,
        args: acp::RequestPermissionRequest,
    ) -> acp::Result<acp::RequestPermissionResponse> {
        let permission_id = uuid::Uuid::new_v4().to_string();
        let session_id = self.session_id.borrow().clone();

        // Extract tool info from the request
        let tool_name = args
            .tool_call
            .fields
            .title
            .clone()
            .unwrap_or_else(|| "unknown".to_string());
        let input = serde_json::to_value(&args.tool_call).unwrap_or_default();

        // Send permission request to server
        send_to_server(
            &self.ws_tx,
            &serde_json::json!({
                "type": "cc_permission_request",
                "session_id": session_id,
                "permission_id": permission_id,
                "tool_name": tool_name,
                "input": input,
            }),
        );

        // Create channel and wait for response
        let (tx, rx) = oneshot::channel();
        self.permission_channels
            .borrow_mut()
            .insert(permission_id.clone(), tx);

        let approved = rx.await.unwrap_or(false);

        if approved {
            // Find the AllowOnce option, falling back to AllowAlways, then first option
            let option_id = args
                .options
                .iter()
                .find(|o| matches!(o.kind, acp::PermissionOptionKind::AllowOnce))
                .or_else(|| {
                    args.options
                        .iter()
                        .find(|o| matches!(o.kind, acp::PermissionOptionKind::AllowAlways))
                })
                .or_else(|| args.options.first())
                .map(|o| o.option_id.clone());

            match option_id {
                Some(id) => Ok(acp::RequestPermissionResponse::new(
                    acp::RequestPermissionOutcome::Selected(acp::SelectedPermissionOutcome::new(
                        id,
                    )),
                )),
                None => Ok(acp::RequestPermissionResponse::new(
                    acp::RequestPermissionOutcome::Cancelled,
                )),
            }
        } else {
            Ok(acp::RequestPermissionResponse::new(
                acp::RequestPermissionOutcome::Cancelled,
            ))
        }
    }

    // Required: forward streaming updates to server
    async fn session_notification(&self, args: acp::SessionNotification) -> acp::Result<()> {
        let session_id = args.session_id.to_string();

        // Update our stored session_id on first notification
        {
            let mut sid = self.session_id.borrow_mut();
            if sid.is_empty() {
                *sid = session_id.clone();
            }
        }

        let (update_type, data) = match &args.update {
            acp::SessionUpdate::AgentMessageChunk(chunk) => {
                let text = match &chunk.content {
                    acp::ContentBlock::Text(t) => t.text.clone(),
                    _ => String::new(),
                };
                ("agent_message_chunk", serde_json::json!({"text": text}))
            }
            acp::SessionUpdate::ToolCall(tc) => (
                "tool_call",
                serde_json::json!({
                    "tool_call_id": tc.tool_call_id.to_string(),
                    "title": tc.title,
                    "status": format!("{:?}", tc.status),
                }),
            ),
            acp::SessionUpdate::ToolCallUpdate(tcu) => (
                "tool_call_update",
                serde_json::json!({
                    "tool_call_id": tcu.tool_call_id.to_string(),
                }),
            ),
            acp::SessionUpdate::Plan(plan) => {
                ("plan", serde_json::to_value(plan).unwrap_or_default())
            }
            _ => return Ok(()),
        };

        send_to_server(
            &self.ws_tx,
            &serde_json::json!({
                "type": "cc_update",
                "session_id": session_id,
                "update_type": update_type,
                "data": data,
            }),
        );

        Ok(())
    }

    // File operations execute locally
    async fn read_text_file(
        &self,
        args: acp::ReadTextFileRequest,
    ) -> acp::Result<acp::ReadTextFileResponse> {
        let path = expand_path(&args.path);
        let content = tokio::fs::read_to_string(&path)
            .await
            .map_err(acp::Error::into_internal_error)?;
        Ok(acp::ReadTextFileResponse::new(content))
    }

    async fn write_text_file(
        &self,
        args: acp::WriteTextFileRequest,
    ) -> acp::Result<acp::WriteTextFileResponse> {
        let path = expand_path(&args.path);
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(acp::Error::into_internal_error)?;
        }
        tokio::fs::write(&path, &args.content)
            .await
            .map_err(acp::Error::into_internal_error)?;
        Ok(acp::WriteTextFileResponse::default())
    }

    // Terminal operations execute locally
    async fn create_terminal(
        &self,
        _args: acp::CreateTerminalRequest,
    ) -> acp::Result<acp::CreateTerminalResponse> {
        // TODO: implement terminal management for Claude Code
        // For now, return not supported
        Err(acp::Error::method_not_found())
    }
}

fn send_to_server(tx: &mpsc::UnboundedSender<String>, msg: &serde_json::Value) {
    let _ = tx.send(serde_json::to_string(msg).unwrap_or_default());
}

const ACP_ADAPTER_PACKAGE: &str = "@zed-industries/claude-code-acp";

/// Ensure the ACP adapter is installed globally. Installs on first use if missing.
async fn ensure_acp_adapter() -> Result<()> {
    let pm = package_manager();

    // Quick check: see if it's already installed
    let list_args = pm.list_global_args(ACP_ADAPTER_PACKAGE);
    let check = tokio::process::Command::new(pm.install_cmd())
        .args(&list_args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await;

    if check.map(|s| s.success()).unwrap_or(false) {
        return Ok(());
    }

    eprintln!(
        "[claude_code] Installing ACP adapter ({ACP_ADAPTER_PACKAGE}) via {:?}...",
        pm
    );
    let install_args = pm.install_global_args(ACP_ADAPTER_PACKAGE);
    let install = tokio::process::Command::new(pm.install_cmd())
        .args(&install_args)
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status()
        .await
        .context("Failed to run package install")?;

    if !install.success() {
        anyhow::bail!("Failed to install {ACP_ADAPTER_PACKAGE}");
    }

    Ok(())
}

fn expand_path(path: &std::path::Path) -> PathBuf {
    let s = path.to_string_lossy();
    if s.starts_with("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(&s[2..]);
        }
    }
    path.to_path_buf()
}
