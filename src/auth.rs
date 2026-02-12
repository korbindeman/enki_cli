//! Authentication commands

use anyhow::{bail, Context, Result};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use url::Url;

use crate::config::{self, Credentials};

const CALLBACK_PORT: u16 = 9876;

/// Perform login flow (standalone command)
pub async fn login() -> Result<()> {
    if let Some(creds) = config::load_credentials()? {
        println!("Already authenticated as: {}", creds.email);
        println!("Run 'enki logout' to sign out first.");
        return Ok(());
    }

    let creds = login_flow().await?;
    println!("Authenticated as: {}", creds.email);
    println!("\nYou can now run 'enki link' to connect this machine.");
    Ok(())
}

/// Core login flow: open browser, wait for callback, save credentials.
/// Returns the credentials on success. Does not check for existing credentials.
pub async fn login_flow() -> Result<Credentials> {
    println!("Opening browser for authentication...");

    // Generate state token
    let state = uuid::Uuid::new_v4().to_string();

    // Build callback URL
    let callback_url = format!("http://localhost:{}", CALLBACK_PORT);

    // Build auth URL
    let web_url = config::web_url();
    let auth_url = format!(
        "{}/?device_auth=1&state={}&callback={}",
        web_url,
        urlencoding::encode(&state),
        urlencoding::encode(&callback_url)
    );

    // Start callback server before opening browser
    let listener = TcpListener::bind(format!("127.0.0.1:{}", CALLBACK_PORT))
        .context("Failed to start callback server. Is port 9876 in use?")?;

    // Set a timeout
    listener
        .set_nonblocking(false)
        .context("Failed to configure listener")?;

    // Open browser
    if let Err(e) = open::that(&auth_url) {
        println!("Failed to open browser automatically: {}", e);
        println!("\nPlease open this URL manually:\n{}\n", auth_url);
    }

    println!("Waiting for authentication...");
    println!("(Press Ctrl+C to cancel)\n");

    // Wait for callback
    let (mut stream, _addr) = listener.accept().context("Failed to accept connection")?;

    // Read the HTTP request
    let mut reader = BufReader::new(&stream);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;

    // Parse the request to get query parameters
    let path = request_line.split_whitespace().nth(1).unwrap_or("/");

    let url = Url::parse(&format!("http://localhost{}", path))?;
    let params: std::collections::HashMap<_, _> = url.query_pairs().collect();

    // Send response
    let response_body = if params.contains_key("token") {
        r##"<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Enki - Device Linked</title>
<script src="https://cdn.tailwindcss.com"></script>
<style>
  :root { --bg-primary: #f8f8f7; --bg-secondary: #ebeae8; --fg-primary: #232320; --fg-muted: #6e6e6a; --border-default: #deddd9; --status-success: #40c057; --status-success-bg: rgba(64, 192, 87, 0.15); }
  @media (prefers-color-scheme: dark) {
    :root { --bg-primary: #1b1b1a; --bg-secondary: #262625; --fg-primary: #f2f2f0; --fg-muted: #adadaa; --border-default: #383835; --status-success: #51cf66; --status-success-bg: rgba(81, 207, 102, 0.2); }
  }
</style>
</head>
<body style="background: var(--bg-primary); color: var(--fg-primary); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;" class="min-h-screen flex items-center justify-center p-4">
  <div class="w-full max-w-sm">
    <div class="text-center mb-8">
      <h1 class="text-3xl font-bold mb-2" style="color: var(--fg-primary);">Enki</h1>
    </div>
    <div class="rounded-xl p-6 shadow-lg" style="background: var(--bg-secondary); border: 1px solid var(--border-default);">
      <div class="flex flex-col items-center py-8">
        <div class="w-12 h-12 rounded-full flex items-center justify-center mb-4" style="background: var(--status-success-bg);">
          <svg class="w-6 h-6" style="color: var(--status-success);" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7"/>
          </svg>
        </div>
        <p class="font-medium mb-2" style="color: var(--fg-primary);">Device linked!</p>
        <p class="text-sm" style="color: var(--fg-muted);">You can close this window and return to the terminal.</p>
      </div>
    </div>
  </div>
</body>
</html>"##
    } else {
        r##"<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Enki - Error</title>
<script src="https://cdn.tailwindcss.com"></script>
<style>
  :root { --bg-primary: #f8f8f7; --bg-secondary: #ebeae8; --fg-primary: #232320; --fg-muted: #6e6e6a; --border-default: #deddd9; --status-error: #fa5252; --status-error-bg: rgba(250, 82, 82, 0.15); }
  @media (prefers-color-scheme: dark) {
    :root { --bg-primary: #1b1b1a; --bg-secondary: #262625; --fg-primary: #f2f2f0; --fg-muted: #adadaa; --border-default: #383835; --status-error: #ff6b6b; --status-error-bg: rgba(255, 107, 107, 0.2); }
  }
</style>
</head>
<body style="background: var(--bg-primary); color: var(--fg-primary); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;" class="min-h-screen flex items-center justify-center p-4">
  <div class="w-full max-w-sm">
    <div class="text-center mb-8">
      <h1 class="text-3xl font-bold mb-2" style="color: var(--fg-primary);">Enki</h1>
    </div>
    <div class="rounded-xl p-6 shadow-lg" style="background: var(--bg-secondary); border: 1px solid var(--border-default);">
      <div class="flex flex-col items-center py-8">
        <div class="w-12 h-12 rounded-full flex items-center justify-center mb-4" style="background: var(--status-error-bg);">
          <svg class="w-6 h-6" style="color: var(--status-error);" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12"/>
          </svg>
        </div>
        <p class="font-medium mb-2" style="color: var(--fg-primary);">Authentication failed</p>
        <p class="text-sm" style="color: var(--fg-muted);">Please try again.</p>
      </div>
    </div>
  </div>
</body>
</html>"##
    };

    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        response_body.len(),
        response_body
    );
    stream.write_all(response.as_bytes())?;
    stream.flush()?;
    drop(stream);

    // Extract credentials
    let refresh_token = params.get("refresh_token").map(|s| s.to_string());
    let user_id = params.get("user_id").map(|s| s.to_string());
    let email = params.get("email").map(|s| s.to_string());

    match (refresh_token, user_id, email) {
        (Some(refresh_token), Some(user_id), Some(email)) => {
            let creds = Credentials {
                refresh_token,
                user_id,
                email,
            };

            config::save_credentials(&creds)?;

            Ok(creds)
        }
        _ => {
            bail!("Authentication failed - missing token or user info");
        }
    }
}

/// Show authentication status and detected capabilities
pub async fn status() -> Result<()> {
    match config::load_credentials()? {
        Some(creds) => {
            println!("Authenticated as: {}", creds.email);
            println!("User ID: {}", creds.user_id);

            // Validate credentials with server
            print!("Status: ");
            match validate_credentials(&creds).await {
                Ok(true) => println!("valid"),
                Ok(false) => println!("invalid (run 'enki login' to re-authenticate)"),
                Err(e) => println!("could not validate ({})", e),
            }
        }
        None => {
            println!("Not authenticated. Run 'enki login' to sign in.");
        }
    }

    // Show detected capabilities
    println!();
    let capabilities = crate::link::detect_capabilities(None)?;
    println!("Capabilities ({}):", capabilities.len());
    for cap in &capabilities {
        match &cap.tools {
            Some(tools) => {
                println!(
                    "  - {} ({})",
                    cap.name,
                    tools
                        .iter()
                        .map(|t| t.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
            None => {
                println!("  - {}", cap.name);
            }
        }
    }

    Ok(())
}

/// Logout (delete credentials)
pub fn logout() -> Result<()> {
    match config::load_credentials()? {
        Some(creds) => {
            config::delete_credentials()?;
            println!("Logged out (was: {})", creds.email);
        }
        None => {
            println!("Not authenticated.");
        }
    }

    Ok(())
}

/// Exchange a refresh token for a JWT.
/// The server rotates refresh tokens on each exchange, so we save the new one.
pub async fn get_jwt(refresh_token: &str) -> Result<String> {
    let url = format!("{}/api/auth/refresh", config::server_url());

    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .json(&serde_json::json!({ "refresh_token": refresh_token }))
        .send()
        .await
        .context("Failed to connect to server")?;

    if !resp.status().is_success() {
        bail!("Token refresh failed");
    }

    let body: serde_json::Value = resp.json().await?;
    let jwt = body["jwt"]
        .as_str()
        .context("Missing jwt in response")?
        .to_string();

    // Server rotates the refresh token — save the new one
    if let Some(new_refresh) = body["refresh_token"].as_str() {
        if let Ok(Some(mut creds)) = config::load_credentials() {
            creds.refresh_token = new_refresh.to_string();
            let _ = config::save_credentials(&creds);
        }
    }

    Ok(jwt)
}

/// Validate credentials by exchanging refresh token and hitting /auth/me
async fn validate_credentials(creds: &Credentials) -> Result<bool> {
    match get_jwt(&creds.refresh_token).await {
        Ok(jwt) => {
            let url = format!("{}/api/auth/me", config::server_url());
            let client = reqwest::Client::new();
            let resp = client
                .get(&url)
                .header("Authorization", format!("Bearer {}", jwt))
                .send()
                .await
                .context("Failed to connect to server")?;
            Ok(resp.status().is_success())
        }
        Err(_) => Ok(false),
    }
}
