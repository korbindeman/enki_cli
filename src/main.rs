//! Enki CLI - Link your machine to the Enki AI assistant

use clap::{Parser, Subcommand};

mod auth;
mod claude_code;
mod config;
mod link;
mod update;

#[derive(Parser)]
#[command(name = "enki")]
#[command(about = "Link your machine to the Enki AI assistant")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Authenticate with Enki (opens browser for passkey login)
    Login,
    /// Remove stored credentials
    Logout,
    /// Show login status and detected capabilities
    Status,
    /// Link this machine to Enki (requires authentication)
    Link {
        /// Limit advertised capabilities (comma-separated: fs,shell,toolchain)
        #[arg(long)]
        capabilities: Option<String>,
        /// Prevent the system from sleeping while the link is active
        #[arg(long)]
        persistent: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    update::check_and_prompt().await?;

    match cli.command {
        Commands::Login => auth::login().await?,
        Commands::Logout => auth::logout()?,
        Commands::Status => auth::status().await?,
        Commands::Link {
            capabilities,
            persistent,
        } => {
            link::start(capabilities, persistent).await?;
        }
    }

    Ok(())
}
