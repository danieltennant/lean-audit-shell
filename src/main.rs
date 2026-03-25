mod cli;
mod config;
mod filter;
mod audit;
mod otel;
mod shell;
mod repl;
mod error;

use anyhow::Result;
use cli::InvocationMode;

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_env("LEASH_LOG")
                .add_directive(tracing::Level::WARN.into()),
        )
        .with_writer(std::io::stderr)
        .init();

    match cli::parse()? {
        InvocationMode::Version => {
            println!("leash {}", env!("CARGO_PKG_VERSION"));
        }
        InvocationMode::Interactive => {
            todo!("interactive REPL (Phase 6)")
        }
        InvocationMode::Command(_cmd) => {
            todo!("non-interactive -c mode (Phase 5)")
        }
        InvocationMode::Login => {
            todo!("login shell mode (Phase 7)")
        }
    }

    Ok(())
}
