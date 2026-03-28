use anyhow::Result;
use leash::cli::{self, InvocationMode};
use leash::config::Config;
use leash::repl::{ProcessResult, Repl};
use leash::shell::ZshBackend;
use std::path::PathBuf;
use std::sync::Arc;

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
            let config = Config::load()?;
            let backend = Arc::new(ZshBackend::new(false));
            let repl = Repl::new(&config, backend);
            repl.run_interactive()?;
        }

        InvocationMode::Login => {
            let config = Config::load()?;
            let backend = Arc::new(ZshBackend::new(true));
            let repl = Repl::new(&config, backend);
            repl.run_interactive()?;
        }

        InvocationMode::Command(cmd) => {
            let config = Config::load()?;
            let backend = Arc::new(ZshBackend::default());
            let repl = Repl::new(&config, backend);
            let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));

            match repl.process(&cmd, &cwd) {
                ProcessResult::Empty => {}
                ProcessResult::Blocked { rule_id, reason } => {
                    eprintln!("[leash] BLOCKED [{rule_id}]: {reason}");
                    std::process::exit(1);
                }
                ProcessResult::Executed { exit_code, .. } => {
                    std::process::exit(exit_code);
                }
                ProcessResult::BackendError(e) => {
                    eprintln!("[leash] error: {e}");
                    std::process::exit(1);
                }
            }
        }
    }

    Ok(())
}
