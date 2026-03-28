// ShellBackend trait + platform dispatch
//
// v1: macOS — ZshBackend (portable-pty, SIGINT via PTY raw mode)
// v2: Windows — PowerShellBackend (wezterm-pty, CTRL_BREAK_EVENT)

pub mod process;
pub mod zsh;

pub use process::MockShellBackend;

#[cfg(unix)]
pub use zsh::ZshBackend;

#[cfg(unix)]
pub use zsh::ZshBackend as DefaultBackend;

use anyhow::Result;
use std::path::Path;

/// Outcome of running a single command through the shell backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunResult {
    /// Exit code returned by the command (or 1 if killed by a signal).
    pub exit_code: i32,
    /// Wall-clock time from spawn to exit, in milliseconds.
    pub duration_ms: u64,
}

/// Platform-agnostic interface for spawning commands inside the underlying
/// shell PTY. Each `run()` call blocks until the command exits.
///
/// SIGINT forwarding: when stdin is a terminal, `ZshBackend` enables raw mode
/// so that Ctrl-C is forwarded as byte 0x03 into the PTY. The child's TTY
/// driver converts that to SIGINT for its foreground process group — no
/// explicit signal forwarding is needed.
pub trait ShellBackend: Send + Sync {
    fn run(&self, command: &str, working_dir: &Path) -> Result<RunResult>;
}
