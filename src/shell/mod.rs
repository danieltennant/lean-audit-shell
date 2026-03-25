// ShellBackend trait + platform dispatch
//
// v1: macOS — ZshBackend (portable-pty, SIGINT)
// v2: Windows — PowerShellBackend (wezterm-pty, CTRL_BREAK_EVENT)

pub mod zsh;
pub mod process;

// Windows backend stub — uncomment when implementing v2
// #[cfg(target_os = "windows")]
// pub mod powershell;

// Platform-selected default backend — uncomment once ZshBackend is implemented in Phase 5.
// #[cfg(target_os = "macos")]
// pub use zsh::ZshBackend as DefaultBackend;
