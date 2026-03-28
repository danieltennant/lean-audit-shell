use super::{RunResult, ShellBackend};
use anyhow::{Context, Result};
use crossterm::terminal;
use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use std::io::{self, IsTerminal, Read, Write};
use std::path::Path;
use std::time::Instant;
use which::which;

/// Shell backend for macOS using zsh and a local PTY via `portable-pty`.
///
/// Spawns `zsh [-l] -c "<command>"` inside a PTY, then forwards I/O between
/// the host terminal and the PTY master. Restores terminal state on exit,
/// even if the command panics or returns an error.
///
/// When `login_shell` is `true` the `-l` flag is passed to zsh so that login
/// profiles (`~/.zprofile`, `/etc/zprofile`) are sourced before the command
/// runs — matching the semantics of `leash -l`.
pub struct ZshBackend {
    shell:       std::path::PathBuf,
    login_shell: bool,
}

impl Default for ZshBackend {
    fn default() -> Self {
        Self::new(false)
    }
}

impl ZshBackend {
    pub fn new(login_shell: bool) -> Self {
        let shell = which("zsh").unwrap_or_else(|_| std::path::PathBuf::from("/bin/zsh"));
        Self { shell, login_shell }
    }
}

/// RAII guard that disables terminal raw mode when dropped.
struct RawModeGuard;

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = terminal::disable_raw_mode();
    }
}

fn current_pty_size() -> PtySize {
    if let Ok((cols, rows)) = terminal::size() {
        PtySize { rows, cols, pixel_width: 0, pixel_height: 0 }
    } else {
        PtySize { rows: 24, cols: 80, pixel_width: 0, pixel_height: 0 }
    }
}

impl ShellBackend for ZshBackend {
    fn run(&self, command: &str, working_dir: &Path) -> Result<RunResult> {
        let start = Instant::now();

        let pty_system = native_pty_system();
        let pair = pty_system
            .openpty(current_pty_size())
            .context("failed to open PTY")?;

        let mut cmd = CommandBuilder::new(&self.shell);
        if self.login_shell {
            cmd.arg("-l");
        }
        cmd.args(["-c", command]);
        cmd.cwd(working_dir);

        let mut child = pair.slave
            .spawn_command(cmd)
            .context("failed to spawn shell")?;
        drop(pair.slave);

        let mut reader = pair.master
            .try_clone_reader()
            .context("failed to clone PTY reader")?;
        let mut writer = pair.master
            .take_writer()
            .context("failed to take PTY writer")?;

        // Enable raw mode and forward stdin only when running interactively.
        // In raw mode, Ctrl-C generates byte 0x03 which the PTY driver converts
        // to SIGINT for the child's foreground process group automatically.
        let stdin_is_tty = io::stdin().is_terminal();
        let _raw_guard: Option<RawModeGuard>;
        // Held open in non-tty mode to prevent premature EOF on the slave PTY,
        // which some shells echo as visible "^D" output.
        let _writer_held: Option<Box<dyn Write + Send>>;

        if stdin_is_tty {
            terminal::enable_raw_mode().context("failed to enable terminal raw mode")?;
            _raw_guard = Some(RawModeGuard);
            _writer_held = None;

            // Spawn a background thread to forward stdin → PTY master.
            // The thread exits naturally when the master write fails (child exited).
            std::thread::spawn(move || {
                let mut stdin = io::stdin();
                let mut buf = [0u8; 256];
                loop {
                    match stdin.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if writer.write_all(&buf[..n]).is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        } else {
            // Non-interactive: hold the writer open (no forwarding) so the slave
            // does not see EOF until after we have finished reading all output.
            _writer_held = Some(writer);
            _raw_guard = None;
        }

        // Forward PTY master output → stdout until the child closes its end.
        // This blocks until the process exits and the slave PTY is fully drained.
        let mut stdout = io::stdout();
        let mut buf = [0u8; 4096];
        loop {
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    stdout.write_all(&buf[..n]).context("write PTY output to stdout")?;
                    stdout.flush().context("flush stdout")?;
                }
            }
        }

        // _raw_guard drops here, restoring terminal mode before we return.
        drop(_raw_guard);

        let exit_code = child
            .wait()
            .context("failed to wait for child")?
            .exit_code() as i32;

        Ok(RunResult {
            exit_code,
            duration_ms: start.elapsed().as_millis() as u64,
        })
    }
}
