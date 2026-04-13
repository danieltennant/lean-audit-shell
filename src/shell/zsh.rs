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

/// A self-cancelling handle to the stdin-forwarding thread.
///
/// The thread forwards bytes from the process's real stdin to the inner PTY
/// master while a child command is running.  A `pipe(2)` cancel channel is
/// used so the thread can be unblocked and joined before `run()` returns —
/// preventing a dangling thread from consuming the next command's input.
#[cfg(unix)]
struct StdinForwarder {
    /// Write end of the cancel pipe; closed by `cancel_and_join`.
    cancel_write: libc::c_int,
    handle:       Option<std::thread::JoinHandle<()>>,
}

#[cfg(unix)]
impl StdinForwarder {
    /// Spawn the forwarding thread.  `writer` is the inner PTY master's write
    /// end; ownership is transferred to the thread.
    fn spawn(mut writer: Box<dyn Write + Send>) -> Self {
        use std::os::unix::io::AsRawFd;

        let mut pipe_fds = [0i32; 2];
        // SAFETY: pipe() is always safe to call.
        unsafe { libc::pipe(pipe_fds.as_mut_ptr()) };
        let cancel_read:  libc::c_int = pipe_fds[0];
        let cancel_write: libc::c_int = pipe_fds[1];

        let handle = std::thread::spawn(move || {
            let stdin_fd = io::stdin().as_raw_fd();
            let mut stdin = io::stdin();
            let mut buf   = [0u8; 256];

            loop {
                // Block until stdin is readable OR the cancel pipe fires.
                let mut pfds = [
                    libc::pollfd { fd: stdin_fd,   events: libc::POLLIN, revents: 0 },
                    libc::pollfd { fd: cancel_read, events: libc::POLLIN, revents: 0 },
                ];
                // SAFETY: pfds is a valid array, poll is signal-safe.
                let ret = unsafe { libc::poll(pfds.as_mut_ptr(), 2, -1) };
                if ret <= 0 { break; }                              // error / EINTR
                if pfds[1].revents & libc::POLLIN != 0 { break; }  // cancel signal

                match stdin.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if writer.write_all(&buf[..n]).is_err() { break; }
                    }
                }
            }

            // SAFETY: close fd we own.
            unsafe { libc::close(cancel_read); }
        });

        Self { cancel_write, handle: Some(handle) }
    }

    /// Signal the thread to exit and block until it has.
    ///
    /// Called after `child.wait()` so that no subsequent stdin data can be
    /// consumed by a forwarder belonging to a finished command.
    fn cancel_and_join(&mut self) {
        if self.cancel_write >= 0 {
            // SAFETY: writing a single byte to a pipe we own.
            unsafe {
                let b: u8 = 1;
                libc::write(
                    self.cancel_write,
                    &b as *const u8 as *const libc::c_void,
                    1,
                );
                libc::close(self.cancel_write);
            }
            self.cancel_write = -1;
        }
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

#[cfg(unix)]
impl Drop for StdinForwarder {
    fn drop(&mut self) {
        self.cancel_and_join();
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
        let writer = pair.master
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
            _raw_guard    = Some(RawModeGuard);
            _writer_held  = None;

            // ── Unix: cancellable forwarder thread ────────────────────────────
            // The StdinForwarder is kept alive until after child.wait() so we can
            // cancel_and_join() it, ensuring the thread exits before run() returns
            // and cannot race with the next command's input.
            #[cfg(unix)]
            let mut _forwarder = StdinForwarder::spawn(writer);

            // ── Non-Unix fallback: detached thread ────────────────────────────
            // On platforms without libc we fall back to a best-effort approach.
            #[cfg(not(unix))]
            std::thread::spawn(move || {
                let mut w   = writer;
                let mut stdin = io::stdin();
                let mut buf = [0u8; 256];
                loop {
                    match stdin.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => { if w.write_all(&buf[..n]).is_err() { break; } }
                    }
                }
            });

            // Forward PTY master output → stdout until the child closes its end.
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

            // _raw_guard drops here, restoring terminal mode before we wait.
            drop(_raw_guard);

            let exit_code = child
                .wait()
                .context("failed to wait for child")?
                .exit_code() as i32;

            // Cancel and join the forwarder *after* child.wait().  This is the
            // point at which we are certain the child is gone and no new data
            // needs to be forwarded, so it is safe to reclaim stdin.
            #[cfg(unix)]
            _forwarder.cancel_and_join();

            Ok(RunResult {
                exit_code,
                duration_ms: start.elapsed().as_millis() as u64,
            })
        } else {
            // Non-interactive: hold the writer open (no forwarding) so the slave
            // does not see EOF until after we have finished reading all output.
            _writer_held = Some(writer);
            _raw_guard   = None;

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
}
