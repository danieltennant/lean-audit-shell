/// PTY-driven integration tests for leash interactive mode.
///
/// Each test spawns the compiled `leash` binary in a real PTY using rexpect,
/// driving it the way a user would: sending input and asserting on output.
/// Both stdout and stderr are visible through the PTY, so blocked/warn
/// messages (written to stderr) appear in the same stream as command output.
use rexpect::session::{spawn_command, PtyReplSession};
use std::io::Write;
use std::process::Command;
use tempfile::NamedTempFile;

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Returns the path to the `claude` binary as zsh would resolve it, or `None`
/// if it is not available. Used to skip Claude-dependent tests gracefully.
fn find_claude() -> Option<String> {
    let out = Command::new("zsh")
        .args(["-c", "which claude"])
        .output()
        .ok()?;
    out.status.success().then(|| {
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    })
}

/// Returns `true` (and prints a skip message) when the `claude` binary is
/// absent. Tests that call this should immediately `return` when it is `true`.
fn skip_without_claude() -> bool {
    if find_claude().is_none() {
        eprintln!("SKIP: claude not found via zsh -c 'which claude'");
        true
    } else {
        false
    }
}

/// Returns `true` (and prints a skip message) when `ANTHROPIC_API_KEY` is not
/// set. Tests that call this should immediately `return` when it is `true`.
fn skip_without_api_key() -> bool {
    if std::env::var("ANTHROPIC_API_KEY").is_err() {
        eprintln!("SKIP: ANTHROPIC_API_KEY not set");
        true
    } else {
        false
    }
}

const TIMEOUT_MS: u64 = 5_000;
const PROMPT: &str = "leash> ";

fn leash_session() -> PtyReplSession {
    let cmd = Command::new(env!("CARGO_BIN_EXE_leash"));
    PtyReplSession {
        echo_on: false,
        prompt: PROMPT.to_string(),
        pty_session: spawn_command(cmd, Some(TIMEOUT_MS)).unwrap(),
        quit_command: None,
    }
}

fn leash_session_with_config(content: &str) -> (PtyReplSession, NamedTempFile) {
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(content.as_bytes()).unwrap();

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_leash"));
    cmd.env("LEASH_CONFIG", f.path());

    let session = PtyReplSession {
        echo_on: false,
        prompt: PROMPT.to_string(),
        pty_session: spawn_command(cmd, Some(TIMEOUT_MS)).unwrap(),
        quit_command: None,
    };
    (session, f)
}

// ── Startup ───────────────────────────────────────────────────────────────────

#[test]
fn prompt_appears_on_startup() {
    let mut p = leash_session();
    p.wait_for_prompt().unwrap();
}

// ── Exit ──────────────────────────────────────────────────────────────────────

#[test]
fn ctrl_d_exits_cleanly() {
    let mut p = leash_session();
    p.wait_for_prompt().unwrap();
    p.send_control('d').unwrap();
    p.exp_eof().unwrap();
}

// ── Ctrl-C ────────────────────────────────────────────────────────────────────

#[test]
fn ctrl_c_at_prompt_reprints_prompt() {
    let mut p = leash_session();
    p.wait_for_prompt().unwrap();
    p.send_control('c').unwrap();
    p.wait_for_prompt().unwrap();
}

// ── Command execution ─────────────────────────────────────────────────────────

#[test]
fn command_output_reaches_terminal() {
    let mut p = leash_session();
    p.wait_for_prompt().unwrap();
    p.send_line("echo hello_leash").unwrap();
    p.exp_string("hello_leash").unwrap();
}

#[test]
fn prompt_reappears_after_successful_command() {
    let mut p = leash_session();
    p.wait_for_prompt().unwrap();
    p.send_line("true").unwrap();
    p.wait_for_prompt().unwrap();
}

#[test]
fn prompt_reappears_after_failed_command() {
    let mut p = leash_session();
    p.wait_for_prompt().unwrap();
    p.send_line("false").unwrap();
    p.wait_for_prompt().unwrap();
}

#[test]
fn multiple_commands_execute_sequentially() {
    // Confirm the shell stays alive across multiple commands.
    // We let the first command run silently (confirmed by the prompt reappearing)
    // then verify the second command produces output.  Checking the first
    // command's output inline causes exp_string to race with rustyline's
    // cursor-positioning escape sequences emitted after the prompt.
    let mut p = leash_session();
    p.wait_for_prompt().unwrap();
    p.send_line("true").unwrap();
    p.wait_for_prompt().unwrap();            // first command finished
    p.send_line("echo SEQUENTIAL_OK").unwrap();
    p.exp_string("SEQUENTIAL_OK").unwrap(); // second command produced output
}

// ── Blocked commands ──────────────────────────────────────────────────────────

const BLOCK_CONFIG: &str = r#"
[audit.local]
enabled = false

[filter]
enabled = true

[[filter.rules]]
id       = "no-danger"
pattern  = "danger"
match    = "contains"
severity = "block"
reason   = "Danger is not allowed."
"#;

#[test]
fn blocked_command_shows_blocked_message() {
    let (mut p, _cfg) = leash_session_with_config(BLOCK_CONFIG);
    p.wait_for_prompt().unwrap();
    p.send_line("danger command").unwrap();
    p.exp_string("BLOCKED").unwrap();
}

#[test]
fn blocked_command_shows_rule_id() {
    let (mut p, _cfg) = leash_session_with_config(BLOCK_CONFIG);
    p.wait_for_prompt().unwrap();
    p.send_line("danger command").unwrap();
    p.exp_string("no-danger").unwrap();
}

#[test]
fn blocked_command_reprompts_and_shell_continues() {
    let (mut p, _cfg) = leash_session_with_config(BLOCK_CONFIG);
    p.wait_for_prompt().unwrap();
    p.send_line("danger command").unwrap();
    p.exp_string("BLOCKED").unwrap();
    p.wait_for_prompt().unwrap();
    // Shell is still alive — a subsequent allowed command executes normally.
    p.send_line("echo still_alive").unwrap();
    p.exp_string("still_alive").unwrap();
}

// ── Warned commands ───────────────────────────────────────────────────────────

const WARN_CONFIG: &str = r#"
[audit.local]
enabled = false

[filter]
enabled = true

[[filter.rules]]
id       = "warn-force"
pattern  = "--force"
match    = "contains"
severity = "warn"
reason   = "Force flag detected."
"#;

#[test]
fn warned_command_shows_warning_message() {
    let (mut p, _cfg) = leash_session_with_config(WARN_CONFIG);
    p.wait_for_prompt().unwrap();
    p.send_line("echo --force").unwrap();
    p.exp_string("WARNING").unwrap();
}

#[test]
fn warned_command_still_executes() {
    let (mut p, _cfg) = leash_session_with_config(WARN_CONFIG);
    p.wait_for_prompt().unwrap();
    // Use a distinct marker so we know the command ran, not just the warn echo.
    p.send_line("echo --force WARN_EXECUTED").unwrap();
    p.exp_string("WARN_EXECUTED").unwrap();
}

#[test]
fn warned_command_reprompts_after_execution() {
    let (mut p, _cfg) = leash_session_with_config(WARN_CONFIG);
    p.wait_for_prompt().unwrap();
    p.send_line("echo --force").unwrap();
    p.exp_string("WARNING").unwrap();
    p.wait_for_prompt().unwrap();
}

// ── Claude Code inside leash ──────────────────────────────────────────────────
//
// These tests exercise running `claude` as a command inside a leash interactive
// session. Tests that require the `claude` binary skip gracefully when it is
// absent. Tests that make API calls also skip when ANTHROPIC_API_KEY is unset.

/// A leash session with a longer per-operation timeout for tests that invoke
/// the Claude API (which can take a few seconds to respond).
fn leash_session_for_claude() -> PtyReplSession {
    PtyReplSession {
        echo_on: false,
        prompt: PROMPT.to_string(),
        pty_session: spawn_command(
            Command::new(env!("CARGO_BIN_EXE_leash")),
            Some(15_000),
        ).unwrap(),
        quit_command: None,
    }
}

#[test]
fn claude_version_is_accessible_from_leash() {
    if skip_without_claude() { return; }
    let mut p = leash_session();
    p.wait_for_prompt().unwrap();
    p.send_line("claude --version").unwrap();
    // Output is "x.y.z (Claude Code)"
    p.exp_string("Claude Code").unwrap();
    p.wait_for_prompt().unwrap();
}

#[test]
fn claude_version_exits_zero_inside_leash() {
    if skip_without_claude() { return; }
    // leash -c propagates the exit code of the command it runs.
    let out = Command::new(env!("CARGO_BIN_EXE_leash"))
        .args(["-c", "claude --version"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Claude Code"), "stdout: {stdout}");
}

#[test]
fn claude_not_blocked_by_default_filter() {
    // With an empty filter rule-set, any claude invocation must be allowed.
    if skip_without_claude() { return; }
    let (mut p, _cfg) = leash_session_with_config(r#"
[audit.local]
enabled = false

[filter]
enabled = true
"#);
    p.wait_for_prompt().unwrap();
    p.send_line("claude --version").unwrap();
    p.exp_string("Claude Code").unwrap();
    p.wait_for_prompt().unwrap();
}

#[test]
fn claude_print_runs_and_returns_to_prompt() {
    if skip_without_claude()  { return; }
    if skip_without_api_key() { return; }
    let mut p = leash_session_for_claude();
    p.wait_for_prompt().unwrap();
    // -p / --print is non-interactive; --output-format text avoids JSON wrapping.
    p.send_line("claude -p 'reply with the single word PONG and nothing else' --output-format text").unwrap();
    p.exp_string("PONG").unwrap();
    p.wait_for_prompt().unwrap();
}

#[test]
fn claude_print_exit_code_propagated_through_leash() {
    if skip_without_claude()  { return; }
    if skip_without_api_key() { return; }
    // leash -c should relay claude's exit code (0 on success) to the caller.
    let out = Command::new(env!("CARGO_BIN_EXE_leash"))
        .args(["-c", "claude -p 'say hi' --output-format text"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "expected claude to exit 0 through leash");
}
