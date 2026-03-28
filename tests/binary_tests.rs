/// End-to-end binary integration tests.
///
/// Each test spawns the compiled `leash` binary as a subprocess via
/// `std::process::Command`. No PTY harness is needed — these exercise
/// the `-c` mode and `--version` paths, which use piped stdout/stderr.
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Command;
use tempfile::{NamedTempFile, TempDir};

fn leash() -> Command {
    Command::new(env!("CARGO_BIN_EXE_leash"))
}

fn write_config(content: &str) -> NamedTempFile {
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(content.as_bytes()).unwrap();
    f
}

fn run_c(cmd: &str) -> std::process::Output {
    leash().args(["-c", cmd]).output().expect("failed to spawn leash")
}

fn run_c_with_config(cmd: &str, config: &Path) -> std::process::Output {
    leash()
        .args(["-c", cmd])
        .env("LEASH_CONFIG", config)
        .output()
        .expect("failed to spawn leash")
}

// ── --version ─────────────────────────────────────────────────────────────────

#[test]
fn version_flag_prints_package_version() {
    let out = leash().arg("--version").output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("leash"), "stdout: {stdout}");
    assert!(stdout.contains(env!("CARGO_PKG_VERSION")), "stdout: {stdout}");
}

// ── -c exit codes ─────────────────────────────────────────────────────────────

#[test]
fn c_mode_exits_zero_for_true() {
    assert_eq!(run_c("true").status.code(), Some(0));
}

#[test]
fn c_mode_exits_nonzero_for_false() {
    assert_ne!(run_c("false").status.code(), Some(0));
}

#[test]
fn c_mode_propagates_exact_exit_code() {
    assert_eq!(run_c("exit 42").status.code(), Some(42));
}

#[test]
fn c_mode_exits_127_for_unknown_command() {
    assert_eq!(run_c("__no_such_leash_cmd__").status.code(), Some(127));
}

// ── -c stdout passthrough ─────────────────────────────────────────────────────

#[test]
fn c_mode_stdout_reaches_caller() {
    let out = run_c("echo hello_leash");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("hello_leash"), "stdout: {stdout}");
}

// ── leash -c "date" — Phase 7 acceptance criterion AC-08 ─────────────────────

#[test]
fn c_mode_date_exits_zero_and_produces_output() {
    let out = run_c("date");
    assert_eq!(out.status.code(), Some(0), "date should exit 0");
    let stdout = String::from_utf8_lossy(&out.stdout);
    // date always produces non-empty output
    assert!(!stdout.trim().is_empty(), "date should produce output");
}

// ── unrecognised arguments ────────────────────────────────────────────────────

#[test]
fn unrecognised_flag_exits_nonzero() {
    let out = leash().arg("--unknown-flag").output().unwrap();
    assert_ne!(out.status.code(), Some(0));
}

#[test]
fn c_flag_without_argument_exits_nonzero() {
    let out = leash().arg("-c").output().unwrap();
    assert_ne!(out.status.code(), Some(0));
}

// ── filter: block ─────────────────────────────────────────────────────────────

#[test]
fn blocked_command_exits_1() {
    let cfg = write_config(
        r#"
[audit.local]
enabled = false

[filter]
enabled = true

[[filter.rules]]
id       = "no-rm-root"
pattern  = "rm -rf /"
match    = "contains"
severity = "block"
reason   = "Deleting root is not allowed."
"#,
    );

    let out = run_c_with_config("rm -rf /", cfg.path());
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn blocked_command_prints_rule_id_to_stderr() {
    let cfg = write_config(
        r#"
[audit.local]
enabled = false

[filter]
enabled = true

[[filter.rules]]
id       = "no-rm-root"
pattern  = "rm -rf /"
match    = "contains"
severity = "block"
reason   = "Deleting root is not allowed."
"#,
    );

    let out = run_c_with_config("rm -rf /", cfg.path());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("BLOCKED"), "stderr: {stderr}");
    assert!(stderr.contains("no-rm-root"), "stderr: {stderr}");
}

#[test]
fn blocked_command_produces_no_stdout() {
    let cfg = write_config(
        r#"
[audit.local]
enabled = false

[filter]
enabled = true

[[filter.rules]]
id       = "no-echo-secret"
pattern  = "echo secret"
match    = "contains"
severity = "block"
reason   = "Secrets must not be echoed."
"#,
    );

    let out = run_c_with_config("echo secret", cfg.path());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.contains("secret"),
        "blocked command must not produce output; stdout: {stdout}");
}

// ── filter: warn ──────────────────────────────────────────────────────────────

#[test]
fn warned_command_still_executes() {
    let cfg = write_config(
        r#"
[audit.local]
enabled = false

[filter]
enabled = true

[[filter.rules]]
id       = "warn-flag"
pattern  = "--force"
match    = "contains"
severity = "warn"
reason   = "Force flag detected."
"#,
    );

    // Command succeeds despite the warn rule
    let out = run_c_with_config("echo --force", cfg.path());
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn warned_command_prints_warning_to_stderr() {
    let cfg = write_config(
        r#"
[audit.local]
enabled = false

[filter]
enabled = true

[[filter.rules]]
id       = "warn-flag"
pattern  = "--force"
match    = "contains"
severity = "warn"
reason   = "Force flag detected."
"#,
    );

    let out = run_c_with_config("echo --force", cfg.path());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("WARNING"), "stderr: {stderr}");
    assert!(stderr.contains("warn-flag"), "stderr: {stderr}");
}

// ── audit log ─────────────────────────────────────────────────────────────────

#[test]
fn c_mode_writes_request_and_result_records() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.log");

    let cfg = write_config(&format!(
        r#"
[audit.local]
enabled  = true
log_path = "{}"

[filter]
enabled = false
"#,
        log_path.display()
    ));

    let out = run_c_with_config("true", cfg.path());
    assert_eq!(out.status.code(), Some(0));

    assert!(log_path.exists(), "audit log should be created");

    let content = fs::read_to_string(&log_path).unwrap();
    let lines: Vec<&str> = content.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(lines.len(), 2, "expected request + result records, got {lines:?}");

    let request: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    let result: serde_json::Value = serde_json::from_str(lines[1]).unwrap();

    assert_eq!(request["record_type"], "request");
    assert_eq!(request["command"],     "true");
    assert_eq!(request["decision"],    "allow");
    assert_eq!(result["record_type"],  "result");
    assert_eq!(result["exit_code"],    0);
    assert_eq!(request["command_id"],  result["command_id"],
        "request and result must share the same command_id");
}

#[test]
fn c_mode_blocked_command_writes_only_request_record() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.log");

    let cfg = write_config(&format!(
        r#"
[audit.local]
enabled  = true
log_path = "{}"

[filter]
enabled = true

[[filter.rules]]
id       = "no-danger"
pattern  = "danger"
match    = "contains"
severity = "block"
reason   = "Danger is blocked."
"#,
        log_path.display()
    ));

    run_c_with_config("danger command", cfg.path());

    let content = fs::read_to_string(&log_path).unwrap();
    let lines: Vec<&str> = content.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(lines.len(), 1, "blocked command should write only a request record");

    let record: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(record["record_type"], "request");
    assert_eq!(record["decision"],    "block");
    assert_eq!(record["rule_id"],     "no-danger");
}
