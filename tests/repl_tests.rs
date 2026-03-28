use leash::config::{Config, FilterConfig, FilterRule, MatchType, Severity};
use leash::repl::{ProcessResult, Repl};
use leash::shell::{MockShellBackend, ShellBackend};
use std::path::Path;
use std::sync::Arc;

fn make_repl(rules: Vec<FilterRule>, mock: Arc<MockShellBackend>) -> Repl {
    let mut config = Config::default();
    config.filter = FilterConfig { enabled: true, rules };
    config.audit.local.enabled = false; // no file I/O in unit tests
    Repl::new(&config, mock as Arc<dyn ShellBackend>)
}

fn block_rule(id: &str, pattern: &str) -> FilterRule {
    FilterRule {
        id:         id.to_string(),
        pattern:    pattern.to_string(),
        match_type: MatchType::Contains,
        severity:   Severity::Block,
        reason:     format!("blocked by {id}"),
    }
}

fn warn_rule(id: &str, pattern: &str) -> FilterRule {
    FilterRule {
        id:         id.to_string(),
        pattern:    pattern.to_string(),
        match_type: MatchType::Contains,
        severity:   Severity::Warn,
        reason:     format!("warned by {id}"),
    }
}

// ── Blocking ──────────────────────────────────────────────────────────────────

#[test]
fn blocked_command_not_sent_to_backend() {
    let mock = Arc::new(MockShellBackend::new());
    let repl = make_repl(vec![block_rule("no-rm", "rm")], Arc::clone(&mock));

    let result = repl.process("rm -rf /", Path::new("/"));

    assert!(matches!(result, ProcessResult::Blocked { .. }),
        "expected Blocked, got {result:?}");
    assert!(mock.calls().is_empty(), "blocked command must not reach the backend");
}

#[test]
fn blocked_result_carries_rule_id_and_reason() {
    let mock = Arc::new(MockShellBackend::new());
    let repl = make_repl(
        vec![FilterRule {
            id:         "my-rule".to_string(),
            pattern:    "forbidden".to_string(),
            match_type: MatchType::Contains,
            severity:   Severity::Block,
            reason:     "Policy violation.".to_string(),
        }],
        Arc::clone(&mock),
    );

    match repl.process("run forbidden thing", Path::new("/")) {
        ProcessResult::Blocked { rule_id, reason } => {
            assert_eq!(rule_id, "my-rule");
            assert_eq!(reason, "Policy violation.");
        }
        other => panic!("expected Blocked, got {other:?}"),
    }
}

// ── Warn ──────────────────────────────────────────────────────────────────────

#[test]
fn warned_command_is_sent_to_backend() {
    let mock = Arc::new(MockShellBackend::new());
    mock.push_response(0, 10);
    let repl = make_repl(vec![warn_rule("warn-force", "--force")], Arc::clone(&mock));

    let result = repl.process("git push --force", Path::new("/"));

    assert!(matches!(result, ProcessResult::Executed { exit_code: 0, .. }),
        "warned command should be executed");
    assert_eq!(mock.calls(), vec!["git push --force"]);
}

// ── Allow ─────────────────────────────────────────────────────────────────────

#[test]
fn allowed_command_is_sent_to_backend() {
    let mock = Arc::new(MockShellBackend::new());
    mock.push_response(0, 5);
    let repl = make_repl(vec![], Arc::clone(&mock));

    repl.process("ls -la", Path::new("/"));

    assert_eq!(mock.calls(), vec!["ls -la"]);
}

#[test]
fn executed_result_carries_exit_code_and_duration() {
    let mock = Arc::new(MockShellBackend::new());
    mock.push_response(42, 123);
    let repl = make_repl(vec![], Arc::clone(&mock));

    match repl.process("some-cmd", Path::new("/")) {
        ProcessResult::Executed { exit_code, duration_ms } => {
            assert_eq!(exit_code, 42);
            assert_eq!(duration_ms, 123);
        }
        other => panic!("expected Executed, got {other:?}"),
    }
}

// ── Empty input ───────────────────────────────────────────────────────────────

#[test]
fn empty_line_returns_empty_and_skips_backend() {
    let mock = Arc::new(MockShellBackend::new());
    let repl = make_repl(vec![], Arc::clone(&mock));

    assert!(matches!(repl.process("", Path::new("/")), ProcessResult::Empty));
    assert!(matches!(repl.process("   ", Path::new("/")), ProcessResult::Empty));
    assert!(mock.calls().is_empty());
}

// ── History gating (inferred from ProcessResult) ──────────────────────────────

#[test]
fn process_returns_blocked_so_caller_skips_history() {
    // The REPL run_interactive() only adds to history when Executed or BackendError.
    // This test confirms Blocked is returned — history gating is in the caller.
    let mock = Arc::new(MockShellBackend::new());
    let repl = make_repl(vec![block_rule("r", "danger")], Arc::clone(&mock));

    let result = repl.process("danger!", Path::new("/"));
    assert!(matches!(result, ProcessResult::Blocked { .. }));
}

#[test]
fn process_returns_executed_so_caller_adds_to_history() {
    let mock = Arc::new(MockShellBackend::new());
    mock.push_response(0, 1);
    let repl = make_repl(vec![], Arc::clone(&mock));

    let result = repl.process("date", Path::new("/"));
    assert!(matches!(result, ProcessResult::Executed { .. }));
}

// ── Multiple sequential commands ──────────────────────────────────────────────

#[test]
fn multiple_commands_processed_in_order() {
    let mock = Arc::new(MockShellBackend::new());
    mock.push_response(0, 1);
    mock.push_response(1, 2);
    let repl = make_repl(vec![block_rule("no-rm", "rm")], Arc::clone(&mock));

    repl.process("ls", Path::new("/"));       // allowed → executed
    repl.process("rm file", Path::new("/"));  // blocked → not sent
    repl.process("date", Path::new("/"));     // allowed → executed

    assert_eq!(mock.calls(), vec!["ls", "date"],
        "only non-blocked commands should reach the backend");
}
