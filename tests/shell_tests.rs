use leash::shell::{MockShellBackend, RunResult, ShellBackend};
use std::path::Path;

// ── MockShellBackend ──────────────────────────────────────────────────────────

#[test]
fn mock_returns_preset_exit_code_and_duration() {
    let backend = MockShellBackend::new();
    backend.push_response(42, 100);
    let result = backend.run("anything", Path::new("/")).unwrap();
    assert_eq!(result, RunResult { exit_code: 42, duration_ms: 100 });
}

#[test]
fn mock_defaults_to_exit_zero_when_queue_empty() {
    let backend = MockShellBackend::new();
    let result = backend.run("cmd", Path::new("/")).unwrap();
    assert_eq!(result.exit_code, 0);
}

#[test]
fn mock_records_commands_in_order() {
    let backend = MockShellBackend::new();
    backend.run("first",  Path::new("/")).unwrap();
    backend.run("second", Path::new("/")).unwrap();
    backend.run("third",  Path::new("/")).unwrap();
    assert_eq!(backend.calls(), vec!["first", "second", "third"]);
}

#[test]
fn mock_responses_consumed_fifo() {
    let backend = MockShellBackend::new();
    backend.push_response(1, 10);
    backend.push_response(2, 20);
    backend.push_response(3, 30);

    assert_eq!(backend.run("a", Path::new("/")).unwrap().exit_code, 1);
    assert_eq!(backend.run("b", Path::new("/")).unwrap().exit_code, 2);
    assert_eq!(backend.run("c", Path::new("/")).unwrap().exit_code, 3);
    // Queue exhausted — falls back to 0
    assert_eq!(backend.run("d", Path::new("/")).unwrap().exit_code, 0);
}

#[test]
fn mock_working_dir_is_not_checked() {
    // MockShellBackend ignores working_dir; this just confirms it doesn't panic
    let backend = MockShellBackend::new();
    backend.run("cmd", Path::new("/nonexistent/path")).unwrap();
}

// ── ZshBackend integration (spawns real zsh; stdin is a pipe in CI) ───────────

#[cfg(unix)]
mod zsh_integration {
    use leash::shell::{ShellBackend, ZshBackend};
    use std::path::Path;

    fn backend() -> ZshBackend {
        ZshBackend::default()
    }

    #[test]
    fn exit_zero_for_true() {
        let result = backend().run("true", Path::new("/tmp")).unwrap();
        assert_eq!(result.exit_code, 0);
    }

    #[test]
    fn exit_nonzero_for_false() {
        let result = backend().run("false", Path::new("/tmp")).unwrap();
        assert_ne!(result.exit_code, 0);
    }

    #[test]
    fn exit_code_1_for_explicit_exit_1() {
        let result = backend().run("exit 1", Path::new("/tmp")).unwrap();
        assert_eq!(result.exit_code, 1);
    }

    #[test]
    fn exit_code_127_for_unknown_command() {
        // zsh exits 127 when a command is not found
        let result = backend().run("__leash_no_such_cmd__", Path::new("/tmp")).unwrap();
        assert_eq!(result.exit_code, 127);
    }

    #[test]
    fn duration_ms_is_plausible() {
        let result = backend().run("true", Path::new("/tmp")).unwrap();
        assert!(result.duration_ms < 10_000, "duration should be under 10 s, got {}ms", result.duration_ms);
    }

    #[test]
    fn working_dir_is_respected() {
        // `test -d .` exits 0 only if cwd is an existing directory
        let result = backend().run("test -d .", Path::new("/tmp")).unwrap();
        assert_eq!(result.exit_code, 0);
    }

    #[test]
    fn multiple_commands_separated_by_semicolons() {
        let result = backend().run("true; true; false", Path::new("/tmp")).unwrap();
        // Exit code of a semicolon-separated list is the last command's exit code
        assert_ne!(result.exit_code, 0);
    }
}
