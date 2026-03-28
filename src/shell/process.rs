use super::{RunResult, ShellBackend};
use anyhow::Result;
use std::collections::VecDeque;
use std::path::Path;
use std::sync::Mutex;

/// A fake shell backend for use in tests.
///
/// Returns preset `(exit_code, duration_ms)` responses in FIFO order.
/// Falls back to `(0, 0)` once the preset queue is exhausted. Records
/// every command string passed to `run()` so tests can assert on them.
pub struct MockShellBackend {
    responses: Mutex<VecDeque<(i32, u64)>>,
    calls:     Mutex<Vec<String>>,
}

impl MockShellBackend {
    pub fn new() -> Self {
        Self {
            responses: Mutex::new(VecDeque::new()),
            calls:     Mutex::new(Vec::new()),
        }
    }

    /// Enqueue a response to be returned by the next `run()` call.
    pub fn push_response(&self, exit_code: i32, duration_ms: u64) {
        self.responses.lock().unwrap().push_back((exit_code, duration_ms));
    }

    /// Return a snapshot of every command string that has been run.
    pub fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
}

impl Default for MockShellBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl ShellBackend for MockShellBackend {
    fn run(&self, command: &str, _working_dir: &Path) -> Result<RunResult> {
        self.calls.lock().unwrap().push(command.to_string());
        let (exit_code, duration_ms) = self
            .responses
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or((0, 0));
        Ok(RunResult { exit_code, duration_ms })
    }
}
