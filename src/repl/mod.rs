pub mod completer;
pub mod display;

use crate::audit::Auditor;
use crate::config::Config;
use crate::filter::{FilterEngine, FilterResult};
use crate::shell::ShellBackend;
use anyhow::Result;
use rustyline::{error::ReadlineError, history::FileHistory, Editor};
use std::path::{Path, PathBuf};
use std::sync::Arc;

type ReplEditor = Editor<(), FileHistory>;

fn history_file_path() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("leash")
        .join("history")
}

/// Outcome of processing one command line through filter + backend.
#[derive(Debug)]
pub enum ProcessResult {
    /// The line was empty or whitespace-only — nothing to do.
    Empty,
    /// A filter rule blocked the command. Not executed, not added to history.
    Blocked { rule_id: String, reason: String },
    /// The command was executed (possibly after a warn). Carries exit code.
    Executed { exit_code: i32, duration_ms: u64 },
    /// Filter allowed/warned but the backend returned an error.
    BackendError(anyhow::Error),
}

pub struct Repl {
    filter:       FilterEngine,
    auditor:      Auditor,
    backend:      Arc<dyn ShellBackend>,
    history_path: PathBuf,
}

impl Repl {
    pub fn new(config: &Config, backend: Arc<dyn ShellBackend>) -> Self {
        Self {
            filter:       FilterEngine::from_config(config),
            auditor:      Auditor::from_config(config),
            backend,
            history_path: history_file_path(),
        }
    }

    /// Process a single command string: filter → audit → (optionally) execute.
    ///
    /// Does not interact with readline or history — the caller decides whether
    /// to add the command to history based on the returned `ProcessResult`.
    pub fn process(&self, command: &str, working_dir: &Path) -> ProcessResult {
        let command = command.trim();
        if command.is_empty() {
            return ProcessResult::Empty;
        }

        let filter_result = self.filter.evaluate(command);
        let cwd = working_dir.to_str().unwrap_or(".");

        match &filter_result {
            FilterResult::Block { rule_id, reason } => {
                self.auditor.write_request(command, cwd, &filter_result);
                ProcessResult::Blocked {
                    rule_id: rule_id.clone(),
                    reason:  reason.clone(),
                }
            }
            result => {
                if let FilterResult::Warn { rule_id, reason } = result {
                    display::print_warned(rule_id, reason);
                }
                let command_id = self.auditor.write_request(command, cwd, &filter_result);
                match self.backend.run(command, working_dir) {
                    Ok(run) => {
                        self.auditor.write_result(&command_id, run.exit_code, run.duration_ms);
                        ProcessResult::Executed {
                            exit_code:   run.exit_code,
                            duration_ms: run.duration_ms,
                        }
                    }
                    Err(e) => {
                        self.auditor.write_result(&command_id, 1, 0);
                        ProcessResult::BackendError(e)
                    }
                }
            }
        }
    }

    /// Run the interactive readline loop until EOF (Ctrl-D) or a fatal error.
    ///
    /// History is appended to disk after each successfully executed command.
    /// Blocked commands are not added to history.
    pub fn run_interactive(&self) -> Result<()> {
        let mut editor = self.make_editor()?;
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));

        loop {
            match editor.readline("leash> ") {
                Ok(line) => {
                    let result = self.process(&line, &cwd);
                    match &result {
                        ProcessResult::Empty => {}
                        ProcessResult::Blocked { rule_id, reason } => {
                            display::print_blocked(rule_id, reason);
                        }
                        ProcessResult::Executed { .. } => {
                            let _ = editor.add_history_entry(line.trim());
                            let _ = editor.append_history(&self.history_path);
                        }
                        ProcessResult::BackendError(e) => {
                            eprintln!("[leash] error running command: {e}");
                            let _ = editor.add_history_entry(line.trim());
                            let _ = editor.append_history(&self.history_path);
                        }
                    }
                }
                Err(ReadlineError::Interrupted) => {
                    // Ctrl-C at the prompt — print new prompt
                    continue;
                }
                Err(ReadlineError::Eof) => {
                    // Ctrl-D — clean exit
                    break;
                }
                Err(e) => {
                    eprintln!("[leash] readline error: {e}");
                    break;
                }
            }
        }

        Ok(())
    }

    fn make_editor(&self) -> Result<ReplEditor> {
        if let Some(parent) = self.history_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let config = rustyline::Config::builder()
            .history_ignore_space(true)
            .auto_add_history(false)
            .build();

        let mut editor = ReplEditor::with_config(config)?;
        let _ = editor.load_history(&self.history_path);
        Ok(editor)
    }
}
