pub mod record;
pub use record::{Decision, RequestRecord, ResultRecord};

use crate::config::Config;
use crate::filter::FilterResult;
use anyhow::{Context, Result};
use chrono::Utc;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use uuid::Uuid;

/// Returns the platform default audit log path.
///
/// - macOS/Linux: `~/.local/share/leash/audit.log`
/// - Windows:     `%APPDATA%\Local\leash\audit.log`
pub fn default_audit_log_path() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("leash")
        .join("audit.log")
}

/// Append-only NDJSON audit logger.
///
/// Each call to `write_request` or `write_result` appends one JSON line and
/// flushes immediately. The sequence counter is monotonically increasing across
/// both record types, so records can be sorted into arrival order.
///
/// If the log file becomes unavailable, errors are emitted to stderr and
/// execution continues — logging failure is never fatal.
pub struct AuditLogger {
    file:     Mutex<fs::File>,
    sequence: AtomicU64,
    username: String,
    hostname: String,
    version:  String,
}

impl AuditLogger {
    /// Open the audit log configured in `config`, creating the file and any
    /// parent directories if they do not exist.
    pub fn from_config(config: &Config) -> Result<Self> {
        let path = config
            .audit
            .local
            .log_path
            .clone()
            .unwrap_or_else(default_audit_log_path);
        Self::open(&path)
    }

    /// Open a log at a specific path (useful for tests).
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create audit log directory: {}", parent.display()))?;
        }

        let file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(path)
            .with_context(|| format!("failed to open audit log: {}", path.display()))?;

        Ok(Self {
            file:     Mutex::new(file),
            sequence: AtomicU64::new(1),
            username: whoami::username(),
            hostname: whoami::fallible::hostname().unwrap_or_else(|_| "unknown".to_string()),
            version:  env!("CARGO_PKG_VERSION").to_string(),
        })
    }

    /// Write a request record. Returns the `command_id` UUID to be passed
    /// to `write_result` after execution completes.
    ///
    /// Always call this before executing (or refusing) a command.
    pub fn write_request(
        &self,
        command: &str,
        working_dir: &str,
        filter_result: &FilterResult,
    ) -> String {
        let command_id = Uuid::new_v4().to_string();
        let (rule_id, rule_reason) = match filter_result {
            FilterResult::Warn { rule_id, reason } => {
                (Some(rule_id.clone()), Some(reason.clone()))
            }
            FilterResult::Block { rule_id, reason } => {
                (Some(rule_id.clone()), Some(reason.clone()))
            }
            FilterResult::Allow => (None, None),
        };

        let record = RequestRecord {
            record_type:  "request".to_string(),
            command_id:   command_id.clone(),
            sequence:     self.sequence.fetch_add(1, Ordering::Relaxed),
            timestamp:    Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            username:     self.username.clone(),
            hostname:     self.hostname.clone(),
            working_dir:  working_dir.to_string(),
            command:      command.to_string(),
            decision:     Decision::from_filter_result(filter_result),
            rule_id,
            rule_reason,
            shell_version: self.version.clone(),
        };

        self.write_line(&record);
        command_id
    }

    /// Write a result record after a command finishes executing.
    ///
    /// `command_id` must be the value returned by the paired `write_request` call.
    pub fn write_result(&self, command_id: &str, exit_code: i32, duration_ms: u64) {
        let record = ResultRecord {
            record_type: "result".to_string(),
            command_id:  command_id.to_string(),
            sequence:    self.sequence.fetch_add(1, Ordering::Relaxed),
            timestamp:   Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            exit_code,
            duration_ms,
        };

        self.write_line(&record);
    }

    /// Serialise `record` to a JSON line and append it to the log file.
    /// On error, warns to stderr — never panics, never blocks execution.
    fn write_line<T: serde::Serialize>(&self, record: &T) {
        let line = match serde_json::to_string(record) {
            Ok(json) => json + "\n",
            Err(e) => {
                eprintln!("[leash] failed to serialise audit record: {e}");
                return;
            }
        };

        match self.file.lock() {
            Ok(mut f) => {
                if let Err(e) = f.write_all(line.as_bytes()).and_then(|_| f.flush()) {
                    eprintln!("[leash] failed to write audit log: {e}");
                }
            }
            Err(e) => {
                eprintln!("[leash] audit log mutex poisoned: {e}");
            }
        }
    }
}

/// A no-op logger used when `audit.local.enabled = false`.
pub struct NullAuditLogger;

impl NullAuditLogger {
    pub fn write_request(&self, _command: &str, _working_dir: &str, _filter_result: &FilterResult) -> String {
        Uuid::new_v4().to_string()
    }
    pub fn write_result(&self, _command_id: &str, _exit_code: i32, _duration_ms: u64) {}
}

/// Dispatch type used by the REPL — either a real logger or the no-op.
pub enum Auditor {
    Active(AuditLogger),
    Null(NullAuditLogger),
}

impl Auditor {
    pub fn from_config(config: &Config) -> Self {
        if config.audit.local.enabled {
            match AuditLogger::from_config(config) {
                Ok(logger) => Auditor::Active(logger),
                Err(e) => {
                    eprintln!("[leash] audit log unavailable, continuing without logging: {e}");
                    Auditor::Null(NullAuditLogger)
                }
            }
        } else {
            Auditor::Null(NullAuditLogger)
        }
    }

    pub fn write_request(&self, command: &str, working_dir: &str, filter_result: &FilterResult) -> String {
        match self {
            Auditor::Active(l) => l.write_request(command, working_dir, filter_result),
            Auditor::Null(l)   => l.write_request(command, working_dir, filter_result),
        }
    }

    pub fn write_result(&self, command_id: &str, exit_code: i32, duration_ms: u64) {
        match self {
            Auditor::Active(l) => l.write_result(command_id, exit_code, duration_ms),
            Auditor::Null(l)   => l.write_result(command_id, exit_code, duration_ms),
        }
    }
}
