use std::collections::HashMap;
use std::path::PathBuf;
use serde::{Deserialize, Serialize};

/// Top-level configuration loaded from config.toml.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct Config {
    pub shell:  ShellConfig,
    pub audit:  AuditConfig,
    pub filter: FilterConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            shell:  ShellConfig::default(),
            audit:  AuditConfig::default(),
            filter: FilterConfig::default(),
        }
    }
}

/// Shell backend configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct ShellConfig {
    /// "auto" to detect the platform shell, or an explicit path.
    pub underlying: String,
}

impl Default for ShellConfig {
    fn default() -> Self {
        Self { underlying: "auto".to_string() }
    }
}

/// Audit logging configuration (local file + optional remote OTel).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct AuditConfig {
    pub local:  LocalAuditConfig,
    pub remote: RemoteAuditConfig,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            local:  LocalAuditConfig::default(),
            remote: RemoteAuditConfig::default(),
        }
    }
}

/// Local NDJSON audit log configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct LocalAuditConfig {
    /// Whether to write the local audit log. Default: true.
    pub enabled:  bool,
    /// Override the default platform log path.
    pub log_path: Option<PathBuf>,
}

impl Default for LocalAuditConfig {
    fn default() -> Self {
        Self { enabled: true, log_path: None }
    }
}

/// Remote OTel audit log configuration.
/// Only active when `enabled = true` AND the binary is built with `--features otel`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct RemoteAuditConfig {
    /// Whether to export to an OTLP endpoint. Default: false.
    pub enabled:          bool,
    pub endpoint:         String,
    pub transport:        Transport,
    pub service_name:     String,
    pub max_retries:      u32,
    pub retry_backoff_ms: u64,
    pub headers:          HashMap<String, String>,
}

impl Default for RemoteAuditConfig {
    fn default() -> Self {
        Self {
            enabled:          false,
            endpoint:         "http://localhost:4317".to_string(),
            transport:        Transport::Http,
            service_name:     "leash".to_string(),
            max_retries:      3,
            retry_backoff_ms: 500,
            headers:          HashMap::new(),
        }
    }
}

/// OTLP transport protocol.
#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    #[default]
    Http,
    Grpc,
}

/// Command filter configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct FilterConfig {
    /// Whether filtering is active. Default: true.
    pub enabled: bool,
    pub rules:   Vec<FilterRule>,
}

impl Default for FilterConfig {
    fn default() -> Self {
        Self { enabled: true, rules: Vec::new() }
    }
}

/// A single filter rule.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FilterRule {
    /// Unique identifier used in log entries and error messages.
    pub id:         String,
    /// The pattern to match against the command string.
    pub pattern:    String,
    /// How to interpret the pattern.
    #[serde(rename = "match")]
    pub match_type: MatchType,
    /// What to do when the rule matches.
    pub severity:   Severity,
    /// Human-readable explanation shown to the user on a match.
    pub reason:     String,
}

/// Pattern match mode.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum MatchType {
    /// Case-insensitive substring match.
    Contains,
    /// Full regular expression match.
    Regex,
}

/// What to do when a rule matches.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Refuse execution, log as blocked, return exit code 1.
    Block,
    /// Allow execution but print a warning and log with rule ID.
    Warn,
}
