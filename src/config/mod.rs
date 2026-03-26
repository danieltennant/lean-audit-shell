pub mod types;
pub use types::{
    AuditConfig, Config, FilterConfig, FilterRule, LocalAuditConfig, MatchType,
    RemoteAuditConfig, Severity, ShellConfig, Transport,
};

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// Returns the platform default config file path.
///
/// - macOS/Linux: `~/.config/leash/config.toml`
/// - Windows:     `%APPDATA%\leash\config.toml`
pub fn default_config_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("leash")
        .join("config.toml")
}

impl Config {
    /// Load configuration from the default path or the `LEASH_CONFIG` env var override.
    ///
    /// If the config file does not exist, a default `Config` is returned silently.
    /// If the file exists but is malformed or contains an invalid regex, an error is returned.
    pub fn load() -> Result<Self> {
        let path = match std::env::var("LEASH_CONFIG") {
            Ok(p) => PathBuf::from(p),
            Err(_) => default_config_path(),
        };
        Self::load_from(&path)
    }

    /// Load configuration from a specific path.
    ///
    /// Missing file → default config. Present but invalid → error.
    pub fn load_from(path: &Path) -> Result<Self> {
        if !path.exists() {
            tracing::debug!("config file not found at {}, using defaults", path.display());
            return Ok(Self::default());
        }

        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config file: {}", path.display()))?;

        let config: Self = toml::from_str(&content)
            .with_context(|| format!("failed to parse config file: {}", path.display()))?;

        config.validate()?;

        tracing::debug!("loaded config from {}", path.display());
        Ok(config)
    }

    /// Validate the loaded config.
    /// Currently: eagerly compile all regex patterns to catch errors at startup.
    fn validate(&self) -> Result<()> {
        for rule in &self.filter.rules {
            if rule.match_type == MatchType::Regex {
                regex::Regex::new(&rule.pattern).with_context(|| {
                    format!(
                        "invalid regex in filter rule '{}': pattern = {:?}",
                        rule.id, rule.pattern
                    )
                })?;
            }
        }
        Ok(())
    }
}
