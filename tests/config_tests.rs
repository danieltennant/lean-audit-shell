use leash::config::{Config, MatchType, Severity, Transport};
use std::io::Write;
use tempfile::NamedTempFile;

fn write_config(content: &str) -> NamedTempFile {
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(content.as_bytes()).unwrap();
    f
}

// ── Defaults ────────────────────────────────────────────────────────────────

#[test]
fn default_config_is_valid() {
    let cfg = Config::default();
    assert_eq!(cfg.shell.underlying, "auto");
    assert!(cfg.audit.local.enabled);
    assert!(!cfg.audit.remote.enabled);
    assert!(cfg.filter.enabled);
    assert!(cfg.filter.rules.is_empty());
}

#[test]
fn missing_file_returns_defaults() {
    let cfg = Config::load_from(std::path::Path::new("/nonexistent/leash/config.toml")).unwrap();
    assert_eq!(cfg.shell.underlying, "auto");
    assert!(cfg.filter.rules.is_empty());
}

// ── Valid configs ────────────────────────────────────────────────────────────

#[test]
fn load_minimal_config() {
    let f = write_config("[filter]\nenabled = false\n");
    let cfg = Config::load_from(f.path()).unwrap();
    assert!(!cfg.filter.enabled);
    // unspecified fields take defaults
    assert_eq!(cfg.shell.underlying, "auto");
    assert!(cfg.audit.local.enabled);
}

#[test]
fn load_full_config() {
    let f = write_config(
        r#"
[shell]
underlying = "/bin/zsh"

[audit.local]
enabled  = true
log_path = "/tmp/leash-test.log"

[audit.remote]
enabled          = true
endpoint         = "http://collector:4317"
transport        = "grpc"
service_name     = "leash-test"
max_retries      = 5
retry_backoff_ms = 1000

[audit.remote.headers]
"x-api-key" = "secret"

[filter]
enabled = true

[[filter.rules]]
id       = "no-rm-root"
pattern  = "rm -rf /"
match    = "contains"
severity = "block"
reason   = "Dangerous."

[[filter.rules]]
id       = "warn-force-push"
pattern  = "git push.*--force"
match    = "regex"
severity = "warn"
reason   = "Force push."
"#,
    );

    let cfg = Config::load_from(f.path()).unwrap();

    assert_eq!(cfg.shell.underlying, "/bin/zsh");

    assert!(cfg.audit.local.enabled);
    assert_eq!(cfg.audit.local.log_path.unwrap().to_str().unwrap(), "/tmp/leash-test.log");

    assert!(cfg.audit.remote.enabled);
    assert_eq!(cfg.audit.remote.endpoint, "http://collector:4317");
    assert_eq!(cfg.audit.remote.transport, Transport::Grpc);
    assert_eq!(cfg.audit.remote.service_name, "leash-test");
    assert_eq!(cfg.audit.remote.max_retries, 5);
    assert_eq!(cfg.audit.remote.retry_backoff_ms, 1000);
    assert_eq!(cfg.audit.remote.headers.get("x-api-key").unwrap(), "secret");

    assert_eq!(cfg.filter.rules.len(), 2);

    let r0 = &cfg.filter.rules[0];
    assert_eq!(r0.id, "no-rm-root");
    assert_eq!(r0.match_type, MatchType::Contains);
    assert_eq!(r0.severity, Severity::Block);

    let r1 = &cfg.filter.rules[1];
    assert_eq!(r1.id, "warn-force-push");
    assert_eq!(r1.match_type, MatchType::Regex);
    assert_eq!(r1.severity, Severity::Warn);
}

#[test]
fn transport_defaults_to_http() {
    let f = write_config("[audit.remote]\nenabled = true\n");
    let cfg = Config::load_from(f.path()).unwrap();
    assert_eq!(cfg.audit.remote.transport, Transport::Http);
}

// ── Error cases ──────────────────────────────────────────────────────────────

#[test]
fn malformed_toml_returns_error() {
    let f = write_config("this is not [ valid toml !!!");
    let err = Config::load_from(f.path()).unwrap_err();
    assert!(err.to_string().contains("failed to parse config file"));
}

#[test]
fn unknown_severity_returns_error() {
    let f = write_config(
        r#"
[[filter.rules]]
id       = "bad"
pattern  = "foo"
match    = "contains"
severity = "explode"
reason   = "test"
"#,
    );
    assert!(Config::load_from(f.path()).is_err());
}

#[test]
fn unknown_match_type_returns_error() {
    let f = write_config(
        r#"
[[filter.rules]]
id       = "bad"
pattern  = "foo"
match    = "fuzzy"
severity = "block"
reason   = "test"
"#,
    );
    assert!(Config::load_from(f.path()).is_err());
}

#[test]
fn invalid_regex_returns_error_at_load_time() {
    let f = write_config(
        r#"
[[filter.rules]]
id       = "bad-regex"
pattern  = "(unclosed"
match    = "regex"
severity = "block"
reason   = "test"
"#,
    );
    let err = Config::load_from(f.path()).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("bad-regex"), "expected rule id in error: {msg}");
    assert!(msg.contains("(unclosed"), "expected pattern in error: {msg}");
}

#[test]
fn invalid_regex_in_contains_rule_is_ignored() {
    // contains rules are not compiled as regex — pattern is a literal string
    let f = write_config(
        r#"
[[filter.rules]]
id       = "literal"
pattern  = "(this would be invalid regex"
match    = "contains"
severity = "block"
reason   = "test"
"#,
    );
    assert!(Config::load_from(f.path()).is_ok());
}

// ── LEASH_CONFIG env var ─────────────────────────────────────────────────────

#[test]
fn leash_config_env_var_overrides_path() {
    let f = write_config("[shell]\nunderlying = \"/usr/bin/bash\"\n");
    // Safety: tests run in a single-threaded context for env var mutation.
    // Use load_from directly to avoid global env mutation where possible;
    // this test verifies the env var plumbing via Config::load().
    unsafe { std::env::set_var("LEASH_CONFIG", f.path()) };
    let cfg = Config::load().unwrap();
    unsafe { std::env::remove_var("LEASH_CONFIG") };
    assert_eq!(cfg.shell.underlying, "/usr/bin/bash");
}
