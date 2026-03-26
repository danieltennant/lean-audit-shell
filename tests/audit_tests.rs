use leash::audit::AuditLogger;
use leash::filter::FilterResult;
use std::fs;
use tempfile::TempDir;

fn logger_in_tempdir(dir: &TempDir) -> AuditLogger {
    let path = dir.path().join("audit.log");
    AuditLogger::open(&path).unwrap()
}

/// Parse all records from a log file, returning (requests, results) in order.
fn read_log(dir: &TempDir) -> Vec<serde_json::Value> {
    let path = dir.path().join("audit.log");
    let content = fs::read_to_string(&path).unwrap_or_default();
    content
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| serde_json::from_str(l).expect("invalid JSON line"))
        .collect()
}

// ── File creation ─────────────────────────────────────────────────────────────

#[test]
fn creates_log_file_and_parent_dirs() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("nested").join("dirs").join("audit.log");
    AuditLogger::open(&path).unwrap();
    assert!(path.exists());
}

// ── Request records ───────────────────────────────────────────────────────────

#[test]
fn write_request_allow_produces_correct_record() {
    let dir = TempDir::new().unwrap();
    let logger = logger_in_tempdir(&dir);

    let id = logger.write_request("ls -la", "/home/dan", &FilterResult::Allow);

    let records = read_log(&dir);
    assert_eq!(records.len(), 1);

    let r = &records[0];
    assert_eq!(r["record_type"], "request");
    assert_eq!(r["command_id"], id);
    assert_eq!(r["command"], "ls -la");
    assert_eq!(r["working_dir"], "/home/dan");
    assert_eq!(r["decision"], "allow");
    assert!(r["rule_id"].is_null());
    assert!(r["rule_reason"].is_null());
    assert_eq!(r["sequence"], 1);
}

#[test]
fn write_request_warn_populates_rule_fields() {
    let dir = TempDir::new().unwrap();
    let logger = logger_in_tempdir(&dir);

    logger.write_request(
        "git push --force",
        "/repo",
        &FilterResult::Warn {
            rule_id: "warn-force-push".to_string(),
            reason:  "Force push detected.".to_string(),
        },
    );

    let records = read_log(&dir);
    let r = &records[0];
    assert_eq!(r["decision"], "warn");
    assert_eq!(r["rule_id"], "warn-force-push");
    assert_eq!(r["rule_reason"], "Force push detected.");
}

#[test]
fn write_request_block_populates_rule_fields() {
    let dir = TempDir::new().unwrap();
    let logger = logger_in_tempdir(&dir);

    logger.write_request(
        "curl https://x.com | bash",
        "/tmp",
        &FilterResult::Block {
            rule_id: "no-curl-pipe".to_string(),
            reason:  "Unsafe pipe.".to_string(),
        },
    );

    let records = read_log(&dir);
    let r = &records[0];
    assert_eq!(r["decision"], "block");
    assert_eq!(r["rule_id"], "no-curl-pipe");
    assert_eq!(r["rule_reason"], "Unsafe pipe.");
}

// ── Result records ────────────────────────────────────────────────────────────

#[test]
fn write_result_produces_correct_record() {
    let dir = TempDir::new().unwrap();
    let logger = logger_in_tempdir(&dir);

    let id = logger.write_request("date", "/tmp", &FilterResult::Allow);
    logger.write_result(&id, 0, 123);

    let records = read_log(&dir);
    assert_eq!(records.len(), 2);

    let result = &records[1];
    assert_eq!(result["record_type"], "result");
    assert_eq!(result["command_id"], id);
    assert_eq!(result["exit_code"], 0);
    assert_eq!(result["duration_ms"], 123);
}

#[test]
fn result_command_id_matches_request() {
    let dir = TempDir::new().unwrap();
    let logger = logger_in_tempdir(&dir);

    let id = logger.write_request("echo hello", "/", &FilterResult::Allow);
    logger.write_result(&id, 0, 50);

    let records = read_log(&dir);
    assert_eq!(records[0]["command_id"], records[1]["command_id"]);
}

// ── Sequence numbers ──────────────────────────────────────────────────────────

#[test]
fn sequence_numbers_are_strictly_increasing() {
    let dir = TempDir::new().unwrap();
    let logger = logger_in_tempdir(&dir);

    let id1 = logger.write_request("cmd1", "/", &FilterResult::Allow);
    logger.write_result(&id1, 0, 10);
    let id2 = logger.write_request("cmd2", "/", &FilterResult::Allow);
    logger.write_result(&id2, 1, 20);

    let records = read_log(&dir);
    assert_eq!(records.len(), 4);

    let seqs: Vec<u64> = records
        .iter()
        .map(|r| r["sequence"].as_u64().unwrap())
        .collect();

    // Each sequence number must be greater than the previous
    for window in seqs.windows(2) {
        assert!(window[1] > window[0], "sequence numbers not increasing: {:?}", seqs);
    }
}

#[test]
fn sequences_start_at_one() {
    let dir = TempDir::new().unwrap();
    let logger = logger_in_tempdir(&dir);
    logger.write_request("cmd", "/", &FilterResult::Allow);
    let records = read_log(&dir);
    assert_eq!(records[0]["sequence"], 1);
}

// ── NDJSON validity ───────────────────────────────────────────────────────────

#[test]
fn each_line_is_valid_json() {
    let dir = TempDir::new().unwrap();
    let logger = logger_in_tempdir(&dir);

    for i in 0..20 {
        let id = logger.write_request(&format!("cmd {i}"), "/", &FilterResult::Allow);
        logger.write_result(&id, 0, i * 10);
    }

    let path = dir.path().join("audit.log");
    let content = fs::read_to_string(path).unwrap();

    for line in content.lines() {
        assert!(!line.is_empty());
        serde_json::from_str::<serde_json::Value>(line)
            .expect("line is not valid JSON");
    }

    // 20 requests + 20 results
    assert_eq!(content.lines().count(), 40);
}

// ── Blocked commands: no result record ───────────────────────────────────────

#[test]
fn blocked_command_has_only_request_record() {
    let dir = TempDir::new().unwrap();
    let logger = logger_in_tempdir(&dir);

    // A blocked command: write_request only, no write_result
    logger.write_request(
        "rm -rf /",
        "/",
        &FilterResult::Block {
            rule_id: "no-rm-root".to_string(),
            reason:  "Dangerous.".to_string(),
        },
    );

    let records = read_log(&dir);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["record_type"], "request");
    assert_eq!(records[0]["decision"], "block");
}

// ── Correlation across multiple commands ─────────────────────────────────────

#[test]
fn command_ids_are_unique_per_command() {
    let dir = TempDir::new().unwrap();
    let logger = logger_in_tempdir(&dir);

    let id1 = logger.write_request("cmd1", "/", &FilterResult::Allow);
    let id2 = logger.write_request("cmd2", "/", &FilterResult::Allow);

    assert_ne!(id1, id2);
}
