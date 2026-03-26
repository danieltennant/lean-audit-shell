use crate::filter::FilterResult;
use serde::{Deserialize, Serialize};

/// The filter decision recorded for a command request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Allow,
    Warn,
    Block,
}

impl Decision {
    pub fn from_filter_result(result: &FilterResult) -> Self {
        match result {
            FilterResult::Allow        => Decision::Allow,
            FilterResult::Warn { .. }  => Decision::Warn,
            FilterResult::Block { .. } => Decision::Block,
        }
    }
}

/// Written immediately when a command is received, before any execution.
/// Always written — including for blocked commands.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestRecord {
    pub record_type:  String,         // always "request"
    pub command_id:   String,         // UUID v4 — correlates with ResultRecord
    pub sequence:     u64,
    pub timestamp:    String,         // RFC3339 UTC
    pub username:     String,
    pub hostname:     String,
    pub working_dir:  String,
    pub command:      String,
    pub decision:     Decision,
    pub rule_id:      Option<String>, // set when a filter rule fired
    pub rule_reason:  Option<String>, // set when a filter rule fired
    pub shell_version: String,
}

/// Written after a command finishes executing.
/// Never written for blocked commands.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultRecord {
    pub record_type: String,  // always "result"
    pub command_id:  String,  // same UUID as the paired RequestRecord
    pub sequence:    u64,
    pub timestamp:   String,  // RFC3339 UTC — time execution completed
    pub exit_code:   i32,
    pub duration_ms: u64,
}
