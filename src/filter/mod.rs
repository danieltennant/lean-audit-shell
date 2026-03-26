pub mod matcher;

use crate::config::{Config, FilterRule, Severity};
use matcher::CompiledMatcher;

/// The result of evaluating a command against the filter engine.
#[derive(Debug, PartialEq)]
pub enum FilterResult {
    /// No rule matched — execute normally.
    Allow,
    /// A warn rule matched — execute, but log and display a warning.
    Warn { rule_id: String, reason: String },
    /// A block rule matched — refuse execution.
    /// Blocks are absolute: there is no in-band override mechanism.
    Block { rule_id: String, reason: String },
}

/// A compiled filter rule, ready for fast evaluation.
struct CompiledRule {
    id:       String,
    reason:   String,
    severity: Severity,
    matcher:  CompiledMatcher,
}

/// The filter engine. Built once at startup from the loaded config.
pub struct FilterEngine {
    enabled: bool,
    rules:   Vec<CompiledRule>,
}

impl FilterEngine {
    /// Build a `FilterEngine` from a loaded `Config`.
    /// All regex patterns are compiled here (they were validated during config load).
    pub fn from_config(config: &Config) -> Self {
        let rules = config
            .filter
            .rules
            .iter()
            .map(|rule: &FilterRule| CompiledRule {
                id:       rule.id.clone(),
                reason:   rule.reason.clone(),
                severity: rule.severity.clone(),
                matcher:  CompiledMatcher::from_rule(rule),
            })
            .collect();

        Self {
            enabled: config.filter.enabled,
            rules,
        }
    }

    /// Evaluate a command string against the filter rules.
    ///
    /// Rules are evaluated in config order. The first matching rule wins.
    /// If filtering is disabled or no rule matches, returns `Allow`.
    pub fn evaluate(&self, command: &str) -> FilterResult {
        if !self.enabled {
            return FilterResult::Allow;
        }

        for rule in &self.rules {
            if rule.matcher.is_match(command) {
                return match rule.severity {
                    Severity::Warn => FilterResult::Warn {
                        rule_id: rule.id.clone(),
                        reason:  rule.reason.clone(),
                    },
                    Severity::Block => FilterResult::Block {
                        rule_id: rule.id.clone(),
                        reason:  rule.reason.clone(),
                    },
                };
            }
        }

        FilterResult::Allow
    }
}
