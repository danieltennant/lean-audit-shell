use crate::config::{MatchType, FilterRule};
use regex::Regex;

/// A compiled, ready-to-evaluate matcher for a single filter rule.
pub enum CompiledMatcher {
    Contains(String),
    Regex(Regex),
}

impl CompiledMatcher {
    /// Build a `CompiledMatcher` from a `FilterRule`.
    ///
    /// Regex patterns are compiled here. `Contains` patterns are stored as-is
    /// (matching is case-insensitive at eval time).
    ///
    /// Panics if called on a `Regex` rule whose pattern failed to compile —
    /// but `Config::load()` validates all regex patterns eagerly at startup,
    /// so this should never be reached with an invalid pattern.
    pub fn from_rule(rule: &FilterRule) -> Self {
        match rule.match_type {
            MatchType::Contains => CompiledMatcher::Contains(rule.pattern.to_lowercase()),
            MatchType::Regex => {
                CompiledMatcher::Regex(Regex::new(&rule.pattern).expect(
                    "regex should have been validated during config load",
                ))
            }
        }
    }

    /// Returns `true` if `input` matches this pattern.
    pub fn is_match(&self, input: &str) -> bool {
        match self {
            CompiledMatcher::Contains(pattern) => input.to_lowercase().contains(pattern.as_str()),
            CompiledMatcher::Regex(re) => re.is_match(input),
        }
    }
}
