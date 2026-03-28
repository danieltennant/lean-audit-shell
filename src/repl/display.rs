/// Print a block message to stderr. Called before skipping execution.
pub fn print_blocked(rule_id: &str, reason: &str) {
    eprintln!("[leash] BLOCKED [{rule_id}]: {reason}");
}

/// Print a warn message to stderr. Called before allowing execution.
pub fn print_warned(rule_id: &str, reason: &str) {
    eprintln!("[leash] WARNING [{rule_id}]: {reason}");
}
