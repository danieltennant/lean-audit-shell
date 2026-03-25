use anyhow::{bail, Result};

/// The four invocation modes leash supports, matching the Windows Terminal
/// and shell-host conventions from the requirements.
pub enum InvocationMode {
    /// `leash` — start an interactive REPL
    Interactive,
    /// `leash -c "command"` — execute a single command and exit
    Command(String),
    /// `leash -l` — interactive REPL with login-shell semantics
    Login,
    /// `leash --version` — print version and exit
    Version,
}

/// Parse `std::env::args()` into an `InvocationMode`.
pub fn parse() -> Result<InvocationMode> {
    let args: Vec<String> = std::env::args().skip(1).collect();

    match args.as_slice() {
        [] => Ok(InvocationMode::Interactive),
        [flag] if flag == "--version" || flag == "-V" => Ok(InvocationMode::Version),
        [flag] if flag == "-l" => Ok(InvocationMode::Login),
        [flag, cmd] if flag == "-c" => Ok(InvocationMode::Command(cmd.clone())),
        [flag, ..] if flag == "-c" => bail!("-c requires exactly one argument"),
        other => bail!("unrecognised arguments: {}", other.join(" ")),
    }
}
