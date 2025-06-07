use anyhow::{Context, Result};
use std::ffi::OsStr;
use std::process::{Child, Command, Stdio};

pub fn run_command<I: IntoIterator<Item = S>, S: AsRef<OsStr>>(
    program: &str,
    arguments: I,
) -> Result<Child> {
    Command::new(program)
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to execute command")
}
