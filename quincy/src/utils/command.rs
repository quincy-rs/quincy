use std::ffi::OsStr;
use std::process::{Child, Command, Stdio};

use crate::error::{QuincyError, Result};

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
        .map_err(|e| QuincyError::system(format!("Failed to execute command '{program}': {e}")))
}
