use std::ffi::OsStr;
use std::process::{Child, Command, Stdio};

use crate::error::{QuincyError, Result};

pub fn run_command<I: IntoIterator<Item = S>, S: AsRef<OsStr>>(
    program: &str,
    arguments: I,
) -> Result<Child> {
    let mut command = Command::new(program);

    command
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    #[cfg(unix)]
    {
        // Force the C locale so that parsing of stdout/stderr from system
        // utilities (e.g. `ip`, `route`, `networksetup`) is not broken by
        // translated messages on localized systems.  Without this, duplicate
        // or not-found route markers such as "File exists" or "No such
        // process" can appear in other languages and silently bypass our
        // string-based detection.
        command.env("LC_ALL", "C").env("LANG", "C");
    }

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;

        // List of all process creation flags:
        // https://learn.microsoft.com/en-us/windows/win32/procthread/process-creation-flags
        const CREATE_NO_WINDOW: u32 = 0x08000000; // Or `134217728u32`

        command.creation_flags(CREATE_NO_WINDOW);
    }

    command
        .spawn()
        .map_err(|e| QuincyError::system(format!("Failed to execute command '{program}': {e}")))
}
