use quincy::Result;
use std::process::Child;

/// Attempts to run a command with elevated privileges.
/// This function will use the appropriate method for the current platform:
/// - macOS: uses osascript with AppleScript to run the command with sudo
/// - Linux: uses pkexec, gksudo, or similar tools
/// - Windows: uses ShellExecuteW with the "runas" verb to trigger UAC
///
/// Returns `Some(Child)` on Unix platforms for error diagnostics,
/// `None` on Windows (ShellExecuteW doesn't provide a process handle).
pub fn run_elevated(
    program: &str,
    args: &[&str],
    title: &str,
    message: &str,
) -> Result<Option<Child>> {
    #[cfg(target_os = "macos")]
    {
        run_elevated_macos(program, args, title, message).map(Some)
    }

    #[cfg(target_os = "linux")]
    {
        run_elevated_linux(program, args, title, message).map(Some)
    }

    #[cfg(target_os = "windows")]
    {
        run_elevated_windows(program, args, title, message).map(|()| None)
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Err(quincy::QuincyError::system(
            "Elevated privileges are not supported on this platform",
        ))
    }
}

#[cfg(target_os = "macos")]
fn run_elevated_macos(program: &str, args: &[&str], _title: &str, message: &str) -> Result<Child> {
    use std::process::{Command, Stdio};
    use tracing::info;

    // Properly escape all arguments for shell execution to prevent command injection.
    // We use single quotes around each argument and escape any embedded single quotes
    // by replacing ' with '\'' (end quote, escaped quote, start quote).
    fn quote_escape(arg: &str) -> String {
        format!("'{}'", arg.replace("'", "'\\''"))
    }

    let escaped_program = quote_escape(program);
    let escaped_args: Vec<String> = args.iter().map(|arg| quote_escape(arg)).collect();
    let command_str = format!(
        "{} {} > /dev/null 2> /dev/null &",
        escaped_program,
        escaped_args.join(" ")
    );

    // Create an AppleScript that will prompt for admin privileges
    // Escape double quotes in the command and message for AppleScript
    let apple_script = format!(
        r#"do shell script "{}" with administrator privileges with prompt "{}""#,
        command_str.replace("\\", "\\\\").replace("\"", "\\\""),
        message.replace("\\", "\\\\").replace("\"", "\\\"")
    );

    info!(
        "Running with elevated privileges on macOS: {}",
        escaped_program
    );

    let child = Command::new("osascript")
        .arg("-e")
        .arg(apple_script)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    Ok(child)
}

#[cfg(target_os = "linux")]
fn run_elevated_linux(program: &str, args: &[&str], _title: &str, message: &str) -> Result<Child> {
    use quincy::QuincyError;
    use std::path::Path;
    use std::process::{Command, Stdio};
    use tracing::info;

    info!("Running with elevated privileges on Linux: {}", program);

    // Try pkexec first (part of PolicyKit, available on most modern Linux distros)
    if Path::new("/usr/bin/pkexec").exists() {
        info!("Using pkexec for privilege elevation");

        let mut cmd = Command::new("pkexec");
        cmd.arg(program);
        cmd.args(args);
        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        return Ok(cmd.spawn()?);
    }
    // Try gksudo (GNOME)
    else if Path::new("/usr/bin/gksudo").exists() {
        info!("Using gksudo for privilege elevation");

        let mut cmd = Command::new("gksudo");
        cmd.args(["--message", message, "--"]);
        cmd.arg(program);
        cmd.args(args);
        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        return Ok(cmd.spawn()?);
    }
    // Try kdesudo (KDE)
    else if Path::new("/usr/bin/kdesudo").exists() {
        info!("Using kdesudo for privilege elevation");

        let mut cmd = Command::new("kdesudo");
        cmd.args(["--comment", message, "--"]);
        cmd.arg(program);
        cmd.args(args);
        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        return Ok(cmd.spawn()?);
    }

    Err(QuincyError::system(
        "No graphical privilege escalation tool found (tried pkexec, gksudo, kdesudo)",
    ))
}

#[cfg(target_os = "windows")]
fn run_elevated_windows(program: &str, args: &[&str], _title: &str, _message: &str) -> Result<()> {
    use quincy::QuincyError;
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::HWND;
    use windows::Win32::UI::Shell::{ShellExecuteW, SE_ERR_ACCESSDENIED};
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    fn to_wide(s: &str) -> Vec<u16> {
        OsStr::new(s).encode_wide().chain(Some(0)).collect()
    }

    let verb = to_wide("runas");
    let file = to_wide(program);
    let params = to_wide(&args.join(" "));

    // SAFETY: All pointers are valid null-terminated wide strings.
    let result = unsafe {
        ShellExecuteW(
            Some(HWND::default()),
            PCWSTR(verb.as_ptr()),
            PCWSTR(file.as_ptr()),
            PCWSTR(params.as_ptr()),
            PCWSTR::null(),
            SW_SHOWNORMAL,
        )
    };

    if result.0 as usize <= 32 {
        return Err(QuincyError::system(
            if result.0 as usize == SE_ERR_ACCESSDENIED as usize {
                "User declined UAC prompt"
            } else {
                "Failed to start elevated process"
            },
        ));
    }

    Ok(())
}
