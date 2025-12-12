#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
use quincy::QuincyError;
use quincy::Result;
use std::process::{Child, Command, Stdio};
use tracing::info;

/// Attempts to run a command with elevated privileges.
/// This function will use the appropriate method for the current platform:
/// - macOS: uses osascript with AppleScript to run the command with sudo
/// - Linux: uses pkexec, gksudo, or similar tools
/// - Windows: uses runas or PowerShell with elevated privileges
pub fn run_elevated(program: &str, args: &[&str], title: &str, message: &str) -> Result<Child> {
    #[cfg(target_os = "macos")]
    {
        run_elevated_macos(program, args, title, message)
    }

    #[cfg(target_os = "linux")]
    {
        run_elevated_linux(program, args, title, message)
    }

    #[cfg(target_os = "windows")]
    {
        run_elevated_windows(program, args, title, message)
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        return Err(QuincyError::system(
            "Elevated privileges are not supported on this platform",
        ));
    }
}

#[cfg(target_os = "macos")]
fn run_elevated_macos(program: &str, args: &[&str], _title: &str, message: &str) -> Result<Child> {
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
fn run_elevated_windows(
    program: &str,
    args: &[&str],
    _title: &str,
    _message: &str,
) -> Result<Child> {
    // On Windows, we'll use PowerShell's Start-Process with -Verb RunAs
    // This will trigger the UAC prompt
    let args_str = args.join(" ");

    info!(
        "Running with elevated privileges on Windows: {} {}",
        program, args_str
    );

    let powershell_command = format!(
        "Start-Process -FilePath '{}' -ArgumentList '{}' -Verb RunAs",
        program,
        args_str.replace("'", "''")
    );

    let child = Command::new("powershell")
        .arg("-Command")
        .arg(powershell_command)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    Ok(child)
}
