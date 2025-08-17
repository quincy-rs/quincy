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
    let command_str = format!("{} {} > /dev/null 2> /dev/null &", program, args.join(" "));

    // Create an AppleScript that will prompt for admin privileges
    let apple_script = format!(
        r#"do shell script "{}" with administrator privileges with prompt "{}""#,
        command_str.replace("\"", "\\\""),
        message.replace("\"", "\\\"")
    );

    info!("Running with elevated privileges on macOS: {}", command_str);

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
    use std::path::Path;

    // Try pkexec first (part of PolicyKit, available on most modern Linux distros)
    if Path::new("/usr/bin/pkexec").exists() {
        info!("Using pkexec for privilege elevation");

        let mut command = Command::new("pkexec");
        command.arg(program);
        command.args(args);

        return Ok(command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?);
    }
    // Try gksudo (GNOME)
    else if Path::new("/usr/bin/gksudo").exists() {
        info!("Using gksudo for privilege elevation");

        let args_str = args.join(" ");
        let command_str = format!("{} {}", program, args_str);

        return Ok(Command::new("gksudo")
            .arg("--message")
            .arg(message)
            .arg(command_str)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?);
    }
    // Try kdesudo (KDE)
    else if Path::new("/usr/bin/kdesudo").exists() {
        info!("Using kdesudo for privilege elevation");

        let args_str = args.join(" ");
        let command_str = format!("{} {}", program, args_str);

        return Ok(Command::new("kdesudo")
            .arg("--comment")
            .arg(message)
            .arg(command_str)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?);
    }

    Err(QuincyError::system(
        "No graphical privilege escalation tool is supported on this platform",
    ))
}

#[cfg(target_os = "windows")]
fn run_elevated_windows(program: &str, args: &[&str], title: &str, message: &str) -> Result<Child> {
    // On Windows, we'll use PowerShell's Start-Process with -Verb RunAs
    // This will trigger the UAC prompt
    let args_str = args.join(" ");

    info!(
        "Running with elevated privileges on Windows: {} {}",
        program, args_str
    );

    let powershell_command = format!(
        "Start-Process -FilePath '{}' -ArgumentList '{}' -Verb RunAs -Wait",
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
