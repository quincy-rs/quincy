use anyhow::{anyhow, Result};
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHasher};
use clap::Parser;
use dashmap::DashMap;
use quincy::auth::users_file::{load_users_file, save_users_file, User};
use rand_core::OsRng;
use rpassword::prompt_password;
use std::io::Write;
use std::path::PathBuf;
use std::process::exit;

#[derive(Parser)]
#[command(name = "quincy")]
pub struct Args {
    #[arg(short, long, group = "mode")]
    pub add: bool,
    #[arg(short, long, group = "mode")]
    pub delete: bool,
    #[arg(requires = "mode", default_value = "users")]
    pub users_file_path: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let mut users = load_users_file(&args.users_file_path)?;

    users = match (args.add, args.delete) {
        (true, false) => add_user(users)?,
        (false, true) => remove_user(users)?,
        _ => {
            eprintln!("Either add or delete switch must be specified");
            exit(1);
        }
    };

    save_users_file(&args.users_file_path, users)?;

    Ok(())
}

/// Adds a new user to the users file.
fn add_user(users: DashMap<String, User>) -> Result<DashMap<String, User>> {
    let username = prompt_username()?;

    let password = prompt_password(format!("Enter password for user '{username}': "))?;
    let password_again = prompt_password(format!("Confirm password for user '{username}': "))?;

    if password != password_again {
        eprintln!("Passwords do not match");
        exit(1);
    }

    let password_hash = hash_password(password)?;

    users.insert(username.clone(), User::new(username, password_hash));

    Ok(users)
}

/// Removes a user from the users file.
fn remove_user(users: DashMap<String, User>) -> Result<DashMap<String, User>> {
    let username = prompt_username()?;

    match users.remove(&username) {
        Some(_) => Ok(users),
        None => {
            eprintln!("User does not exist: {username}");
            exit(1);
        }
    }
}

/// Prompts the user for a username.
fn prompt_username() -> Result<String> {
    let mut username = String::new();
    print!("Enter the username: ");
    std::io::stdout().flush()?;
    std::io::stdin().read_line(&mut username)?;

    Ok(username.trim_end().to_owned())
}

/// Hashes a password using Argon2.
fn hash_password(password: String) -> Result<String> {
    let argon = Argon2::default();
    let salt = SaltString::generate(&mut OsRng);

    let password_hash = argon
        .hash_password(password.as_bytes(), salt.as_salt())
        .map_err(|e| anyhow!("Failed to hash password: {e}"))?;

    Ok(password_hash.to_string())
}
