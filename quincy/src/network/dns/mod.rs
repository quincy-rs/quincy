#[cfg(target_os = "macos")]
mod darwin;
#[cfg(target_os = "macos")]
pub use darwin::{add_dns_servers, delete_dns_servers};

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
mod linux;
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
pub use linux::{add_dns_servers, delete_dns_servers};

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use windows::{add_dns_servers, delete_dns_servers};
