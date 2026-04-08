use std::net::SocketAddr;

use socket2::{Domain, Protocol, Socket, Type};
use tracing::warn;

use crate::constants::MIN_SOCKET_BUFFER_SIZE;
use crate::error::{Result, SocketError};

/// Binds a UDP socket to the given address and sets the send and receive buffer sizes.
///
/// Buffer sizes are set on a best-effort basis - if the OS rejects the requested
/// size with `ENOBUFS` (e.g. FreeBSD when the value exceeds system limits),
/// the function halves the request repeatedly until it is accepted or
/// [`MIN_SOCKET_BUFFER_SIZE`] is reached. Other errors are propagated
/// immediately.
///
/// ### Arguments
/// - `addr` - the address to bind the socket to
/// - `send_buffer_size` - the desired size of the send buffer
/// - `recv_buffer_size` - the desired size of the receive buffer
/// - `reuse_socket` - whether to reuse the socket across multiple Quincy instances
///
/// ### Returns
/// - `std::net::UdpSocket` - the bound socket
pub fn bind_socket(
    addr: SocketAddr,
    send_buffer_size: usize,
    recv_buffer_size: usize,
    reuse_socket: bool,
) -> Result<std::net::UdpSocket> {
    let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))
        .map_err(|_| SocketError::CreationFailed)?;

    if addr.is_ipv6() {
        socket
            .set_only_v6(false)
            .map_err(|_| SocketError::ConfigFailed {
                option: "dual-stack (not IPv6-only)".to_string(),
            })?;
    }

    if reuse_socket {
        socket
            .set_reuse_address(true)
            .map_err(|_| SocketError::ConfigFailed {
                option: "SO_REUSEADDR".to_string(),
            })?;

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        socket
            .set_reuse_port(true)
            .map_err(|_| SocketError::ConfigFailed {
                option: "SO_REUSEPORT".to_string(),
            })?;

        #[cfg(target_os = "freebsd")]
        socket
            .set_reuse_port_lb(true)
            .map_err(|_| SocketError::ConfigFailed {
                option: "SO_REUSEPORT_LB".to_string(),
            })?;
    }

    socket
        .bind(&socket2::SockAddr::from(addr))
        .map_err(|_| SocketError::BindFailed {
            address: addr.to_string(),
        })?;

    try_set_buffer_size(
        &socket,
        send_buffer_size,
        Socket::set_send_buffer_size,
        Socket::send_buffer_size,
        "send buffer size",
    )?;
    try_set_buffer_size(
        &socket,
        recv_buffer_size,
        Socket::set_recv_buffer_size,
        Socket::recv_buffer_size,
        "recv buffer size",
    )?;

    Ok(socket.into())
}

/// Tries to set a socket buffer size. On `ENOBUFS`, halves the request
/// repeatedly until it is accepted or [`MIN_SOCKET_BUFFER_SIZE`] is reached.
/// Other errors are propagated. Emits at most one warning.
fn try_set_buffer_size(
    socket: &Socket,
    requested: usize,
    set_fn: fn(&Socket, usize) -> std::io::Result<()>,
    get_fn: fn(&Socket) -> std::io::Result<usize>,
    label: &str,
) -> Result<()> {
    if try_set_fn(socket, requested, set_fn, label)? {
        if let Ok(actual) = get_fn(socket) {
            if actual < requested {
                warn!("Unable to set desired {label}. Desired: {requested}, Actual: {actual}",);
            }
        }
        return Ok(());
    }

    // ENOBUFS — halve repeatedly until accepted or the floor is reached.
    let mut size = (requested / 2).max(MIN_SOCKET_BUFFER_SIZE);
    while size >= MIN_SOCKET_BUFFER_SIZE {
        if try_set_fn(socket, size, set_fn, label)? {
            warn!("Reduced {label} from {requested} to {size} due to OS buffer size limits",);
            return Ok(());
        }
        size /= 2;
    }

    // Every attempt failed — fall back to the OS default.
    warn!("Failed to set {label} (requested {requested}); using OS default");
    Ok(())
}

/// Calls `set_fn` and returns `Ok(true)` on success, `Ok(false)` on `ENOBUFS`,
/// or propagates any other error as `SocketError::ConfigFailed`.
fn try_set_fn(
    socket: &Socket,
    size: usize,
    set_fn: fn(&Socket, usize) -> std::io::Result<()>,
    label: &str,
) -> Result<bool> {
    match set_fn(socket, size) {
        Ok(()) => Ok(true),
        Err(e) if e.raw_os_error().is_some_and(|e| e == libc::ENOBUFS) => Ok(false),
        Err(_) => Err(SocketError::ConfigFailed {
            option: format!("{label}: {size}"),
        }
        .into()),
    }
}
