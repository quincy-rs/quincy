use std::net::SocketAddr;

use ::tracing::warn;
use socket2::{Domain, Protocol, Socket, Type};

use crate::error::{Result, SocketError};

/// Binds a UDP socket to the given address and sets the send and receive buffer sizes.
///
/// ### Arguments
/// - `addr` - the address to bind the socket to
/// - `send_buffer_size` - the size of the send buffer
/// - `recv_buffer_size` - the size of the receive buffer
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
    socket
        .set_send_buffer_size(send_buffer_size)
        .map_err(|_| SocketError::ConfigFailed {
            option: format!("send buffer size: {send_buffer_size}"),
        })?;
    socket
        .set_recv_buffer_size(recv_buffer_size)
        .map_err(|_| SocketError::ConfigFailed {
            option: format!("recv buffer size: {recv_buffer_size}"),
        })?;

    let buf_size = socket
        .send_buffer_size()
        .map_err(|_| SocketError::ConfigFailed {
            option: "send buffer size query".to_string(),
        })?;
    if buf_size < send_buffer_size {
        warn!(
            "Unable to set desired send buffer size. Desired: {}, Actual: {}",
            send_buffer_size, buf_size
        );
    }

    let buf_size = socket
        .recv_buffer_size()
        .map_err(|_| SocketError::ConfigFailed {
            option: "recv buffer size query".to_string(),
        })?;
    if buf_size < recv_buffer_size {
        warn!(
            "Unable to set desired recv buffer size. Desired: {recv_buffer_size}, Actual: {buf_size}",
        );
    }

    Ok(socket.into())
}
