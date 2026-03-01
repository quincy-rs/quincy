//! IP assignment protocol over QUIC uni-directional streams.
//!
//! After the QUIC handshake completes (which includes authentication via Noise
//! allowed-keys or TLS mTLS), the server opens a uni-directional stream to send
//! the client its assigned IP address and the server's tunnel address.

use std::{net::IpAddr, time::Duration};

use ipnet::IpNet;
use quinn::Connection;
use serde::{Deserialize, Serialize};
use tokio::time::timeout;

use crate::error::{AuthError, Result};

/// IP assignment payload sent from server to client after authentication.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IpAssignment {
    /// The IP address assigned to the client (with network mask).
    pub client_address: IpNet,
    /// The server's tunnel address (with network mask).
    pub server_address: IpNet,
}

/// Sends an IP assignment to the client over a QUIC uni-directional stream.
///
/// Opens a new uni-stream on the connection, serializes the assignment as JSON,
/// writes it, and finishes the stream.
///
/// ### Arguments
/// - `connection` - the established QUIC connection
/// - `assignment` - the IP assignment to send
/// - `duration` - timeout for the entire operation
///
/// ### Errors
/// Returns an error if the stream cannot be opened, the write fails, or the
/// operation times out.
pub async fn send_ip_assignment(
    connection: &Connection,
    assignment: &IpAssignment,
    duration: Duration,
) -> Result<()> {
    timeout(duration, async {
        let mut send_stream = connection
            .open_uni()
            .await
            .map_err(|_| AuthError::IpAssignmentFailed)?;

        let payload = serde_json::to_vec(assignment)?;
        send_stream.write_all(&payload).await?;
        send_stream
            .finish()
            .map_err(|_| AuthError::IpAssignmentFailed)?;

        Ok::<(), crate::error::QuincyError>(())
    })
    .await
    .map_err(|_| AuthError::Timeout)?
}

/// Receives an IP assignment from the server over a QUIC uni-directional stream.
///
/// Accepts a uni-stream, reads the full payload, and deserializes the IP assignment.
///
/// ### Arguments
/// - `connection` - the established QUIC connection
/// - `duration` - timeout for the entire operation
///
/// ### Returns
/// The received `IpAssignment` containing the client and server addresses.
///
/// ### Errors
/// Returns an error if no stream is received, the read fails, deserialization fails,
/// or the operation times out.
pub async fn recv_ip_assignment(
    connection: &Connection,
    duration: Duration,
) -> Result<IpAssignment> {
    timeout(duration, async {
        let mut recv_stream = connection
            .accept_uni()
            .await
            .map_err(|_| AuthError::IpAssignmentFailed)?;

        let payload = recv_stream
            .read_to_end(4096)
            .await
            .map_err(|_| AuthError::IpAssignmentFailed)?;

        let assignment: IpAssignment = serde_json::from_slice(&payload)?;

        validate_assignment(&assignment)?;

        Ok::<IpAssignment, crate::error::QuincyError>(assignment)
    })
    .await
    .map_err(|_| AuthError::Timeout)?
}

/// Validates that an IP assignment address is safe for use as a tunnel endpoint.
///
/// Rejects loopback, unspecified, multicast, and broadcast addresses,
/// as well as networks with a zero prefix length (which would capture all traffic).
///
/// ### Arguments
/// - `ipnet` - the IP network to validate
///
/// ### Errors
/// Returns an error if the address is invalid for tunnel use.
fn validate_assignment_address(ipnet: IpNet) -> Result<()> {
    let addr = ipnet.addr();

    if addr.is_loopback() || addr.is_unspecified() || addr.is_multicast() {
        return Err(AuthError::IpAssignmentFailed.into());
    }

    if let IpAddr::V4(v4) = addr {
        if v4.is_broadcast() {
            return Err(AuthError::IpAssignmentFailed.into());
        }
    }

    if ipnet.prefix_len() == 0 {
        return Err(AuthError::IpAssignmentFailed.into());
    }

    Ok(())
}

/// Validates that an IP assignment contains safe, usable addresses.
///
/// Rejects assignments where either address is loopback, unspecified,
/// multicast, or broadcast. Also validates that addresses share the same
/// subnet and have non-zero prefix lengths.
///
/// ### Arguments
/// - `assignment` - the IP assignment to validate
///
/// ### Errors
/// Returns an error if the assignment contains unsafe addresses.
fn validate_assignment(assignment: &IpAssignment) -> Result<()> {
    let client = assignment.client_address;
    let server = assignment.server_address;

    validate_assignment_address(client)?;
    validate_assignment_address(server)?;

    // Validate that client and server are in the same subnet
    if !client.contains(&server.addr()) || !server.contains(&client.addr()) {
        return Err(AuthError::IpAssignmentFailed.into());
    }

    Ok(())
}
