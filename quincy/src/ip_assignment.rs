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

/// Minimum IPv4 prefix length accepted for an assigned tunnel endpoint.
///
/// Shorter prefixes would install an overly broad on-link route, so they are
/// rejected before a TUN interface is created.
const MINIMUM_ASSIGNMENT_PREFIX_V4: u8 = 8;

/// Minimum IPv6 prefix length accepted for an assigned tunnel endpoint.
///
/// Shorter prefixes would install an overly broad on-link route, so they are
/// rejected before a TUN interface is created.
const MINIMUM_ASSIGNMENT_PREFIX_V6: u8 = 64;

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
/// Rejects loopback, unspecified, multicast, and broadcast addresses, as well as
/// prefixes shorter than the family-specific minimum (`/8` for IPv4, `/64` for
/// IPv6), since those would install an overly broad on-link route.
///
/// ### Arguments
/// - `ipnet` - the IP network to validate
///
/// ### Errors
/// Returns an error if the address or prefix is invalid for tunnel use.
fn validate_assignment_address(ipnet: IpNet) -> Result<()> {
    let addr = ipnet.addr();

    if addr.is_loopback() || addr.is_unspecified() || addr.is_multicast() {
        return Err(AuthError::IpAssignmentFailed.into());
    }

    if let IpAddr::V4(v4) = addr
        && v4.is_broadcast()
    {
        return Err(AuthError::IpAssignmentFailed.into());
    }

    let minimum_prefix = match addr {
        IpAddr::V4(_) => MINIMUM_ASSIGNMENT_PREFIX_V4,
        IpAddr::V6(_) => MINIMUM_ASSIGNMENT_PREFIX_V6,
    };

    if ipnet.prefix_len() < minimum_prefix {
        return Err(AuthError::IpAssignmentFailed.into());
    }

    Ok(())
}

/// Validates that an IP assignment contains safe, usable addresses.
///
/// Rejects assignments where either address is loopback, unspecified,
/// multicast, or broadcast, or whose prefix is shorter than the family-specific
/// minimum. Also requires the client and server to describe exactly the same
/// network: identical prefix lengths and identical networks.
///
/// ### Arguments
/// - `assignment` - the IP assignment to validate
///
/// ### Errors
/// Returns an error if the assignment contains unsafe addresses or inconsistent
/// client/server networks.
fn validate_assignment(assignment: &IpAssignment) -> Result<()> {
    let client = assignment.client_address;
    let server = assignment.server_address;

    validate_assignment_address(client)?;
    validate_assignment_address(server)?;

    if client.prefix_len() != server.prefix_len() || client.network() != server.network() {
        return Err(AuthError::IpAssignmentFailed.into());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::QuincyError;
    use std::str::FromStr;

    fn make_ipv4(addr: &str, prefix: u8) -> IpNet {
        IpNet::from_str(&format!("{}/{}", addr, prefix)).unwrap()
    }

    fn make_ipv6(addr: &str, prefix: u8) -> IpNet {
        IpNet::from_str(&format!("{}/{}", addr, prefix)).unwrap()
    }

    mod validate_assignment_address {
        use super::*;

        #[test]
        fn accepts_valid_ipv4_address() {
            let ipnet = make_ipv4("10.0.0.1", 24);
            assert!(validate_assignment_address(ipnet).is_ok());
        }

        #[test]
        fn accepts_valid_ipv6_address() {
            let ipnet = make_ipv6("fd00::1", 64);
            assert!(validate_assignment_address(ipnet).is_ok());
        }

        #[test]
        fn rejects_ipv4_loopback() {
            let ipnet = make_ipv4("127.0.0.1", 8);
            let result = validate_assignment_address(ipnet);
            assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                QuincyError::Auth(AuthError::IpAssignmentFailed)
            ));
        }

        #[test]
        fn rejects_ipv6_loopback() {
            let ipnet = make_ipv6("::1", 128);
            let result = validate_assignment_address(ipnet);
            assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                QuincyError::Auth(AuthError::IpAssignmentFailed)
            ));
        }

        #[test]
        fn rejects_ipv4_unspecified() {
            let ipnet = make_ipv4("0.0.0.0", 0);
            let result = validate_assignment_address(ipnet);
            assert!(result.is_err());
        }

        #[test]
        fn rejects_ipv6_unspecified() {
            let ipnet = make_ipv6("::", 0);
            let result = validate_assignment_address(ipnet);
            assert!(result.is_err());
        }

        #[test]
        fn rejects_ipv4_multicast() {
            let ipnet = make_ipv4("224.0.0.1", 24);
            let result = validate_assignment_address(ipnet);
            assert!(result.is_err());
        }

        #[test]
        fn rejects_ipv6_multicast() {
            let ipnet = make_ipv6("ff02::1", 64);
            let result = validate_assignment_address(ipnet);
            assert!(result.is_err());
        }

        #[test]
        fn rejects_ipv4_broadcast() {
            let ipnet = make_ipv4("255.255.255.255", 32);
            let result = validate_assignment_address(ipnet);
            assert!(result.is_err());
        }

        #[test]
        fn rejects_zero_prefix_length_ipv4() {
            let ipnet = make_ipv4("10.0.0.1", 0);
            let result = validate_assignment_address(ipnet);
            assert!(result.is_err());
        }

        #[test]
        fn rejects_zero_prefix_length_ipv6() {
            let ipnet = make_ipv6("fd00::1", 0);
            let result = validate_assignment_address(ipnet);
            assert!(result.is_err());
        }

        #[test]
        fn accepts_ipv4_minimum_prefix() {
            let ipnet = make_ipv4("10.0.0.1", 8);
            assert!(validate_assignment_address(ipnet).is_ok());
        }

        #[test]
        fn rejects_ipv4_prefix_below_minimum() {
            let ipnet = make_ipv4("10.0.0.1", 7);
            let result = validate_assignment_address(ipnet);
            assert!(matches!(
                result.unwrap_err(),
                QuincyError::Auth(AuthError::IpAssignmentFailed)
            ));
        }

        #[test]
        fn accepts_ipv6_minimum_prefix() {
            let ipnet = make_ipv6("fd00::1", 64);
            assert!(validate_assignment_address(ipnet).is_ok());
        }

        #[test]
        fn rejects_ipv6_prefix_below_minimum() {
            let ipnet = make_ipv6("fd00::1", 63);
            let result = validate_assignment_address(ipnet);
            assert!(matches!(
                result.unwrap_err(),
                QuincyError::Auth(AuthError::IpAssignmentFailed)
            ));
        }
    }

    mod validate_assignment {
        use super::*;

        #[test]
        fn accepts_valid_assignment_ipv4() {
            let assignment = IpAssignment {
                client_address: make_ipv4("10.0.0.2", 24),
                server_address: make_ipv4("10.0.0.1", 24),
            };
            assert!(validate_assignment(&assignment).is_ok());
        }

        #[test]
        fn accepts_valid_assignment_ipv6() {
            let assignment = IpAssignment {
                client_address: make_ipv6("fd00::2", 64),
                server_address: make_ipv6("fd00::1", 64),
            };
            assert!(validate_assignment(&assignment).is_ok());
        }

        #[test]
        fn rejects_client_not_in_server_subnet_ipv4() {
            let assignment = IpAssignment {
                client_address: make_ipv4("10.0.0.2", 24),
                server_address: make_ipv4("192.168.1.1", 24),
            };
            let result = validate_assignment(&assignment);
            assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                QuincyError::Auth(AuthError::IpAssignmentFailed)
            ));
        }

        #[test]
        fn rejects_client_not_in_server_subnet_ipv6() {
            let assignment = IpAssignment {
                client_address: make_ipv6("fd00::2", 64),
                server_address: make_ipv6("fd01::1", 64),
            };
            let result = validate_assignment(&assignment);
            assert!(result.is_err());
        }

        #[test]
        fn rejects_server_not_in_client_subnet_ipv4() {
            let assignment = IpAssignment {
                client_address: make_ipv4("10.0.0.2", 24),
                server_address: make_ipv4("10.0.1.1", 24),
            };
            let result = validate_assignment(&assignment);
            assert!(result.is_err());
        }

        #[test]
        fn rejects_different_subnets_with_same_prefix() {
            let assignment = IpAssignment {
                client_address: make_ipv4("10.0.1.2", 24),
                server_address: make_ipv4("10.0.2.1", 24),
            };
            let result = validate_assignment(&assignment);
            assert!(result.is_err());
        }

        #[test]
        fn rejects_assignment_with_loopback_client() {
            let assignment = IpAssignment {
                client_address: make_ipv4("127.0.0.1", 8),
                server_address: make_ipv4("10.0.0.1", 24),
            };
            let result = validate_assignment(&assignment);
            assert!(result.is_err());
        }

        #[test]
        fn rejects_assignment_with_loopback_server() {
            let assignment = IpAssignment {
                client_address: make_ipv4("10.0.0.2", 24),
                server_address: make_ipv4("127.0.0.1", 8),
            };
            let result = validate_assignment(&assignment);
            assert!(result.is_err());
        }

        #[test]
        fn rejects_assignment_with_unspecified_client() {
            let assignment = IpAssignment {
                client_address: make_ipv4("0.0.0.0", 24),
                server_address: make_ipv4("10.0.0.1", 24),
            };
            let result = validate_assignment(&assignment);
            assert!(result.is_err());
        }

        #[test]
        fn rejects_assignment_with_multicast_client() {
            let assignment = IpAssignment {
                client_address: make_ipv4("224.0.0.1", 24),
                server_address: make_ipv4("10.0.0.1", 24),
            };
            let result = validate_assignment(&assignment);
            assert!(result.is_err());
        }

        #[test]
        fn rejects_assignment_with_broadcast_server() {
            let assignment = IpAssignment {
                client_address: make_ipv4("10.0.0.2", 24),
                server_address: make_ipv4("255.255.255.255", 32),
            };
            let result = validate_assignment(&assignment);
            assert!(result.is_err());
        }

        #[test]
        fn rejects_assignment_with_zero_prefix_client() {
            let assignment = IpAssignment {
                client_address: make_ipv4("10.0.0.2", 0),
                server_address: make_ipv4("10.0.0.1", 0),
            };
            let result = validate_assignment(&assignment);
            assert!(result.is_err());
        }

        #[test]
        fn rejects_reported_asymmetric_short_prefix() {
            let assignment = IpAssignment {
                client_address: make_ipv4("10.0.0.2", 1),
                server_address: make_ipv4("10.0.0.1", 24),
            };
            let result = validate_assignment(&assignment);
            assert!(matches!(
                result.unwrap_err(),
                QuincyError::Auth(AuthError::IpAssignmentFailed)
            ));
        }

        #[test]
        fn rejects_symmetric_ipv4_short_prefix() {
            let assignment = IpAssignment {
                client_address: make_ipv4("10.0.0.2", 1),
                server_address: make_ipv4("10.0.0.1", 1),
            };
            let result = validate_assignment(&assignment);
            assert!(matches!(
                result.unwrap_err(),
                QuincyError::Auth(AuthError::IpAssignmentFailed)
            ));
        }

        #[test]
        fn rejects_symmetric_ipv6_short_prefix() {
            let assignment = IpAssignment {
                client_address: make_ipv6("fd00::2", 1),
                server_address: make_ipv6("fd00::1", 1),
            };
            let result = validate_assignment(&assignment);
            assert!(matches!(
                result.unwrap_err(),
                QuincyError::Auth(AuthError::IpAssignmentFailed)
            ));
        }

        #[test]
        fn rejects_ipv6_asymmetric_prefix() {
            let assignment = IpAssignment {
                client_address: make_ipv6("fd00::2", 64),
                server_address: make_ipv6("fd00::1", 65),
            };
            let result = validate_assignment(&assignment);
            assert!(matches!(
                result.unwrap_err(),
                QuincyError::Auth(AuthError::IpAssignmentFailed)
            ));
        }

        #[test]
        fn rejects_mismatched_prefix_lengths_in_same_network() {
            let assignment = IpAssignment {
                client_address: make_ipv4("10.0.0.2", 24),
                server_address: make_ipv4("10.0.0.1", 16),
            };
            let result = validate_assignment(&assignment);
            assert!(matches!(
                result.unwrap_err(),
                QuincyError::Auth(AuthError::IpAssignmentFailed)
            ));
        }

        #[test]
        fn accepts_ipv4_minimum_prefix_assignment() {
            let assignment = IpAssignment {
                client_address: make_ipv4("10.0.0.2", 8),
                server_address: make_ipv4("10.0.0.1", 8),
            };
            assert!(validate_assignment(&assignment).is_ok());
        }

        #[test]
        fn accepts_ipv6_minimum_prefix_assignment() {
            let assignment = IpAssignment {
                client_address: make_ipv6("fd00::2", 64),
                server_address: make_ipv6("fd00::1", 64),
            };
            assert!(validate_assignment(&assignment).is_ok());
        }
    }
}
