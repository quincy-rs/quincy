use crate::error::NetworkError;
use crate::Result;
use bytes::{Bytes, BytesMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::{Deref, DerefMut};

/// Structure encapsulating a network packet (its data) with additional metadata parsed from the packet.
#[derive(Debug, Clone)]
pub struct Packet {
    pub data: Bytes,
}

impl Packet {
    pub fn new(data: Bytes) -> Self {
        Self { data }
    }

    /// Returns the destination IP address of the packet.
    #[inline]
    pub fn destination(&self) -> Result<IpAddr> {
        if self.is_empty() {
            return Err(NetworkError::PacketError {
                reason: "Packet is empty".to_string(),
            }
            .into());
        }

        let version = self.data[0] >> 4;

        match version {
            4 => {
                let dest_addr = self.parse_ipv4_destination()?;
                Ok(IpAddr::V4(dest_addr))
            }
            6 => {
                let dest_addr = self.parse_ipv6_destination()?;
                Ok(IpAddr::V6(dest_addr))
            }
            _ => Err(NetworkError::PacketError {
                reason: format!("Unsupported IP version: {version}"),
            }
            .into()),
        }
    }

    #[inline]
    fn parse_ipv4_destination(&self) -> Result<Ipv4Addr> {
        if self.data.len() < 20 {
            return Err(NetworkError::PacketError {
                reason: "Packet is too short for IPv4 header".to_string(),
            }
            .into());
        }

        let destination_slice: [u8; 4] = self.data[16..20]
            .try_into()
            .expect("slice has valid length");

        let dest_addr = Ipv4Addr::from(destination_slice);

        Ok(dest_addr)
    }

    #[inline]
    fn parse_ipv6_destination(&self) -> Result<Ipv6Addr> {
        if self.data.len() < 40 {
            return Err(NetworkError::PacketError {
                reason: "Packet is too short for IPv6 header".to_string(),
            }
            .into());
        }

        let destination_slice: [u8; 16] = self.data[24..40]
            .try_into()
            .expect("slice had valid length");

        let dest_addr = Ipv6Addr::from(destination_slice);

        Ok(dest_addr)
    }
}

impl Deref for Packet {
    type Target = Bytes;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl DerefMut for Packet {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

impl From<BytesMut> for Packet {
    fn from(data: BytesMut) -> Self {
        Self::new(data.freeze())
    }
}

impl From<Bytes> for Packet {
    fn from(data: Bytes) -> Self {
        Self::new(data)
    }
}

impl From<Packet> for Bytes {
    fn from(packet: Packet) -> Self {
        packet.data
    }
}
