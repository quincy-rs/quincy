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

    /// Returns the source IP address of the packet.
    #[inline]
    pub fn source(&self) -> Result<IpAddr> {
        if self.is_empty() {
            return Err(NetworkError::PacketError {
                reason: "Packet is empty".to_string(),
            }
            .into());
        }

        let version = self.data[0] >> 4;

        match version {
            4 => {
                let dest_addr = self.parse_ipv4_source()?;
                Ok(IpAddr::V4(dest_addr))
            }
            6 => {
                let dest_addr = self.parse_ipv6_source()?;
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

    #[inline]
    fn parse_ipv4_source(&self) -> Result<Ipv4Addr> {
        if self.data.len() < 20 {
            return Err(NetworkError::PacketError {
                reason: "Packet is too short for IPv4 header".to_string(),
            }
            .into());
        }

        let source_slice: [u8; 4] = self.data[12..16]
            .try_into()
            .expect("slice has valid length");

        let source_addr = Ipv4Addr::from(source_slice);

        Ok(source_addr)
    }

    #[inline]
    fn parse_ipv6_source(&self) -> Result<Ipv6Addr> {
        if self.data.len() < 40 {
            return Err(NetworkError::PacketError {
                reason: "Packet is too short for IPv6 header".to_string(),
            }
            .into());
        }

        let source_slice: [u8; 16] = self.data[8..24].try_into().expect("slice had valid length");

        let source_addr = Ipv6Addr::from(source_slice);

        Ok(source_addr)
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

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::{Ipv4Header, Ipv6Header};

    fn create_ipv4_packet(src: Ipv4Addr, dst: Ipv4Addr) -> Bytes {
        let mut header =
            Ipv4Header::new(0, 64, etherparse::IpNumber::UDP, src.octets(), dst.octets()).unwrap();
        header.header_checksum = header.calc_header_checksum();
        let mut buf = Vec::with_capacity(header.header_len());
        header.write(&mut std::io::Cursor::new(&mut buf)).unwrap();
        Bytes::from(buf)
    }

    fn create_ipv6_packet(src: Ipv6Addr, dst: Ipv6Addr) -> Bytes {
        let header = Ipv6Header {
            traffic_class: 0,
            flow_label: etherparse::Ipv6FlowLabel::try_new(0).unwrap(),
            payload_length: 0,
            next_header: etherparse::IpNumber::UDP,
            hop_limit: 64,
            source: src.octets(),
            destination: dst.octets(),
        };
        let mut buf = Vec::with_capacity(40);
        header.write(&mut std::io::Cursor::new(&mut buf)).unwrap();
        Bytes::from(buf)
    }

    #[test]
    fn test_ipv4_destination() {
        let src = Ipv4Addr::new(192, 168, 1, 100);
        let dst = Ipv4Addr::new(10, 0, 0, 1);
        let packet = Packet::new(create_ipv4_packet(src, dst));

        let result = packet.destination().unwrap();
        assert_eq!(result, IpAddr::V4(dst));
    }

    #[test]
    fn test_ipv4_source() {
        let src = Ipv4Addr::new(192, 168, 1, 100);
        let dst = Ipv4Addr::new(10, 0, 0, 1);
        let packet = Packet::new(create_ipv4_packet(src, dst));

        let result = packet.source().unwrap();
        assert_eq!(result, IpAddr::V4(src));
    }

    #[test]
    fn test_ipv6_destination() {
        let src = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 2);
        let packet = Packet::new(create_ipv6_packet(src, dst));

        let result = packet.destination().unwrap();
        assert_eq!(result, IpAddr::V6(dst));
    }

    #[test]
    fn test_ipv6_source() {
        let src = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 2);
        let packet = Packet::new(create_ipv6_packet(src, dst));

        let result = packet.source().unwrap();
        assert_eq!(result, IpAddr::V6(src));
    }

    #[test]
    fn test_empty_packet_destination() {
        let packet = Packet::new(Bytes::from(vec![]));

        let result = packet.destination();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Packet is empty"));
    }

    #[test]
    fn test_empty_packet_source() {
        let packet = Packet::new(Bytes::from(vec![]));

        let result = packet.source();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Packet is empty"));
    }

    #[test]
    fn test_unsupported_ip_version_destination() {
        let mut data = vec![0u8; 20];
        data[0] = 0x50;
        let packet = Packet::new(Bytes::from(data));

        let result = packet.destination();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Unsupported IP version"));
    }

    #[test]
    fn test_unsupported_ip_version_source() {
        let mut data = vec![0u8; 20];
        data[0] = 0x50;
        let packet = Packet::new(Bytes::from(data));

        let result = packet.source();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Unsupported IP version"));
    }

    #[test]
    fn test_ipv4_header_too_short_destination() {
        let mut data = vec![0x45];
        data.extend_from_slice(&[0u8; 18]);
        let packet = Packet::new(Bytes::from(data));

        let result = packet.destination();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("too short for IPv4 header"));
    }

    #[test]
    fn test_ipv4_header_too_short_source() {
        let mut data = vec![0x45];
        data.extend_from_slice(&[0u8; 18]);
        let packet = Packet::new(Bytes::from(data));

        let result = packet.source();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("too short for IPv4 header"));
    }

    #[test]
    fn test_ipv6_header_too_short_destination() {
        let mut data = vec![0x60];
        data.extend_from_slice(&[0u8; 38]);
        let packet = Packet::new(Bytes::from(data));

        let result = packet.destination();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("too short for IPv6 header"));
    }

    #[test]
    fn test_ipv6_header_too_short_source() {
        let mut data = vec![0x60];
        data.extend_from_slice(&[0u8; 38]);
        let packet = Packet::new(Bytes::from(data));

        let result = packet.source();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("too short for IPv6 header"));
    }

    #[test]
    fn test_deref() {
        let data = Bytes::from(vec![1, 2, 3, 4]);
        let packet = Packet::new(data.clone());

        assert_eq!(&*packet, &data);
    }

    #[test]
    fn test_deref_mut() {
        let data = BytesMut::from(&[1, 2, 3, 4][..]);
        let mut packet = Packet::from(data);
        let packet_mut: &mut Bytes = &mut packet;
        assert_eq!(packet_mut.len(), 4);
    }

    #[test]
    fn test_from_bytes_mut() {
        let bytes_mut = BytesMut::from(&[1, 2, 3, 4][..]);
        let packet = Packet::from(bytes_mut);

        assert_eq!(&*packet, &[1, 2, 3, 4][..]);
    }

    #[test]
    fn test_from_bytes() {
        let bytes = Bytes::from(vec![1, 2, 3, 4]);
        let packet = Packet::from(bytes.clone());

        assert_eq!(&*packet, &bytes);
    }

    #[test]
    fn test_into_bytes() {
        let data = Bytes::from(vec![1, 2, 3, 4]);
        let packet = Packet::new(data.clone());
        let result: Bytes = packet.into();

        assert_eq!(result, data);
    }
}
