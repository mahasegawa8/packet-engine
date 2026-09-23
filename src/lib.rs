#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct MacAddress(pub [u8; 6]);

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum EtherType {
    IPv4,
    Arp,
    IPv6,
    Unknown(u16),
}

impl EtherType {
    pub const IPV4: u16 = 0x0800;
    pub const ARP: u16 = 0x0806;
    pub const IPV6: u16 = 0x86DD;
}

impl From<u16> for EtherType {
    fn from(val: u16) -> Self {
        match val {
            Self::IPV4 => EtherType::IPv4,
            Self::ARP => EtherType::Arp,
            Self::IPV6 => EtherType::IPv6,
            other => EtherType::Unknown(other),
        }
    }
}

impl From<EtherType> for u16 {
    fn from(ether_type: EtherType) -> Self {
        match ether_type {
            EtherType::IPv4 => EtherType::IPV4,
            EtherType::Arp => EtherType::ARP,
            EtherType::IPv6 => EtherType::IPV6,
            EtherType::Unknown(val) => val,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct EthernetHeader {
    pub dst: MacAddress,
    pub src: MacAddress,
    pub ether_type: EtherType,
}

impl EthernetHeader {
    pub const HEADER_LEN: usize = 14;

    /// Parses an Ethernet header from a raw byte slice without heap allocation,
    /// returning the parsed header and the remaining payload slice.
    pub fn parse(packet: &[u8]) -> Result<(Self, &[u8]), &'static str> {
        if packet.len() < Self::HEADER_LEN {
            return Err("Frame too short for Ethernet header");
        }

        let mut dst = [0u8; 6];
        let mut src = [0u8; 6];
        dst.copy_from_slice(&packet[0..6]);
        src.copy_from_slice(&packet[6..12]);

        // Convert big-endian bytes (network byte order) to host u16
        let ether_type_raw = u16::from_be_bytes([packet[12], packet[13]]);
        let ether_type = EtherType::from(ether_type_raw);

        let header = EthernetHeader {
            dst: MacAddress(dst),
            src: MacAddress(src),
            ether_type,
        };

        // Return parsed header and zero-copy slice of the payload
        Ok((header, &packet[Self::HEADER_LEN..]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_ipv4_frame() {
        // Raw Ethernet frame: 14 bytes header + dummy payload
        let frame: [u8; 18] = [
            0x52, 0x54, 0x00, 0x12, 0x34, 0x56, // Destination MAC
            0x08, 0x00, 0x27, 0xaa, 0xbb, 0xcc, // Source MAC
            0x08, 0x00,                         // EtherType: IPv4
            0xde, 0xad, 0xbe, 0xef,             // Dummy L3 payload
        ];

        let (hdr, payload) = EthernetHeader::parse(&frame).unwrap();

        assert_eq!(hdr.dst, MacAddress([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]));
        assert_eq!(hdr.src, MacAddress([0x08, 0x00, 0x27, 0xaa, 0xbb, 0xcc]));
        assert_eq!(hdr.ether_type, EtherType::IPv4);
        assert_eq!(payload, &[0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn parse_valid_arp_frame() {
        let frame: [u8; 14] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x08, 0x06,
        ];

        let (hdr, payload) = EthernetHeader::parse(&frame).unwrap();

        assert_eq!(hdr.dst, MacAddress([0xff, 0xff, 0xff, 0xff, 0xff, 0xff]));
        assert_eq!(hdr.src, MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]));
        assert_eq!(hdr.ether_type, EtherType::Arp);
        assert!(payload.is_empty());
    }

    #[test]
    fn parse_unknown_ethertype() {
        let frame: [u8; 14] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x88, 0xb5, // IEEE 802.1 Local Experimental EtherType
        ];

        let (hdr, _) = EthernetHeader::parse(&frame).unwrap();
        assert_eq!(hdr.ether_type, EtherType::Unknown(0x88b5));
    }

    #[test]
    fn parse_frame_too_short() {
        let short_frame = [0u8; 13];
        assert_eq!(
            EthernetHeader::parse(&short_frame),
            Err("Frame too short for Ethernet header")
        );
    }
}

