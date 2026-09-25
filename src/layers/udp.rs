#[derive(Debug, PartialEq, Eq)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
}

impl UdpHeader {
    pub const HEADER_LEN: usize = 8;

    pub fn parse(packet: &[u8]) -> Result<(Self, &[u8]), &'static str> {
        if packet.len() < Self::HEADER_LEN {
            return Err("Packet too short for UDP header");
        }
        
        let src_port = u16::from_be_bytes([packet[0], packet[1]]);
        let dst_port = u16::from_be_bytes([packet[2], packet[3]]);
        let length = u16::from_be_bytes([packet[4], packet[5]]);
        let checksum = u16::from_be_bytes([packet[6], packet[7]]);

        let header = UdpHeader {
            src_port,
            dst_port,
            length,
            checksum,
        };

        Ok((header, &packet[Self::HEADER_LEN..]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_up_packet() {
        let packet = [
            0x04, 0xd2,
            0x00, 0x50,
            0x00, 0x0c,
            0x1a, 0x2b,
            0xde, 0xad, 0xbe, 0xef,
        ];

        let (hdr, payload) = UdpHeader::parse(&packet).unwrap();

        assert_eq!(hdr.src_port, 1234);
        assert_eq!(hdr.dst_port, 80);
        assert_eq!(hdr.length, 12);
        assert_eq!(hdr.checksum, 0x1a2b);
        assert_eq!(payload, &[0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn parse_udp_packet_too_short() {
        let packet = [0x04, 0xd2, 0x00, 0x50];
        assert_eq!(UdpHeader::parse(&packet), Err("Packet too short for UDP header"));
    }
}

