#[derive(Debug, PartialEq, Eq)]
pub struct Ipv4Header {
    pub version: u8,
    pub ihl: u8,
    pub ttl: u8,
    pub protocol: u8,
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
}

impl Ipv4Header {
    pub const MIN_HEADER_LEN: usize = 20;

    pub fn parse(packet: &[u8]) -> Result<(Self, &[u8]), &'static str> {
        if packet.len() < Self::MIN_HEADER_LEN {
            return Err("Packet too short for IPv4 header");
        }

        let version = (packet[0] >> 4) & 0x0F;
        let ihl = packet[0] & 0x0F;

        if version != 4 {
            return Err("Unsupported IPv4 version");
        }

        let ttl = packet[8];
        let protocol = packet[9];

        let mut src_ip = [0u8; 4];
        let mut dst_ip = [0u8; 4];
        src_ip.copy_from_slice(&packet[12..16]);
        dst_ip.copy_from_slice(&packet[16..20]);

        let header = Ipv4Header {
            version,
            ihl,
            ttl,
            protocol,
            src_ip,
            dst_ip,
        };
        Ok((header, &packet[Self::MIN_HEADER_LEN..]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ipv4_version_and_ihl() {
        let packet = [
            0x45, 0x00, 0x00, 0x18,
            0x00, 0x00, 0x00, 0x00,
            0x40, 0x06, 0x00, 0x00,
            192, 168, 1, 10,
            192, 168, 1, 20,
            0xde, 0xad, 0xbe, 0xef,
        ];

        let (hdr, payload) = Ipv4Header::parse(&packet).unwrap();

        assert_eq!(hdr.version, 4);
        assert_eq!(hdr.ihl, 5);
        assert_eq!(hdr.ttl, 64);
        assert_eq!(hdr.protocol, 6);
        assert_eq!(hdr.src_ip, [192, 168, 1, 10]);
        assert_eq!(hdr.dst_ip, [192, 168, 1, 20]);
        assert_eq!(payload, &[0xde, 0xad, 0xbe, 0xef]);
    }
}

