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

        if ihl < 5 {
            return Err("Invalid IPv4 header length (IHL must be >= 5)");
        }

        let header_len = (ihl as usize) * 4;
        if packet.len() < header_len {
            return Err("Packet too short for IPv4 options");
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

        Ok((header, &packet[header_len..]))
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

    #[test]
    fn parse_ipv4_with_options() {
        let packet = [
            0x46, 0x00, 0x00, 0x1c,
            0x00, 0x00, 0x00, 0x00,
            0x40, 0x06, 0x00, 0x00,
            192, 168, 1, 10,
            192, 168, 1, 20,
            0x01, 0x01, 0x01, 0x01,
            0xaa, 0xbb, 0xcc, 0xdd,
        ];

        let (hdr, payload) = Ipv4Header::parse(&packet).unwrap();

        assert_eq!(hdr.ihl, 6);
        assert_eq!(payload, &[0xaa, 0xbb, 0xcc, 0xdd]);
    }

    #[test]
    fn parse_ipv4_invalid_ihl() {
        let mut packet = [0u8; 20];
        packet[0] = 0x44;

        assert_eq!(
            Ipv4Header::parse(&packet),
            Err("Invalid IPv4 header length (IHL must be >= 5)")
        );
    }
}

