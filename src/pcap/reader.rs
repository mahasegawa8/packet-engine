pub const PCAP_MAGIC_IDENTICAL: u32 = 0xa1b2c3d4;
pub const LINKTYPE_ETHERNET: u32 = 1;

#[derive(Debug, PartialEq, Eq)]
pub struct PcapGlobalHeader {
    pub magic_number: u32,
    pub version_major: u16,
    pub version_minor: u16,
    pub thiszone: i32,
    pub sigfigs: u32,
    pub snaplen: u32,
    pub network: u32,
}

impl PcapGlobalHeader {
    pub const HEADER_LEN: usize = 24;

    pub fn parse(data: &[u8]) -> Result<(Self, &[u8]), &'static str> {
        if data.len() < Self::HEADER_LEN {
            return Err("Data too short for PCAP global header");
        }

        let magic_number = u32::from_le_bytes(data[0..4].try_into().unwrap());
        if magic_number != PCAP_MAGIC_IDENTICAL {
            return Err("Unsupported PCAP magic number or endianness");
        }

        let version_major = u16::from_le_bytes(data[4..6].try_into().unwrap());
        let version_minor = u16::from_le_bytes(data[6..8].try_into().unwrap());
        let thiszone = i32::from_le_bytes(data[8..12].try_into().unwrap());
        let sigfigs = u32::from_le_bytes(data[12..16].try_into().unwrap());
        let snaplen = u32::from_le_bytes(data[16..20].try_into().unwrap());
        let network = u32::from_le_bytes(data[20..24].try_into().unwrap());

        let header = PcapGlobalHeader {
            magic_number,
            version_major,
            version_minor,
            thiszone,
            sigfigs,
            snaplen,
            network,
        };

        Ok((header, &data[Self::HEADER_LEN..]))
    }
}
    
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_global_header() {
        let data = [
            0xd4, 0xc3, 0xb2, 0xa1,
            0x02, 0x00,
            0x04, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0xff, 0xff, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00,
            0xde, 0xad, 0xbe, 0xef,
        ];

        let (hdr, remaining) = PcapGlobalHeader::parse(&data).unwrap();

        assert_eq!(hdr.magic_number, PCAP_MAGIC_IDENTICAL);
        assert_eq!(hdr.version_major, 2);
        assert_eq!(hdr.version_minor, 4);
        assert_eq!(hdr.snaplen, 65535);
        assert_eq!(hdr.network, LINKTYPE_ETHERNET);
        assert_eq!(remaining, &[0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn parse_header_too_short() {
        let data = [0xd4, 0xc3, 0xb2, 0xa1];
        assert_eq!(
            PcapGlobalHeader::parse(&data),
            Err("Data too short for PCAP global header")
        );
    }
}

