#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
pub struct TcpFlags {
    pub urg: bool,
    pub ack: bool,
    pub psh: bool,
    pub rst: bool,
    pub syn: bool,
    pub fin: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub sequence_number: u32,
    pub acknowledgment_number: u32,
    pub data_offset: u8,
    pub flags: TcpFlags,
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
}

impl TcpHeader {
    pub const MIN_HEADER_LEN: usize = 20;

    pub fn parse (data: &[u8]) -> Result<(Self, &[u8]), &'static str> {
        if data.len() < Self::MIN_HEADER_LEN {
            return Err("Data too short for TCP header");
        }

        let src_port = u16::from_be_bytes(data[0..2].try_into().unwrap());
        let dst_port = u16::from_be_bytes(data[2..4].try_into().unwrap());
        let sequence_number = u32::from_be_bytes(data[4..8].try_into().unwrap());
        let acknowledgment_number = u32::from_be_bytes(data[8..12].try_into().unwrap());

        let data_offset_raw = data[12] >> 4;
        if data_offset_raw < 5 {
            return Err("Invalid TCP data offset (less than 5)");
        }
        let data_offset = data_offset_raw * 4;
        let header_len = data_offset as usize;

        if data.len() < header_len {
            return Err("TCP packet smaller than specified header length");
        }

        let flags_byte = data[13];
        let flags = TcpFlags {
            urg: (flags_byte & 0x20) != 0,
            ack: (flags_byte & 0x10) != 0,
            psh: (flags_byte & 0x08) != 0,
            rst: (flags_byte & 0x04) != 0,
            syn: (flags_byte & 0x02) != 0,
            fin: (flags_byte & 0x01) != 0,
        };

        let window_size = u16::from_be_bytes(data[14..16].try_into().unwrap());
        let checksum = u16::from_be_bytes(data[16..18].try_into().unwrap());
        let urgent_pointer = u16::from_be_bytes(data[18..20].try_into().unwrap());

        let header = TcpHeader {
            src_port,
            dst_port,
            sequence_number,
            acknowledgment_number,
            data_offset,
            flags,
            window_size,
            checksum,
            urgent_pointer,
        };

        Ok((header, &data[header_len..]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_tcp_syn_packet() {
        let data = [
            0x04, 0xd2,
            0x00, 0x50,
            0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00,
            0x50,
            0x02,
            0x72, 0x10,
            0x1a, 0x2b,
            0x00, 0x00,
            0xde, 0xad, 0xbe, 0xef,
        ];

        let (hdr, payload) = TcpHeader::parse(&data).unwrap();

        assert_eq!(hdr.src_port, 1234);
        assert_eq!(hdr.dst_port, 80);
        assert_eq!(hdr.sequence_number, 1);
        assert_eq!(hdr.acknowledgment_number, 0);
        assert_eq!(hdr.data_offset, 20);
        assert_eq!(hdr.flags.syn, true);
        assert_eq!(hdr.flags.ack, false);
        assert_eq!(hdr.window_size, 29200);
        assert_eq!(payload, &[0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn parse_tcp_header_too_short() {
        let data = [0x04, 0xd2, 0x00, 0x50];
        assert_eq!(TcpHeader::parse(&data), Err("Data too short for TCP header"));
    }

    #[test]
    fn parse_tcp_invalid_data_offset() {
        let mut data = [0u8; 20];
        data[12] = 0x40;
        assert_eq!(TcpHeader::parse(&data), Err("Invalid TCP data offset (less than 5)"));
    }
}

