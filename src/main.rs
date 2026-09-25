use packet_engine::layers::ethernet::{EtherType, EthernetHeader};
use packet_engine::layers::ipv4::Ipv4Header;
use packet_engine::layers::udp::UdpHeader;

fn main() {
    // Ethernet (14 bytes) + IPv4 (20 bytes) + UDP (8 bytes) + Payload
    let raw_packet: [u8; 46] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        0x08, 0x00,

        0x45,
        0x00,
        0x00, 0x20,
        0x12, 0x34,
        0x40, 0x00,
        0x40,
        0x11,
        0x00, 0x00,
        192, 168, 1, 100,
        10, 0, 0, 1,

        0x1f, 0x90,
        0x00, 0x35,
        0x00, 0x0c,
        0x00, 0x00,

        0x50, 0x49, 0x4e, 0x47,
    ];

    println!("=== Packet Engine: Zero-Copy Pipeline ===");

    let (eth_hdr, l3_payload) = match EthernetHeader::parse(&raw_packet) {
        Ok(res) => res,
        Err(e) => {
            eprintln!("[L2 Error] {}", e);
            return;
        }
    };
    let s = eth_hdr.src.0;
    let d = eth_hdr.dst.0;
    println!(
        "[L2 Ethernet] {:02x?}:{:02x?}:{:02x?}:{:02x?}:{:02x?}:{:02x?} -> {:02x?}:{:02x?}:{:02x?}:{:02x?}:{:02x?}:{:02x?} | Type: {:?}",
        s[0], s[1], s[2], s[3], s[4], s[5],
        d[0], d[1], d[2], d[3], d[4], d[5],
        eth_hdr.ether_type
    );

    if eth_hdr.ether_type != EtherType::IPv4 {
        println!("[L3] Non-IPv4 packet skipped");
        return;
    }

    let (ip_hdr, l4_payload) = match Ipv4Header::parse(l3_payload) {
        Ok(res) => res,
        Err(e) => {
            eprintln!("[L3 Error] {}", e);
            return;
        }
    };
    println!(
        "[L3 IPv4] {}.{}.{}.{} -> {}.{}.{}.{} | Protocol: {} | TTL: {}",
        ip_hdr.src_ip[0], ip_hdr.src_ip[1], ip_hdr.src_ip[2], ip_hdr.src_ip[3],
        ip_hdr.dst_ip[0], ip_hdr.dst_ip[1], ip_hdr.dst_ip[2], ip_hdr.dst_ip[3],
        ip_hdr.protocol,
        ip_hdr.ttl
    );

    if ip_hdr.protocol  != 17 {
        println!("[L4] Non-UDP packet skipped");
        return;
    }

    let (udp_hdr, app_payload) = match UdpHeader::parse(l4_payload) {
        Ok(res) => res,
        Err(e) => {
            eprintln!("[L4 Error] {}", e);
            return;
        }
    };
    println!(
        "[L4 UDP] Port {} -> {} | Length: {} bytes",
        udp_hdr.src_port,
        udp_hdr.dst_port,
        udp_hdr.length
    );

    let payload_str = String::from_utf8_lossy(app_payload);
    println!("[Payload] Raw bytes: {:02x?} | UTF-8: \"{}\"", app_payload, payload_str);
}

