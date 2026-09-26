use std::env;
use std::fs;
use std::process;

use packet_engine::layers::ethernet::{EtherType, EthernetHeader};
use packet_engine::layers::ipv4::Ipv4Header;
use packet_engine::layers::udp::UdpHeader;
use packet_engine::pcap::reader::PcapReader;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <path-to-pcap-file>", args[0]);
        process::exit(1);
    }

    let pcap_path = &args[1];
    let file_data = match fs::read(pcap_path) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Error reading '{}': {}", pcap_path, e);
            process::exit(1);
        }
    };

    let reader = match PcapReader::new(&file_data) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error parsing PCAP global header: {}", e);
            process::exit(1);
        }
    };

    println!("=== PCAP Global Header ===");
    println!("Snaplen: {} bytes", reader.global_header.snaplen);
    println!("LinkType: {}", reader.global_header.network);
    println!("==========================\n");

    for (idx, packet_result) in reader.enumerate() {
        let packet = match packet_result {
            Ok(p) => p,
            Err(e) => {
                eprintln!("[Packet #{}] Parse error: {}", idx + 1, e);
                break;
            }
        };

        println!(
            "--- Packet #{} [ts: {}.{:06}, cap_len: {} bytes, orig_len: {} bytes] ---",
            idx + 1,
            packet.header.ts_sec,
            packet.header.ts_usec,
            packet.header.incl_len,
            packet.header.orig_len,
        );

        let (eth_hdr, l3_payload) = match EthernetHeader::parse(packet.data) {
            Ok(res) => res,
            Err(e) => {
                println!(" [L2 Error] {}", e);
                continue;
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
            continue;
        }

        let (ip_hdr, l4_payload) = match Ipv4Header::parse(l3_payload) {
            Ok(res) => res,
            Err(e) => {
                eprintln!("[L3 Error] {}", e);
                continue;
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
            continue;
        }

        // 3. Layer 4: UDP
        let (udp_hdr, app_payload) = match UdpHeader::parse(l4_payload) {
            Ok(res) => res,
            Err(e) => {
                eprintln!("[L4 Error] {}", e);
                continue;
            }
        };

        println!(
            "[L4 UDP] Port {} -> {} | Length: {} bytes",
            udp_hdr.src_port,
            udp_hdr.dst_port,
            udp_hdr.length
        );

        // 4. Payload
        println!(
            "[Payload] {} bytes | Raw bytes: {:02x?}",
            app_payload.len(),
            &app_payload[..app_payload.len().min(16)]
        );
    }
}

