use std::path::Path;

use holo_bgp::{
    neighbor::PeerType,
    packet::message::{DecodeCxt, Message as Packet, NegotiatedCapability},
};
use yaml_rust2::YamlLoader;
fn test_correct_pass(bytes: &[u8]) -> Result<String, ()> {
    let cxt = DecodeCxt {
        peer_type: PeerType::Internal,
        peer_as: 65550,
        reject_as_sets: true,
        capabilities: [NegotiatedCapability::FourOctetAsNumber].into(),
    };
    let packet = Packet::decode(bytes, &cxt);
    // packet should decode without error or panic
    if packet.is_err() {
        println!("!!Failed to decode packet: {:?}", packet);
        return Err(());
    }
    Ok(format!("Decoded packet: {:?}", packet.unwrap()))
}

fn test_incorrect_fail(bytes: &[u8]) -> Result<String, ()> {
    let cxt = DecodeCxt {
        peer_type: PeerType::Internal,
        peer_as: 65550,
        reject_as_sets: true,
        capabilities: [NegotiatedCapability::FourOctetAsNumber].into(),
    };
    let packet = Packet::decode(bytes, &cxt);
    // packet should fail to decode
    if packet.is_ok() {
        println!(
            "!!Unexpected decoded packet: {:?}",
            packet.as_ref().unwrap()
        );
        return Err(());
    }
    Ok(format!("Failed to decode packet as expected: {:?}", packet))
}

fn load_packet_bytes_from_yaml(_yaml_file: &str) -> Vec<(String, Vec<u8>)> {
    // Read the YAML file and parse packet bytes.
    // use yaml-rust2 to read the file and extract packet bytes.
    let mut packets = Vec::new();
    let contents =
        std::fs::read_to_string(_yaml_file).expect("Failed to read YAML file");
    let docs =
        YamlLoader::load_from_str(&contents).expect("Failed to parse YAML");
    // expecting a list of packets. It should look like:
    // packets:
    //   - /path/to/packet1.bin (should be absolute path)
    //   - /path/to/packet2.bin
    //   - ...
    let packet_list = &docs[0]["packets"];
    for packet_yaml in packet_list.as_vec().unwrap() {
        let packet_path = packet_yaml.as_str().unwrap();
        let packet_path = Path::new(packet_path);
        let last_4_layers_str = packet_path
            .components()
            .rev()
            .take(4)
            .map(|c| c.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
            .join("/");
        // println!("Loading packet from path: {}", packet_path);
        let packet_bytes =
            std::fs::read(packet_path).expect("Failed to read packet file");
        packets.push((last_4_layers_str, packet_bytes));
    }
    packets
}

#[test]
fn test_correct_pass_packets() {
    let args: Vec<String> = std::env::args().collect();
    // the last argument should be a yaml file containing packets' paths to test
    let yaml_file = args.last().unwrap();
    let mut success = true;
    for packet_bytes in load_packet_bytes_from_yaml(yaml_file) {
        match test_correct_pass(&packet_bytes.1) {
            Ok(msg) => println!("{}", msg),
            Err(_) => {
                success = false;
            }
        }
    }
    assert!(success);
}

#[test]
fn test_incorrect_fail_packets() {
    let args: Vec<String> = std::env::args().collect();
    // Process args here
    // the second last argument should be a yaml file containing packets' paths to test
    let mut success = true;
    let yaml_file = args[args.len() - 2].as_str();
    for packet_bytes in load_packet_bytes_from_yaml(yaml_file) {
        match test_incorrect_fail(&packet_bytes.1) {
            Ok(msg) => println!("{}", msg),
            Err(_) => {
                println!("Packet name: {:?}", packet_bytes.0);
                success = false;
            }
        }
    }
    assert!(success);
}
