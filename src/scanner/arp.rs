use pcap::{Capture, Device};
use macaddr::MacAddr6;
use ipnetwork::IpNetwork;
use std::net::{IpAddr, Ipv4Addr};
use std::collections::{HashSet, HashMap};
use std::time::Duration;
use serde::Serialize;
use tokio::time::sleep;
use pnet::datalink;
use pnet_packet::arp::{ArpHardwareTypes, ArpOperations, MutableArpPacket};
use pnet_packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet_packet::Packet;
use std::convert::TryInto;
use std::fs::File;
use std::io::{BufRead, BufReader};

#[derive(Serialize, Debug)]
pub struct DiscoveredDevice {
    pub ip: Ipv4Addr,
    pub mac: String,
    pub vendor: Option<String>,
}

pub fn list_interfaces() -> Result<(), Box<dyn std::error::Error>> {
    let devices = Device::list()?;
    for d in devices {
        println!("{}: {:?}", d.name, d.desc);
    }
    Ok(())
}

fn load_ieee_oui(csv_path: &str) -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
    let file = File::open(csv_path)?;
    let reader = BufReader::new(file);
    let mut map = HashMap::new();
    for line in reader.lines().skip(1) { // skip header
        let line = line?;
        let parts: Vec<&str> = line.split(',').collect();
        if parts.len() > 2 {
            // "MA-L","28-ED-6A","Xiaomi Communications Co Ltd"
            let prefix = parts[1].replace("\"", "").replace("-", "").to_uppercase();
            let vendor = parts[2].trim_matches('"').to_string();
            map.insert(prefix, vendor);
        }
    }
    Ok(map)
}

fn lookup_vendor(mac: &str, oui_map: &HashMap<String, String>) -> Option<String> {
    let mac = mac.replace(":", "").replace("-", "").to_uppercase();
    let oui = &mac[0..6.min(mac.len())];
    oui_map.get(oui).cloned()
}

pub async fn run_arp_scan(iface: &str, cidr: &str) -> Result<(), Box<dyn std::error::Error>> {
    let devices = Device::list()?;
    let iface = devices
        .into_iter()
        .find(|d| d.name == iface)
        .ok_or("Interface not found")?;

    // Find the MAC address using pnet
    let our_mac = datalink::interfaces()
        .into_iter()
        .find(|i| i.name == iface.name)
        .and_then(|i| i.mac)
        .map(|mac| MacAddr6::new(mac.octets()[0], mac.octets()[1], mac.octets()[2], mac.octets()[3], mac.octets()[4], mac.octets()[5]))
        .ok_or("Could not get MAC for interface")?;

    // Load OUI from IEEE CSV file
    let oui_map = load_ieee_oui("oui.csv").map_err(|e| format!("Failed to load OUI database: {}", e))?;

    let network: IpNetwork = cidr.parse()?;

    let mut cap = Capture::from_device(iface.name.as_str())?
        .promisc(true)
        .timeout(500)
        .open()?;

    // Only capture ARP traffic
    cap.filter("arp", true)
        .map_err(|e| format!("Failed to set ARP filter: {}", e))?;

    let mut discovered: HashSet<(Ipv4Addr, MacAddr6)> = HashSet::new();

    for ip in network.iter().filter_map(|ip| match ip {
        IpAddr::V4(v4) => Some(v4),
        _ => None,
    }) {
        if ip == Ipv4Addr::new(0, 0, 0, 0) {
            continue;
        }
        let arp_packet = build_arp_request(our_mac, ip);
        cap.sendpacket(&arp_packet[..])?;
    }

    let scan_end = std::time::Instant::now() + Duration::from_secs(2);

    while std::time::Instant::now() < scan_end {
        if let Ok(packet) = cap.next_packet() {
            if let Some((sender_ip, sender_mac)) = parse_arp_reply(&packet.data) {
                discovered.insert((sender_ip, sender_mac));
            }
        }
        sleep(Duration::from_millis(10)).await;
    }

    let results: Vec<DiscoveredDevice> = discovered
        .into_iter()
        .map(|(ip, mac)| {
            let vendor = lookup_vendor(&mac.to_string(), &oui_map);
            DiscoveredDevice {
                ip,
                mac: mac.to_string(),
                vendor,
            }
        })
        .collect();

    println!("{}", serde_json::to_string_pretty(&results)?);

    Ok(())
}

fn build_arp_request(our_mac: MacAddr6, target_ip: Ipv4Addr) -> Vec<u8> {
    let mut ethernet_buffer = [0u8; 42]; // Ethernet (14) + ARP (28)
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();

    ethernet_packet.set_destination([0xff, 0xff, 0xff, 0xff, 0xff, 0xff].into()); // Broadcast

    // Convert MacAddr6 to pnet::util::MacAddr using [u8; 6]
    let mac_bytes: [u8; 6] = our_mac.as_bytes().try_into().unwrap();
    ethernet_packet.set_source(pnet::util::MacAddr::from(mac_bytes));
    ethernet_packet.set_ethertype(EtherTypes::Arp);

    let mut arp_buffer = [0u8; 28];
    let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();

    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(ArpOperations::Request);

    // Use the same [u8; 6] for sender_hw_addr
    arp_packet.set_sender_hw_addr(pnet::util::MacAddr::from(mac_bytes));
    arp_packet.set_sender_proto_addr(Ipv4Addr::new(0, 0, 0, 0)); // Use 0.0.0.0 or interface IP
    arp_packet.set_target_hw_addr([0, 0, 0, 0, 0, 0].into()); // Unknown
    arp_packet.set_target_proto_addr(target_ip);

    ethernet_packet.set_payload(arp_packet.packet());

    ethernet_buffer.to_vec()
}

fn parse_arp_reply(data: &[u8]) -> Option<(Ipv4Addr, MacAddr6)> {
    use pnet_packet::ethernet::EthernetPacket;
    use pnet_packet::arp::ArpPacket;

    let ethernet = EthernetPacket::new(data)?;
    if ethernet.get_ethertype() != EtherTypes::Arp {
        return None;
    }

    let arp = ArpPacket::new(ethernet.payload())?;
    if arp.get_operation() != ArpOperations::Reply {
        return None;
    }

    let sender_ip = arp.get_sender_proto_addr();
    let sender_mac = arp.get_sender_hw_addr();
    let mac = MacAddr6::new(
        sender_mac.octets()[0],
        sender_mac.octets()[1],
        sender_mac.octets()[2],
        sender_mac.octets()[3],
        sender_mac.octets()[4],
        sender_mac.octets()[5],
    );

    Some((sender_ip, mac))
}
