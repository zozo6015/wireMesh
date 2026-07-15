// Sends one ICMPv4 "fragmentation needed" (type 3, code 4) from this netns,
// embedding a fake original IPv4+TCP header, to <dst>.
//
// Usage: pktgen <dst> <esrc> <edst> <esport> <edport>
//   dst   — where to send the ICMP error (the node whose ingress enforcer we're probing)
//   esrc  — embedded original packet's src addr (the outbound flow's recorded src)
//   edst  — embedded original packet's dst addr (the outbound flow's recorded dst)
//   esport/edport — embedded original packet's TCP ports
//
// Proves spec §5.3's ICMP-error rule: an inbound ICMP error whose embedded
// header matches a flow this segment itself originated (recorded at egress)
// must be let through; one with no matching embedded flow must be denied.
use std::net::Ipv4Addr;

fn csum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    for c in data.chunks(2) {
        sum += u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let dst: Ipv4Addr = a[1].parse().unwrap(); // where to send the ICMP error
    let esrc: Ipv4Addr = a[2].parse().unwrap(); // embedded original src
    let edst: Ipv4Addr = a[3].parse().unwrap(); // embedded original dst
    let esport: u16 = a[4].parse().unwrap();
    let edport: u16 = a[5].parse().unwrap();

    // embedded original: minimal IPv4 hdr (proto tcp) + first 8 bytes of TCP hdr
    let mut emb = vec![0u8; 28];
    emb[0] = 0x45;
    emb[8] = 64;
    emb[9] = 6;
    emb[12..16].copy_from_slice(&esrc.octets());
    emb[16..20].copy_from_slice(&edst.octets());
    emb[20..22].copy_from_slice(&esport.to_be_bytes());
    emb[22..24].copy_from_slice(&edport.to_be_bytes());
    let ecs = csum(&emb[0..20]);
    emb[10..12].copy_from_slice(&ecs.to_be_bytes());

    // icmp: type 3 code 4, unused(2B)=0, next-hop mtu = 1000
    let mut icmp = vec![3u8, 4, 0, 0, 0, 0, 0x03, 0xe8];
    icmp.extend_from_slice(&emb);
    let cs = csum(&icmp);
    icmp[2..4].copy_from_slice(&cs.to_be_bytes());

    let sock = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::RAW,
        Some(socket2::Protocol::ICMPV4),
    )
    .unwrap();
    sock.send_to(&icmp, &std::net::SocketAddr::from((dst, 0)).into())
        .unwrap();
    println!("sent frag-needed to {dst} embedding {esrc}:{esport}->{edst}:{edport}");
}
