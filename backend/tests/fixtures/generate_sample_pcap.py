from pathlib import Path
from scapy.all import IP, TCP, UDP, Raw, wrpcap


def generate_test_pcap(output_path: Path):
    """
    Generates a deterministic, safe, synthetic offline PCAP file for testing.
    Contains strictly local RFC-5737 documentation addresses (192.0.2.x).
    """
    packets = []

    # 1. Flow A: 192.0.2.10:49152 -> 192.0.2.80:80 (TCP Web Traffic - 4 packets)
    # SYN (t=10.000), ACK (t=10.050), PSH+ACK data (t=10.150), FIN+ACK (t=10.500)
    p1 = IP(src="192.0.2.10", dst="192.0.2.80") / TCP(sport=49152, dport=80, flags="S")
    p1.time = 10.000000
    packets.append(p1)

    p2 = IP(src="192.0.2.10", dst="192.0.2.80") / TCP(sport=49152, dport=80, flags="A")
    p2.time = 10.050000
    packets.append(p2)

    p3 = IP(src="192.0.2.10", dst="192.0.2.80") / TCP(sport=49152, dport=80, flags="PA") / Raw(load=b"GET /index.html HTTP/1.1\r\nHost: example.local\r\n\r\n")
    p3.time = 10.150000
    packets.append(p3)

    p4 = IP(src="192.0.2.10", dst="192.0.2.80") / TCP(sport=49152, dport=80, flags="FA")
    p4.time = 10.500000
    packets.append(p4)

    # 2. Flow B: 192.0.2.25:50001 -> 192.0.2.99:443 (Periodic C2 Beaconing - 5 packets at exact 1.0s interval)
    for i in range(5):
        pkt = IP(src="192.0.2.25", dst="192.0.2.99") / TCP(sport=50001, dport=443, flags="PA") / Raw(load=b"\x00" * 32)
        pkt.time = 20.000000 + i * 1.000000
        packets.append(pkt)

    # 3. Flow C: 192.0.2.33:53535 -> 192.0.2.53:53 (UDP DNS query - 2 packets)
    udp1 = IP(src="192.0.2.33", dst="192.0.2.53") / UDP(sport=53535, dport=53) / Raw(load=b"\x12\x34\x01\x00\x00\x01")
    udp1.time = 30.000000
    packets.append(udp1)

    udp2 = IP(src="192.0.2.33", dst="192.0.2.53") / UDP(sport=53535, dport=53) / Raw(load=b"\x56\x78\x01\x00\x00\x01")
    udp2.time = 30.250000
    packets.append(udp2)

    # 4. Flow D: 192.0.2.44:60000 -> 192.0.2.88:22 (Single SYN Probe - 1 packet)
    syn_probe = IP(src="192.0.2.44", dst="192.0.2.88") / TCP(sport=60000, dport=22, flags="S")
    syn_probe.time = 40.000000
    packets.append(syn_probe)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output_path), packets)
    print(f"[TEST FIXTURE] Generated {len(packets)} packets into: {output_path}")


if __name__ == "__main__":
    out_file = Path(__file__).parent / "sample_offline.pcap"
    generate_test_pcap(out_file)
