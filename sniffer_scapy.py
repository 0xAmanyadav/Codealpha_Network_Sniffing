import argparse
from datetime import datetime
from scapy.all import sniff, Ether, IP, TCP, UDP, Raw

# For pretty display
def print_packet(pkt_num, ether=None, ip=None, transport=None, payload=None):
    print("=" * 100)
    print(f"📦 Packet #{pkt_num}  |  Time: {datetime.now().strftime('%H:%M:%S')}")
    print("-" * 100)

    if ether:
        print(f"🔹 Ethernet Layer")
        print(f"    ├─ Source MAC      : {ether.src}")
        print(f"    └─ Destination MAC : {ether.dst}")
    if ip:
        print(f"🔸 IP Layer")
        print(f"    ├─ Source IP       : {ip.src}")
        print(f"    ├─ Destination IP  : {ip.dst}")
        print(f"    └─ Protocol        : {ip.proto}")
    if transport:
        if isinstance(transport, TCP):
            print(f"🔶 TCP Layer")
            print(f"    ├─ Src Port        : {transport.sport}")
            print(f"    ├─ Dst Port        : {transport.dport}")
            print(f"    ├─ Seq/Ack         : {transport.seq}/{transport.ack}")
            print(f"    └─ Flags           : {transport.flags}")
        elif isinstance(transport, UDP):
            print(f"🟢 UDP Layer")
            print(f"    ├─ Src Port        : {transport.sport}")
            print(f"    └─ Dst Port        : {transport.dport}")
    if payload:
        preview = payload[:80].decode(errors='ignore') if isinstance(payload, bytes) else str(payload)[:80]
        print(f"🧩 Payload Preview:")
        print("    " + preview.replace("\n", " "))

    print("=" * 100 + "\n")


def packet_handler(pkt):
    global pkt_count
    pkt_count += 1

    ether = pkt[Ether] if Ether in pkt else None
    ip = pkt[IP] if IP in pkt else None
    transport = pkt[TCP] if TCP in pkt else pkt[UDP] if UDP in pkt else None
    payload = pkt[Raw].load if Raw in pkt else None

    print_packet(pkt_count, ether, ip, transport, payload)


def main():
    parser = argparse.ArgumentParser(description="Basic Network Sniffer using Scapy (Formatted Output)")
    parser.add_argument("-i", "--interface", help="Network interface (e.g., eth0, wlan0)")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0=unlimited)")
    parser.add_argument("-f", "--filter", help="BPF filter (e.g., 'tcp port 80')")
    args = parser.parse_args()

    print("\n🕵️  Starting Scapy Packet Capture...")
    print("💡  Press Ctrl+C to stop.\n")
    sniff(iface=args.interface, filter=args.filter, prn=packet_handler, count=args.count)


if __name__ == "__main__":
    pkt_count = 0
    main()
