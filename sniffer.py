from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import Counter

# Dictionary to count packets by protocol
packet_count = Counter()

def packet_callback(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # TCP packets
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flags = packet[TCP].flags
            packet_count['TCP'] += 1
            print(f"[TCP] {src_ip}:{src_port} -> {dst_ip}:{dst_port} | Flags: {flags}")

        # UDP packets
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            packet_count['UDP'] += 1
            print(f"[UDP] {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

        # ICMP packets
        elif packet.haslayer(ICMP):
            packet_count['ICMP'] += 1
            print(f"[ICMP] {src_ip} -> {dst_ip}")

        else:
            packet_count['Other'] += 1
            print(f"[Other] {src_ip} -> {dst_ip}")

# Start sniffing 10 packets
sniff(prn=packet_callback, count=10)

# Keep window open after finishing
input("\nPress Enter to exit...")

# Show summary
print("\nPacket Counts:")
for protocol, count in packet_count.items():
    print(f"{protocol}: {count}")