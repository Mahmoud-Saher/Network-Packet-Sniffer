from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_callback(packet):
    print("="*60)
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        print(f"[IP] {ip_layer.src}  -->  {ip_layer.dst}")
        print(f"Protocol: {ip_layer.proto}")
    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        print(f"[TCP] Source Port: {tcp_layer.sport} --> Dest Port: {tcp_layer.dport}")
    elif packet.haslayer(UDP):
        udp_layer = packet[UDP]
        print(f"[UDP] Source Port: {udp_layer.sport} --> Dest Port: {udp_layer.dport}")
    elif packet.haslayer(ICMP):
        print("[ICMP] Ping/Reply detected")

    if hasattr(packet, "load"):
        try:
            print("Payload:", packet.load.decode(errors="ignore"))
        except:
            print("Payload: (binary data)")

print("Starting packet capture... Press Ctrl+C to stop.")
sniff(prn=packet_callback, store=False)
