from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        
        # Determine the protocol
        if TCP in packet:
            protocol = 'TCP'
            payload = bytes(packet[TCP].payload)
        elif UDP in packet:
            protocol = 'UDP'
            payload = bytes(packet[UDP].payload)
        else:
            protocol = 'Other'
            payload = bytes(packet[IP].payload)
        
        # Print packet information
        print(f"Source IP: {ip_src}")
        print(f"Destination IP: {ip_dst}")
        print(f"Protocol: {protocol}")
        print(f"Payload: {payload}\n")

# Capture packets
print("Starting packet sniffer...")
sniff(prn=packet_callback, store=0)
