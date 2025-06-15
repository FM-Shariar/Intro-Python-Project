# Short Description of the Packet Sniffer Code
# This Python script is a basic packet sniffer using the scapy library. Here's what it does:
# Captures network packets in real-time using sniff().
# Extracts and analyzes key details:
# Source and destination IP addresses.
# Protocol used (TCP, UDP, ICMP, or others).
# First 50 bytes of the packet's payload (if available).
# Adds timestamps to each log entry.
# Logs the data into a file named packet_log.txt for later review.
# Prints the output to the console while running.
# Can be safely stopped with CTRL+C, which also closes the log file.

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from datetime import datetime

# Open the log file for writing
log_file = open("packet_log.txt", "w")

def process_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]

        # Detect protocol
        if packet.haslayer(TCP):
            protocol = "TCP"
        elif packet.haslayer(UDP):
            protocol = "UDP"
        elif packet.haslayer(ICMP):
            protocol = "ICMP"
        else:
            protocol = "Other"

        # Get current timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Print info to console
        print(f"[{timestamp}] {protocol} Packet:")
        print(f"    From: {ip_layer.src}")
        print(f"    To:   {ip_layer.dst}")

        # Prepare log line
        log_line = f"[{timestamp}] {protocol} | From: {ip_layer.src} -> To: {ip_layer.dst}"

        # Check for payload
        if packet.haslayer(Raw):
            payload = packet[Raw].load[:50]  # First 50 bytes
            try:
                payload_text = payload.decode(errors='replace')
            except:
                payload_text = str(payload)
            print(f"    Payload: {payload_text}...")
            log_line += f" | Payload: {payload_text}..."

        # Write to file
        log_file.write(log_line + "\n")
        print("-" * 50)

def start_sniffing():
    print("Starting packet capture... (Press CTRL+C to stop)")
    try:
        sniff(prn=process_packet, store=False)
    except KeyboardInterrupt:
        print("\nStopped packet capture.")
        log_file.close()
        print("Log saved to packet_log.txt")

if __name__ == "__main__":
    start_sniffing()
