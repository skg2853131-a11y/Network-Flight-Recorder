import csv
import sys # New import to handle the shut down
from scapy.all import sniff, IP, DNS

# 1. THE BLACKLIST: Add IPs that should trigger a shutdown
# For testing, you can put '8.8.8.8' (Google DNS) here
BLACKLIST = ['192.168.1.100', '8.8.8.8', '10.0.0.5']

def process_packet(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # 2. THE KILL SWITCH LOGIC
        # Check if the Source or Destination matches our Blacklist
        if src_ip in BLACKLIST or dst_ip in BLACKLIST:
            print(f"\n[!!!] CRITICAL SECURITY ALERT [!!!]")
            print(f"Malicious IP Detected: {src_ip if src_ip in BLACKLIST else dst_ip}")
            print("EMERGENCY SHUTDOWN INITIATED TO PREVENT DATA EXFILTRATION.")
            
            # Save the final alert to the log before dying
            with open('flight_log.csv', 'a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([packet.time, src_ip, dst_ip, "ALERT", "KILL SWITCH", "Blacklisted IP Access"])
            
            sys.exit() # This kills the script immediately

        # 3. Normal recording logic continues below...
        print(f"[SAFE] {src_ip} -> {dst_ip}")

print("--- Flight Recorder with Kill Switch Active ---")
# Start Sniffing
sniff(prn=process_packet, store=False)