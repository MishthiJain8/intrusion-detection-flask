from flask import Flask, render_template, jsonify
from threading import Thread
from scapy.all import sniff, IP, TCP
import time
from collections import defaultdict

app = Flask(__name__)

# Store alerts in a list to display them on the webpage
alerts = []

# Dictionary to track source IP and accessed ports
ip_ports = defaultdict(list)
scan_threshold = 5
time_window = 10  # seconds

# This function checks for port scans
def detect_port_scan(packet):
    if packet.haslayer(TCP):
        source_ip = packet[IP].src
        dest_port = packet[TCP].dport
        
        # Debug print to show packet info
        print(f"Packet received: {source_ip} -> Port {dest_port}")
        
        current_time = time.time()
        ip_ports[source_ip].append((dest_port, current_time))

        # Remove old entries that are out of the time window
        ip_ports[source_ip] = [(port, timestamp) for port, timestamp in ip_ports[source_ip] if current_time - timestamp < time_window]

        # Debug print for accessed ports
        accessed_ports = {port for port, _ in ip_ports[source_ip]}
        print(f"Accessed ports from {source_ip}: {accessed_ports}")
        
        # If the number of distinct ports accessed by the IP exceeds the threshold, it's a port scan
        if len(accessed_ports) >= scan_threshold:
            alert_message = f"Port scan detected from {source_ip}!"
            print(alert_message)  # Print the alert message when a port scan is detected
            alerts.append(alert_message)
            return True
    return False

# Function to start sniffing in a separate thread
def start_sniffing_thread():
    sniff(filter="tcp", prn=detect_port_scan, store=0)

# The route for your webpage
@app.route('/')
def index():
    return render_template('index.html', alerts=alerts)

@app.route('/start_sniffing', methods=["POST"])
def start_sniffing():
    sniff_thread = Thread(target=start_sniffing_thread)
    sniff_thread.start()
    
    # After 30 seconds, if no alerts, display a message
    time.sleep(30)
    if not alerts:
        alerts.append("No issues detected after sniffing.")

    return jsonify(message="Sniffing started, waiting for alerts!")

if __name__ == "__main__":
    app.run(debug=True, port=5002)
