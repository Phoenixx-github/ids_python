from flask import Flask, render_template, jsonify
import threading
import time
import sys
from collections import defaultdict
from scapy.all import *

app = Flask(__name__)

# This is a simple shared list to store alerts.
# In a real-world application, you would use a database.
alerts = []

# Dictionaries to manage state for the sniffer
syn_counts = defaultdict(int)
syn_timestamps = defaultdict(float)

# Thresholds
SYN_THRESHOLD = 50
TIME_WINDOW = 5

def packet_callback(packet):
    """
    Packet processing function.
    """
    if IP in packet and TCP in packet:
        if packet[TCP].flags == "S":
            src_ip = packet[IP].src
            current_time = time.time()

            if (current_time - syn_timestamps[src_ip]) < TIME_WINDOW:
                syn_counts[src_ip] += 1
                if syn_counts[src_ip] > SYN_THRESHOLD:
                    alert_message = f"Potential SYN flood attack detected from IP: {src_ip}"
                    print(alert_message)
                    alerts.append({"type": "SYN Flood", "ip": src_ip, "timestamp": time.ctime(), "message": alert_message})
                    syn_counts[src_ip] = 0
            else:
                syn_counts[src_ip] = 1
            
            syn_timestamps[src_ip] = current_time

def start_sniffer():
    """
    Starts the Scapy sniffer in a separate thread.
    """
    print("Starting NIDS sniffer...")
    # You'll need to specify your network interface here, e.g., "eth0" or "en0"
    # Or, if not specified, Scapy will sniff on the default interface.
    sniff(prn=packet_callback, store=0)

# Start the sniffer in a background thread
sniffer_thread = threading.Thread(target=start_sniffer, daemon=True)
sniffer_thread.start()

@app.route('/')
def index():
    """
    Renders the main web page with alerts.
    """
    return render_template('index.html', alerts=alerts)

@app.route('/api/alerts')
def get_alerts():
    """
    API endpoint to fetch alerts for dynamic updates.
    """
    return jsonify(alerts)

if __name__ == '__main__':
    # You can change the host and port
    app.run(host='0.0.0.0', port=5000, debug=True)

@app.route('/api/logs')
def get_logs():
    """Reads and returns the content of the log file."""
    try:
        with open(log_file, 'r') as f:
            logs = f.read()
        return logs
    except FileNotFoundError:
        return "Log file not found.", 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)