import sys
import threading
import time
import os
from collections import defaultdict
from flask import Flask, render_template, jsonify
from scapy.all import *
from logging.handlers import RotatingFileHandler
import logging
from datetime import datetime

# --- Global Termination Flag ---
stop_sniffer_flag = threading.Event()

# Data structures
alerts = []
packet_data = {}
alert_id_counter = 0

packet_counts = defaultdict(lambda: {"count": 0, "timestamp": time.time()})
port_scan_counts = defaultdict(set)
blocked_ips = set()

# Whitelist and Blacklist
WHITELISTED_IPS = {"127.0.0.1", "192.168.1.100"}  
BLACKLISTED_IPS = set() 

# Thresholds
DDoS_THRESHOLD = 100
PORT_SCAN_THRESHOLD = 10
TIME_WINDOW = 1

# --- Logger Setup ---
log_file = 'nids_events.log'
file_handler = RotatingFileHandler(log_file, maxBytes=10240, backupCount=5)
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logger = logging.getLogger('NIDS')
logger.addHandler(file_handler)
logger.setLevel(logging.INFO)

def create_alert(alert_type, ip_address, message, packet=None):
    """Creates an alert with a unique ID and stores the packet."""
    global alert_id_counter
    alert_id = alert_id_counter
    alert_id_counter += 1
    
    if packet:
        packet_data[alert_id] = packet.summary()
    else:
        packet_data[alert_id] = None

    alert = {
        "id": alert_id,
        "type": alert_type,
        "ip": ip_address,
        "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "message": message
    }
    alerts.append(alert)
    logger.warning(message)

def block_ip(ip_address, reason):
    """Blocks an IP address using iptables and logs the action."""
    if ip_address not in blocked_ips and ip_address not in WHITELISTED_IPS:
        try:
            os.system(f"sudo iptables -A INPUT -s {ip_address} -j DROP")
            blocked_ips.add(ip_address)
            message = f"ATTACKER BLOCKED: IP {ip_address} for {reason}"
            create_alert("BLOCK", ip_address, message)
            logger.critical(message)
        except Exception as e:
            logger.error(f"Error blocking IP {ip_address}: {e}")

def detect_ddos(packet):
    """Detects a potential DDoS attack."""
    src_ip = packet[IP].src
    current_time = time.time()
    
    if (current_time - packet_counts[src_ip]["timestamp"]) < TIME_WINDOW:
        packet_counts[src_ip]["count"] += 1
        if packet_counts[src_ip]["count"] > DDoS_THRESHOLD:
            alert_message = f"Potential DDoS attack detected from IP: {src_ip}"
            create_alert("DDoS Attack", src_ip, alert_message, packet.copy())
            block_ip(src_ip, "DDoS attack")
            packet_counts[src_ip]["count"] = 0
            packet_counts[src_ip]["timestamp"] = current_time
    else:
        packet_counts[src_ip]["count"] = 1
        packet_counts[src_ip]["timestamp"] = current_time

def detect_port_scan(packet):
    """Detects a potential port scan."""
    if TCP in packet:
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        
        port_scan_counts[src_ip].add(dst_port)

        if len(port_scan_counts[src_ip]) > PORT_SCAN_THRESHOLD:
            alert_message = f"Potential port scan detected from IP: {src_ip} on ports: {list(port_scan_counts[src_ip])}"
            create_alert("Port Scan", src_ip, alert_message, packet.copy())
            block_ip(src_ip, "Port Scan")
            port_scan_counts[src_ip].clear()

def packet_callback(packet):
    """Main packet analysis function."""
    if IP in packet:
        src_ip = packet[IP].src
        
        if src_ip in WHITELISTED_IPS or src_ip in BLACKLISTED_IPS:
            return

        detect_ddos(packet)
        detect_port_scan(packet)

def start_sniffer():
    """Starts the packet sniffer and watches for the termination flag."""
    logger.info("NIDS sniffer started.")
    try:
        sniff(prn=packet_callback, store=0, stop_filter=lambda p: stop_sniffer_flag.is_set())
    except Exception as e:
        logger.error(f"Sniffer thread terminated with an error: {e}")
    finally:
        logger.info("NIDS sniffer stopped gracefully.")

# --- Flask Web Interface ---
app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html', alerts=alerts)

@app.route('/api/alerts')
def get_alerts():
    return jsonify(alerts)

@app.route('/api/packet/<int:alert_id>')
def get_packet_details(alert_id):
    packet_summary = packet_data.get(alert_id)
    if packet_summary:
        return jsonify({"summary": packet_summary})
    return jsonify({"error": "Packet not found or not available."}), 404

@app.route('/api/logs')
def get_logs():
    try:
        with open(log_file, 'r') as f:
            logs = f.read()
        return logs
    except FileNotFoundError:
        return "Log file not found.", 404

if __name__ == '__main__':
    # Start the sniffer thread
    sniffer_thread = threading.Thread(target=start_sniffer)
    sniffer_thread.start()

    try:
        # Crucially, set `use_reloader=False` to prevent automatic restarts.
        app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)
    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt received. Shutting down gracefully...")
    finally:
        stop_sniffer_flag.set()
        sniffer_thread.join()
        logger.info("Application has shut down completely.")
        sys.exit(0)