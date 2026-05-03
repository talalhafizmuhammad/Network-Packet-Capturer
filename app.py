from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
import threading
import time
import json
from datetime import datetime
from collections import defaultdict

app = Flask(__name__)
CORS(app)
packets_log = []
stats = {
    "total": 0,
    "tcp": 0,
    "udp": 0,
    "icmp": 0,
    "other": 0,
    "total_size": 0,
}
monitoring = False
sniff_thread = None
lock = threading.Lock()

PORT_MAP = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    80: "HTTP", 110: "POP3", 143: "IMAP", 161: "SNMP",
    194: "IRC", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    514: "Syslog", 587: "SMTP", 993: "IMAPS", 995: "POP3S",
    1080: "SOCKS", 1194: "OpenVPN", 1433: "MSSQL", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
}

def get_service(port):
    if port is None:
        return "Unknown"
    return PORT_MAP.get(port, f"Port-{port}")

def process_packet(pkt):
    global packets_log, stats
    try:
        from scapy.layers.inet import IP, TCP, UDP, ICMP
        if not pkt.haslayer(IP):
            return

        ip = pkt[IP]
        src_ip = ip.src
        dst_ip = ip.dst
        size = len(pkt)
        timestamp = datetime.now().strftime("%H:%M:%S")

        proto = "OTHER"
        src_port = None
        dst_port = None

        if pkt.haslayer(TCP):
            proto = "TCP"
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
        elif pkt.haslayer(UDP):
            proto = "UDP"
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
        elif pkt.haslayer(ICMP):
            proto = "ICMP"

        service = get_service(dst_port)

        record = {
            "id": stats["total"] + 1,
            "time": timestamp,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": proto,
            "src_port": src_port,
            "dst_port": dst_port,
            "service": service,
            "size": size,
        }

        with lock:
            packets_log.append(record)
            if len(packets_log) > 500:
                packets_log = packets_log[-500:]
            stats["total"] += 1
            stats["total_size"] += size
            if proto == "TCP":
                stats["tcp"] += 1
            elif proto == "UDP":
                stats["udp"] += 1
            elif proto == "ICMP":
                stats["icmp"] += 1
            else:
                stats["other"] += 1

    except Exception as e:
        pass 
def start_sniffing():
    from scapy.all import sniff
    while monitoring:
        sniff(prn=process_packet, store=False, timeout=2, filter="ip")

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/start", methods=["POST"])
def start():
    global monitoring, sniff_thread, packets_log, stats
    if monitoring:
        return jsonify({"status": "already_running"})

    with lock:
        packets_log = []
        stats = {"total": 0, "tcp": 0, "udp": 0, "icmp": 0, "other": 0, "total_size": 0}

    monitoring = True
    sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
    sniff_thread.start()
    return jsonify({"status": "started"})

@app.route("/api/stop", methods=["POST"])
def stop():
    global monitoring
    monitoring = False
    return jsonify({"status": "stopped"})

@app.route("/api/packets")
def get_packets():
    proto_filter = request.args.get("protocol", "").upper()
    src_filter = request.args.get("src_ip", "").strip()
    dst_filter = request.args.get("dst_ip", "").strip()

    with lock:
        result = list(packets_log)

    if proto_filter and proto_filter != "ALL":
        result = [p for p in result if p["protocol"] == proto_filter]
    if src_filter:
        result = [p for p in result if src_filter in p["src_ip"]]
    if dst_filter:
        result = [p for p in result if dst_filter in p["dst_ip"]]

    return jsonify(result)

@app.route("/api/stats")
def get_stats():
    with lock:
        s = dict(stats)
    avg_size = round(s["total_size"] / s["total"], 1) if s["total"] > 0 else 0
    s["avg_size"] = avg_size
    s["is_monitoring"] = monitoring
    return jsonify(s)

@app.route("/api/status")
def get_status():
    return jsonify({"monitoring": monitoring})


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)