# 🔍 NetWatch — Network Traffic Monitoring and Analysis Platform

A real-time network traffic monitoring platform built with **Python (Flask + Scapy)** and a clean **HTML/CSS/JS** web interface. Captures live packets from your network interface, displays them in a filterable table, and shows protocol statistics — all in your browser.

> **CN Project — University of the Punjab, FCIT**

---

## 📸 Preview

> *(Add screenshots of the running application here)*

---

## ✨ Features

- ✅ **Real-time packet sniffing** using Scapy (live capture, no dataset needed)
- ✅ Start / Stop monitoring controls
- ✅ Live packet table with: Time, Source IP, Destination IP, Protocol, Ports, Service, Size
- ✅ **Port → Service mapping** (HTTP, DNS, HTTPS, SSH, FTP, etc.)
- ✅ Filter by Protocol (TCP / UDP / ICMP), Source IP, Destination IP
- ✅ Statistics: Total packets, TCP/UDP/ICMP counts, Average packet size
- ✅ System log panel
- ✅ Stores last 500 packets in memory

---

## 🗂️ Project Structure

```
network-monitor/
├── app.py               # Flask backend + Scapy sniffer
├── requirements.txt     # Python dependencies
├── templates/
│   └── index.html       # Frontend (HTML + CSS + JS)
└── README.md
```

---

## ⚙️ Setup & Run

### Prerequisites
- Python 3.8+
- **Admin/root privileges** (required for raw packet capture)
- Works on Linux / macOS. On Windows, install [Npcap](https://npcap.com/) first.

### 1. Clone the repository
```bash
git clone https://github.com/YOUR_USERNAME/network-monitor.git
cd network-monitor
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Run the app (with root/admin privileges)
```bash
# Linux / macOS
sudo python app.py

# Windows (run Command Prompt as Administrator)
python app.py
```

### 4. Open in browser
```
http://localhost:5000
```

### 5. Click **▶ START** to begin live capture

---

## 📖 Methodology

### Step 1 — Technology Selection
Chose **Python** for the backend because of Scapy's powerful packet-capture capabilities and Flask's simplicity for serving a web interface. Plain HTML/CSS/JS was used for the frontend as required, with no heavy frameworks.

### Step 2 — Backend Architecture
- **Flask** serves the HTML page and exposes REST API endpoints (`/api/start`, `/api/stop`, `/api/packets`, `/api/stats`).
- **Scapy's `sniff()`** function runs in a **background thread** so it doesn't block the web server.
- A **threading lock** protects the shared packet list and stats dictionary from race conditions.
- Captured packets are stored in a rolling buffer (last 500 packets) to control memory usage.

### Step 3 — Packet Processing
Each captured packet is inspected using Scapy's layer system:
- Extract `IP` layer for source/destination IPs and packet size.
- Check for `TCP`, `UDP`, or `ICMP` layers to determine protocol and ports.
- Map destination port to a human-readable service name using a static dictionary (80 → HTTP, 53 → DNS, etc.).

### Step 4 — Frontend & Filtering
- The frontend polls `/api/packets` and `/api/stats` every **1 second** using `fetch()`.
- Filters (protocol dropdown, source/destination IP text fields) are sent as query parameters to the backend, which filters the packet list server-side before returning results.
- Stats are updated live with every poll cycle.

### Step 5 — Testing
Tested by:
1. Starting the app and opening a browser to generate HTTP/DNS traffic.
2. Running `ping 8.8.8.8` to generate ICMP packets.
3. Verifying filter functionality by filtering for specific source IPs.

---

## 🧱 Challenges Faced

| # | Challenge | Solution |
|---|-----------|----------|
| 1 | **Thread safety** — Scapy's sniffer runs on a separate thread and writes to the same list the Flask API reads from. | Used `threading.Lock()` to wrap all read/write operations on the shared state. |
| 2 | **Blocking sniffer** — `scapy.sniff()` blocks indefinitely, making it impossible to stop cleanly. | Used `timeout=2` in a `while monitoring:` loop so the thread checks the stop flag every 2 seconds. |
| 3 | **Root privileges** — Raw packet capture requires admin rights; the app crashes without them. | Documented this in the README and added a try/except around packet processing to handle permission errors gracefully. |
| 4 | **Memory growth** — Continuous capture accumulates thousands of packets and slows the browser. | Capped the in-memory log at 500 packets using a slice; the table renders only the latest 200. |
| 5 | **CORS issues** — Browser blocked API calls during development. | Added `flask-cors` to allow cross-origin requests during testing. |

---

## 🚀 Future Work

- **Persistent logging** — Save captured packets to a SQLite database or CSV file for post-session analysis.
- **Live charts** — Add real-time protocol distribution charts (pie/bar) using Chart.js.
- **GeoIP lookup** — Map destination IPs to countries/cities using a GeoIP database.
- **Alert system** — Flag suspicious traffic patterns (e.g., port scanning, unusual packet rates).
- **Export** — Allow users to download captured packets as a `.pcap` or `.csv` file.
- **BPF filter input** — Let users enter custom Berkeley Packet Filter expressions for advanced capture.
- **Multi-interface support** — Allow selection of which network interface to sniff on.
- **Packet payload inspection** — Show a hex dump of packet payloads for deeper analysis.

---

## 📚 References (Libraries)

| Library | Version | Purpose |
|---------|---------|---------|
| [Flask](https://flask.palletsprojects.com/) | 3.0.3 | Web server and REST API |
| [Scapy](https://scapy.net/) | 2.5.0 | Real-time packet capture and parsing |
| [Flask-CORS](https://flask-cors.readthedocs.io/) | 4.0.1 | Cross-Origin Resource Sharing support |
| Python `threading` | stdlib | Background sniffer thread |
| Python `collections` | stdlib | `defaultdict` for stats |
| [Rajdhani & Share Tech Mono](https://fonts.google.com/) | — | Frontend typography (Google Fonts) |

---

## 📋 Dataset Note

This project implements **real-time packet sniffing** — no pre-recorded dataset is required. All network data is captured live from the active network interface at runtime using Scapy.

---

## ⚠️ Disclaimer

This tool is built for educational purposes as part of a university Computer Networks course. Only use it to monitor traffic on networks you own or have explicit permission to monitor.

---

*Built by [Your Name] | University of the Punjab, FCIT*