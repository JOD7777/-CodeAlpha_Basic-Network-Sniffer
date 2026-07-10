[README.md](https://github.com/user-attachments/files/29899874/README.md)
# 🌐 Basic Network Sniffer

<p align="center">
  <img src="Assets/Screenshot From 2026-07-10 19-21-48.png" alt="Basic Network Sniffer Banner" width="100%">
</p>

<p align="center">

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge\&logo=python\&logoColor=white)
![Scapy](https://img.shields.io/badge/Scapy-Network%20Sniffing-red?style=for-the-badge)
![Linux](https://img.shields.io/badge/Linux-Supported-FCC624?style=for-the-badge\&logo=linux\&logoColor=black)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-success?style=for-the-badge)
![Educational](https://img.shields.io/badge/Purpose-Educational-blue?style=for-the-badge)

</p>

<p align="center">
A Python-based network packet sniffer built using <b>Scapy</b> to capture and inspect live network traffic for networking and cybersecurity learning.
</p>

---

# 📖 Overview

Basic Network Sniffer is an educational Python application that captures live network packets and displays useful information such as source and destination IP addresses, protocols, ports, and packet payloads. It provides hands-on experience with packet sniffing, protocol analysis, and network monitoring while helping users understand how data travels across a network.

---

# ✨ Features

* 📡 Live packet capture
* 🌐 Source & destination IP detection
* 🔍 TCP, UDP, ICMP and ARP packet identification
* 🌍 DNS packet analysis
* 📦 Packet payload inspection
* 📊 Real-time packet statistics
* 💾 Export captured data to JSON and TXT
* 📁 Analyze PCAP files
* 🎨 Colorized command-line interface
* 🖥️ Network interface detection
* ⚡ Lightweight and beginner-friendly

---

# 🎥 Demo

<p align="center">
<img src="demo.jpg" width="850">
</p>

---

# 📸 Screenshots

| Main Menu                        |
| -------------------------------- | 
| ![](ex.jp) |

---

# ⚙️ Installation

```bash
git clone https://github.com/JOD7777/Basic-Network-Sniffer.git

cd Basic-Network-Sniffer

python3 -m venv venv

source venv/bin/activate

pip install -r requirements.txt
```

---

# ▶️ Usage

Run the sniffer:

```bash
sudo python3 src/main.py
```

Analyze a PCAP file:

```bash
python3 src/main.py --analyze capture.pcap
```

List available network interfaces:

```bash
python3 src/main.py --interfaces
```

---

# 📂 Project Structure

```text
Basic-Network-Sniffer/
│
├── assets/
│   ├── banner.png
│   ├── demo.gif
│   └── screenshots/
│
├── src/
│   ├── main.py
│   ├── sniffer.py
│   ├── analyzer.py
│   └── utils.py
│
├── requirements.txt
├── README.md
├── LICENSE
├── .gitignore
└── docs/
```

---

# 📊 Example Output

```text
[TCP ] 192.168.1.5 → 142.250.183.78
Port: 51234 → 443

[DNS ] 192.168.1.5 → 8.8.8.8
Query: github.com

Capture Summary
-------------------------
Total Packets : 1245
TCP           : 910
UDP           : 201
DNS           : 78
ICMP          : 56
```

---

# 🛠 Technologies Used

* Python 3
* Scapy
* Socket Programming
* Colorama
* JSON
* Logging

---

# 🛣️ Roadmap

* Packet filtering
* Save captures as PCAP
* CSV export
* IPv6 support
* Improved protocol parsing
* Simple GUI interface

---

# 🚀 Future Improvements

* HTTP/HTTPS request visualization
* Traffic graphs
* Search and filter packets
* Geo-IP lookup
* Packet replay
* Cross-platform enhancements

---

# 🤝 Contributing

Contributions are welcome! Feel free to fork the repository, improve the project, and submit a pull request.

---

# 📄 License

This project is licensed under the **MIT License**.

---

# ⚠️ Disclaimer

This project is intended **for educational purposes and authorized network monitoring only**. Capture and analyze traffic only on networks you own or have explicit permission to test. Unauthorized packet interception may violate applicable laws or organizational policies.

---

# 👨‍💻 Author

**Supriyo Malik**

Advanced Networking & Cyber Security Student

⭐ If you found this project helpful, please consider starring the repository.
