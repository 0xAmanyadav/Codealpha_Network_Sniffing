🕵 Basic Network Sniffer (Windows + Python + Scapy)

---

🚀 Features

Capture live packets (Ethernet, IP, TCP, UDP)

Colorful, readable output

Preview packet payloads

Works on Windows using Npcap

Command-line interface for filters and interface selection



---

🧩 Project Structure

basic-network-sniffer/
│
├── sniffer_scapy.py      # main sniffer script
├── requirements.txt      # dependencies
├── .gitignore            # ignore cache/venv
└── README.md             # documentation


---

⚙ Requirements

Windows 10/11

Python 3.8 or above

VS Code (recommended editor)

Npcap (for packet capture)

Administrator rights to sniff traffic



---

📦 Installation Steps

1. Clone or create project folder

mkdir basic-network-sniffer
cd basic-network-sniffer


2. Create virtual environment (optional but recommended)

python -m venv venv
venv\Scripts\activate


3. Install dependencies

pip install -r requirements.txt

or manually:

pip install scapy colorama


4. Install Npcap

Download from ➡ https://nmap.org/npcap/

During install, tick these:

✅ Install Npcap in WinPcap API-compatible mode

✅ Support raw 802.11 traffic (if you want Wi-Fi capture)






---

▶ Usage

Open VS Code Terminal (Run as Administrator) and execute:

python sniffer_scapy.py

Optional arguments:

Option	Example	Description

-i	-i Wi-Fi	Select network interface
-c	-c 10	Capture only 10 packets
-f	-f "tcp port 80"	Apply capture filter


Examples:

python sniffer_scapy.py -i Wi-Fi
python sniffer_scapy.py -f "tcp port 80"


---

🧠 Example Output

==========================================================================================
📦 Packet #1  |  Time: 21:05:32
------------------------------------------------------------------------------------------
🔹 Ethernet Layer
    Src MAC: 00:1A:2B:3C:4D:5E
    Dst MAC: 11:22:33:44:55:66
🔸 IP Layer
    Src IP : 192.168.1.5
    Dst IP : 142.250.187.78
    Proto  : 6
🔶 TCP Layer
    Src Port: 50024
    Dst Port: 443
    Seq/Ack : 654321/123456
🧩 Payload:
    GET / HTTP/1.1 Host: google.com User-Agent: Mozilla/5.0 ...
==========================================================================================


---

🔍 How It Works

1. Scapy uses Npcap driver to read packets at the data-link layer.


2. The sniffer prints headers for Ethernet, IP, and TCP/UDP.


3. If a payload exists, it prints the first 80 bytes as a preview.




---

⚠ Legal Note

> Use this sniffer only on networks you own or have explicit permission to analyze.
Unauthorized sniffing is illegal in many countries.



For safe testing:

Run on a private network or VM

Generate test traffic using ping, curl, or netcat



---

💡 Future Improvements

Save packets to .pcap files for Wireshark analysis

Add HTTP/DNS protocol parsers

Real-time dashboard (Tkinter or PyQt)

Packet statistics and logging



---

🧾 requirements.txt

scapy
colorama

---

👨‍💻 Author

Created by Aman Yadav
Educational Purpose Only | Feel free to fork & contribute
---
