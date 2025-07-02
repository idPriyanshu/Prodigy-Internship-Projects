# 🚀 PRODIGY_CS_05

## 📝 Task Overview

**Task:** Build a Packet Sniffer Tool  
**Description:** Develop a Python-based tool that captures and analyzes network packets. The tool displays essential details such as source and destination IP addresses, protocols, and payload data. The tool is intended solely for ethical and educational use. 
**Status:** ✅ Completed

---

## 🌟 Features

### 📡 **Packet Capture and Analysis**
- Captures live network packets using the `scapy` library.
- Analyzes packets to extract:
  - **Source IP Address**
  - **Destination IP Address**
  - **Protocol**
  - **Payload Data**
- Supports multiple protocols, including TCP, UDP, and ICMP.

### 🔎 **Filtered Output**
- Filters packets based on protocol types.
- Displays a clean and readable summary of packet information.

### ⚙️ **Customizable Configuration**
- Provides options to:
  - Modify filter criteria (e.g., capture only TCP packets).
  - Adjust the interface for packet capture.

---

## 📦 Dependencies

This project requires the following Python modules:
- **scapy**: For packet capturing and analysis.
- **tkinter**: For providing gui.
- **matplotlib**: For visualizing the data through graphs.
- **psutils**: For monitoring the packets.
- **collection**: For counting the packets

---

## 📥 Installation Instructions

### 1. Install Python
Ensure Python 3.6 or later is installed. Download it from the [official Python website](https://www.python.org/downloads/).

### 2. Install Required Modules

Install the required Python libraries using `pip`:
```bash
pip install -r requirements.txt
```

### 3. Install Npcap (Windows Users Only)
To enable packet capturing on Windows, install [Npcap](https://nmap.org/npcap/):
1. Download the installer from the [Npcap website](https://nmap.org/npcap/).
2. Run the installer and follow the on-screen instructions.
3. Ensure that the "Install Npcap in WinPcap API-compatible Mode" option is checked.

---

## ▶️ Usage Instructions

1. 📂 Clone the repository:
   ```bash
   git clone https://github.com/idPriyanshu/PRODIGY_CS_05.git
   ```

2. 📂 Navigate to the project directory:
   ```bash
   cd PRODIGY_CS_05
   ```

3. ▶️ Run the program:
   ```bash
   sudo python Network-Packet-Analyzer.py
   ```
   **Note:** Use `sudo` on Linux or run as Administrator on Windows for required permissions.

---

## 📜 How It Works

1. **Initialize Sniffer:** The script initializes a packet sniffer on the specified network interface.
2. **Capture Packets:** Captures packets in real-time using the `scapy` library.
3. **Analyze Packets:** Extracts essential details such as IP addresses, protocols, and payloads.
4. **Log Data:** Saves packet details to a file for offline analysis.
5. **Display Output:** Outputs filtered and formatted packet details to the console.

---


## 🛠️ Challenges & Solutions

### 1. **Permission Issues**
**Challenge:** Packet capturing requires elevated permissions.
**Solution:** Use `sudo` on Linux or run the script as Administrator on Windows.

### 2. **Protocol Handling**
**Challenge:** Properly parsing different protocols.
**Solution:** Leveraged `scapy`’s built-in protocol dissection capabilities.

### 3. **Windows Compatibility**
**Challenge:** Ensuring compatibility with Windows systems.
**Solution:** Included instructions for installing Npcap.

---

## 🌟 Future Improvements

- Add support for advanced packet analysis, such as:
  - Detecting suspicious patterns or anomalies.
  - Visualizing network traffic.
- Integrate a GUI for easier use.
- Implement packet reassembly for fragmented packets.

---

## 📂 Repository Structure

```
PRODIGY_CS_05/
├── packet_sniffer.py       # Main Python script
├── README.md               # Documentation file
└── requirements.txt        # List of dependencies
```

---

## 🏆 Credits

- **Developer:** [@idPriyanshu](https://www.github.com/idPriyanshu)  
- **Mentorship:** Prodigy InfoTech Cyber Security Internship Program  

---

## 📧 Contact

For queries or suggestions, reach out at [iiit.Priyanshu@gmail.com](mailto:iiit.Priyanshu@gmail.com).

---

## 🔗 Useful Links

- [Scapy Documentation](https://scapy.readthedocs.io/en/latest/index.html)  
- [Npcap Installation Guide](https://nmap.org/npcap/)  
- [Packet Sniffing Basics](https://en.wikipedia.org/wiki/Packet_analyzer)

