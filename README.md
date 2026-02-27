# Next-Generation Firewall + Intrusion Detection System (NGFW + IDS)

![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)
![Security](https://img.shields.io/badge/Type-NGFW%20%2B%20IDS-red.svg)
![Status](https://img.shields.io/badge/Status-Active-brightgreen.svg)

A fully functional Next-Generation Firewall and Intrusion Detection System built from scratch in Python.

This project demonstrates how modern enterprise firewalls operate internally by combining:

- Static policy enforcement
- Stateful behavioral detection
- Correlation-based decision making
- Automated mitigation
- Real-time SOC dashboard visualization
- Performance monitoring

The system transforms raw network traffic into intelligent, adaptive defense decisions in real time.

---

## 📌 Project Overview

### 🔍 The Problem

Traditional firewalls rely primarily on static rule sets such as blocked IP addresses or restricted ports. While effective against known threats, they fail to detect behavioral attacks like:

- Port scanning
- SYN flood attacks
- ICMP flooding
- Malformed packet anomalies

Modern networks require layered security mechanisms capable of analyzing traffic patterns over time.

---

### 🎯 The Solution

This project implements a modular 9-stage security pipeline that performs:

1. High-performance packet ingestion
2. Packet normalization
3. Static firewall policy enforcement
4. Stateful IDS behavioral analysis
5. Correlation-based decision making
6. Automated IP blacklisting
7. Multi-format forensic logging
8. Real-time SOC dashboard visualization
9. System performance monitoring

---

## 🏗 Architecture Overview

The system follows a layered security architecture inspired by enterprise firewall models.

![NGFW Architecture Diagram](assets/ngfw.png)

### Key Architectural Concepts

- **Producer-Consumer Model** for stable packet ingestion
- **Stateful Behavioral Detection**
- **Correlation Engine** combining policy + behavior
- **Dynamic Rule Injection**
- **Multi-threaded processing**
- **Real-time visualization**

---

## 🚀 Core Features

### 🔹 Packet Capture
- Live traffic capture using Scapy
- Buffered queue for performance stability
- Prevents packet loss during traffic spikes

### 🔹 Packet Normalization
- Extracts structured metadata:
  - Source IP
  - Destination IP
  - Protocol
  - Ports
  - TCP flags
- Converts raw packets into analysis-ready format

### 🔹 Firewall Rule Engine
- JSON-based static rule enforcement
- Supports:
  - Blocked IPs
  - Blocked ports
  - Blocked protocols
- Atomic rule updates

### 🔹 Intrusion Detection System (IDS)
Stateful detection of:

- SYN Flood attacks
- Port scanning behavior
- ICMP flooding
- LAND attack (source = destination IP)

Maintains per-source tracking for behavioral pattern analysis.

### 🔹 Decision Engine (Correlation Layer)
- Combines firewall and IDS outputs
- Escalates repeated offenders
- Triggers automatic blacklisting

### 🔹 Automated Response
- Dynamic IP blacklisting
- Real-time mitigation
- Persistent rule updates

### 🔹 Logging & Forensics
Events are stored in:

- JSON (structured logs)
- CSV (human-readable)
- SQLite database (dashboard queries)

### 🔹 SOC Dashboard
Built using Flask + Chart.js

Displays:
- Allowed vs Blocked traffic
- Protocol distribution
- Recent security events
- Admin rule management
- System health metrics

### 🔹 Performance Monitoring
Tracks:
- CPU usage
- Memory utilization
- Packet rate

Ensures detection logic does not degrade system performance.

---

## 🧪 Demonstration Setup

Tested using a two-machine lab setup:

- Ubuntu → Firewall + IDS + Dashboard
- Kali Linux → Attacker machine

Simulated attacks:

- `nmap -sS` (Port Scan)
- `hping3 -S --flood` (SYN Flood)
- `ping -f` (ICMP Flood)
- LAND attack using spoofed source IP

The system detects, logs, escalates, and blocks malicious traffic automatically.

---

## 📂 Project Structure

```text
capture/        → Packet ingestion & parsing
core/           → Decision engine, logger, monitor
ids/            → Behavioral detection engine
rules/          → Firewall rule engine
dashboard/      → Flask SOC dashboard
logs/           → JSON & CSV logs
storage/        → SQLite databases
main.py         → System orchestrator
```
---

## Installation

### Clone the repository:
```bash
git clone [https://github.com/yourusername/n-firewall-ids.git](https://github.com/yourusername/n-firewall-ids.git)
cd n-firewall-ids
```

### Install dependencies:

```bash
pip install -r requirements.txt
```

### Run the system:

```bash
sudo python main.py
```

### Start the dashboard:

```bash
cd dashboard
python app.py
```

### Access the dashboard at:

```text
http://localhost:5000
```

## Future Enhancements
The architecture is designed to scale further with:
- Machine Learning-based anomaly detection
- Threat intelligence feed integration
- Distributed sensor deployment
- Extended Detection and Response (XDR) capabilities

(Current implementation focuses on rule-based + behavioral detection.)

## Learning Outcomes
This project demonstrates:
- Deep understanding of network packet flow
- Stateful intrusion detection logic
- Correlation-based threat classification
- Multi-threaded system architecture
- Real-time security monitoring design
- Practical firewall automation

## ⚠ Disclaimer
This project is intended strictly for educational and laboratory use.
Only test in controlled environments. Do not deploy in production networks without proper hardening and security review.

📬 Contact
If you have feedback or suggestions, feel free to open an issue or connect.

⭐ If you found this project useful, consider giving it a star.
