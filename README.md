# 🛡️ Network Intrusion Detection System (IDS)

A lightweight, real-time IDS built in Python that captures and analyzes live network traffic to detect malicious activity.

## Features
- 📡 **Packet capture** — raw TCP/UDP/ICMP sniffing via Scapy in promiscuous mode
- 🔍 **Port scan detection** — SYN sweep, half-open, XMAS, NULL, and FIN scan signatures
- 📊 **Traffic stats** — per-IP packet/byte rate tracking using Exponential Moving Averages
<!-- 
- 🚨 **Alert engine** — severity scoring (INFO → CRITICAL), deduplication, and cooldown suppression
- 🗄️ **Logging** — rotating JSON logs + queryable SQLite database for forensic analysis

## Stack
Python · Scapy · SQLite · Threading
-->
