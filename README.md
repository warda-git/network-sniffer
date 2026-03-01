# Python Network Sniffer

## Overview
This project implements a **basic network sniffer** in Python using the [Scapy](https://scapy.net/) library.  
The sniffer captures network packets in real time and analyzes their structure, providing insights into the flow of data across a network. It is designed as an educational tool to understand TCP, UDP, and ICMP packet behavior.

---

## Features
- Captures **TCP, UDP, and ICMP packets** on the local network.
- Displays **source and destination IP addresses**.
- Shows **ports** and **TCP flags** for TCP packets.
- Maintains a **count of packets** per protocol.
- Keeps the console open until user exits, allowing thorough inspection.

---

## Requirements
- Python 3.8 or higher  
- Scapy library

Install Scapy via pip if not already installed:

```bash
pip install scapy
