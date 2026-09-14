CodeAlpha Network Sniffer

A basic network packet sniffer developed in Python as part of the CodeAlpha Cyber Security Internship.

Project Overview

This project captures network packets from a selected network interface and analyzes basic packet information.

The sniffer displays:

Source IP address
Destination IP address
Network protocol
Source port
Destination port
TCP flags
Packet size
Payload information
Packet capture statistics

The project uses the Scapy library for packet capture and analysis.

Features
Select a network interface before capturing packets
Capture a fixed number of packets or run continuously
Detect TCP, UDP, ICMP and other network traffic
Support for IPv4 and IPv6 addresses
Display TCP/UDP port information
Display TCP flags
Inspect packet payloads
Identify readable payload data
Mark encrypted or binary payloads
Display protocol statistics after capture
Technologies Used
Python 3
Scapy
Npcap
Windows PowerShell
Requirements
Python 3
Scapy
Npcap on Windows

Install Scapy using:

pip install scapy

Npcap is required on Windows for live packet capture.

How to Run

Open PowerShell as Administrator and navigate to the project directory.

Run the program:

python network_sniffer.py

The program will display the available network interfaces.

Select the required interface and choose the desired capture mode.

Example:

Select interface: 5

Capture Options
------------------------------
1. Capture 20 packets
2. Capture 50 packets
3. Capture 100 packets
4. Capture continuously

The program then captures and analyzes the selected network traffic.

Example Output
============================================================
PACKET #1
============================================================
Protocol    : TCP
Source      : 192.168.1.7
Destination : 40.79.163.155
Source Port : 61721
Dest Port   : 443
TCP Flags   : PA
Packet Size : 89 bytes
Payload     : [Encrypted/Binary Data]

At the end of the capture, protocol statistics are displayed:

============================================================
             PACKET STATISTICS
============================================================
Total Packets : 20
TCP           : 20
UDP           : 0
ICMP          : 0
Other         : 0
============================================================
Project Structure
CodeAlpha_NetworkSniffer/
│
├── network_sniffer.py
└── README.md
Learning Outcomes

This project provides practical experience with:

Network packet capture
Packet structure and analysis
IP addressing
TCP and UDP communication
TCP flags
Network ports
Payload inspection
IPv4 and IPv6 traffic
Basic network security monitoring
Ethical Use

This project is intended for educational and authorized network monitoring purposes only.

Only capture network traffic on networks and devices where you have permission to do so.
