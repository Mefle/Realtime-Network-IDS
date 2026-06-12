**Real-Time Network Intrusion Detection System (IDS)**

**Overview**

This project is a real-time Intrusion Detection System designed to monitor network traffic and detect malicious activities such as SYN Flood attacks, Port Scanning, and ICMP Ping Sweeps. The system is built using a modular architecture that separates packet detection, backend processing, data storage, and visualization.

The system operates in a controlled environment and is intended for educational and research purposes in network security.

**System Components**

The project consists of the following main components:
  IDS Engine (Sniffer): Captures and analyzes network packets using Scapy and applies detection rules.
  Backend API: Built with Flask, responsible for receiving alerts and storing them in the database.
  Database: SQLite database used to store detected alerts through SQLAlchemy ORM.
  Frontend Dashboard: A web interface that displays alerts and statistics in real time.
  
**Features**

Real-time network packet monitoring
Detection of SYN Flood attacks
Detection of Port Scan activities
Detection of ICMP Ping Sweep behavior
REST API for alert communication between components
Persistent storage using SQLite
Live dashboard for visualization of alerts and statistics
Simulation scripts for generating test traffic

**Technologies Used**

Python
Flask
Flask-SQLAlchemy
Flask-CORS
Scapy
Requests
SQLite
HTML
JavaScript
TailwindCSS

**Project Structure**

backend/ - Flask backend API and database models
ids_engine/ - Packet sniffer and detection logic
frontend/ - Web-based dashboard interface
simulation/ - Traffic simulation scripts
requirements.txt - Project dependencies

**How to Run the Project**

1. Install dependencies
pip install -r requirements.txt

2. Run the backend server
python backend/app.py
Backend runs on:
http://127.0.0.1:5000

3. Run the frontend
python -m http.server 8080
Open in browser:
http://localhost:8080

4. Run IDS engine (requires administrator privileges)
sudo python ids_engine/sniffer.py

6. Run simulation script
sudo python ids_engine/simulate_scan.py

**API Endpoints**

GET /alerts - Retrieve all alerts
POST /alerts - Create new alert
GET /stats - System statistics
DELETE /alerts/clear - Clear all alerts (admin only)

**Purpose:**

This project demonstrates the implementation of a basic intrusion detection system capable of detecting network attacks in real time using Python-based tools.

**Disclaimer:**
This project is for educational purposes only and must be used in a controlled environment.
