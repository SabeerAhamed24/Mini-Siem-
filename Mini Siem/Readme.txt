# Mini SIEM System – Clavis Solutions

A lightweight Security Information and Event Management (SIEM) system designed for real-time monitoring, log analysis, and basic threat detection within a local network environment.

---

## What It Does

The Mini SIEM system monitors endpoint activities and collects security-related logs from connected devices. It analyzes events using rule-based detection and presents results through a centralized dashboard.

The system helps administrators:
- Monitor system activity in real time
- Detect suspicious behavior
- View alerts and severity levels
- Analyze logs using visual dashboards
- Generate reports for investigation

---

## Features

- Real-time log monitoring
- File Integrity Monitoring (FIM)
- Process monitoring using system data
- USB detection and removal control
- Severity-based alert classification (INFO, MEDIUM, HIGH)
- Centralized dashboard (Tkinter GUI)
- Analytics visualization (charts and graphs)
- PDF report generation
- Local database storage (SQLite)

---

## How It Works

The system operates in two main components:

1. **Endpoint Agent**
   - Monitors system activities (files, processes, USB devices)
   - Generates logs and sends them to the server

2. **SIEM Server**
   - Receives logs via TCP socket communication
   - Stores logs in SQLite database
   - Applies rule-based detection
   - Displays data in dashboard

---

## Installation

```bash
pip install -r requirements.txt

## Running The System 

Step 1 – Start the Server
-python server.py

Step 2 – Start the Endpoint Agent
-python agent.py

Step 3 – Launch Dashboard
python dashboard.py