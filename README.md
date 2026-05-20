<div align="center">

# 🍯 ParryPot

### Enterprise Honeypot Security Platform

> **Deploy. Trap. Analyze. Protect.**

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Linux%20|%20Windows%20|%20macOS-lightgrey?style=for-the-badge)](#)
[![Status](https://img.shields.io/badge/Status-Production_Ready-brightgreen?style=for-the-badge)](#)
[![License](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)](#)
[![PRs Welcome](https://img.shields.io/badge/PRs-Welcome-orange?style=for-the-badge)](#contributing)

</div>

---
<img width="1672" height="941" alt="ChatGPT Image May 20, 2026, 03_03_38 PM" src="https://github.com/user-attachments/assets/6bdc7068-c172-4279-b186-0fc55406934c" />


# 📌 Table of Contents

- [🎯 Overview](#-overview)
- [✨ Features](#-features)
- [🏗️ Architecture](#️-architecture)
- [🚀 Quick Start](#-quick-start)
- [📥 Installation](#-installation)
- [⚙️ Configuration](#️-configuration)
- [🔥 Firewall Setup](#-firewall-setup)
- [📊 Dashboard Guide](#-dashboard-guide)
- [🧪 Testing the Honeypot](#-testing-the-honeypot)
- [🔌 API Reference](#-api-reference)
- [🚢 Deployment](#-deployment)
- [🔧 Troubleshooting](#-troubleshooting)
- [🛠️ Project Structure](#️-project-structure)
- [🤝 Contributing](#-contributing)
- [📄 License](#-license)
- [🙏 Acknowledgments](#-acknowledgments)
- [📞 Contact & Support](#-contact--support)

---

# 🎯 Overview

**ParryPot** is a production-ready honeypot platform developed by **ParrySecurity** that deploys deceptive services to trap, analyze, and visualize cyber attacks in real-time.

Built for:

- SOC Teams
- Security Researchers
- Blue Teams
- Threat Hunters
- Red Team Labs
- Cybersecurity Enthusiasts

ParryPot transforms attacker reconnaissance into actionable threat intelligence.

---

# ✨ Features

## 🎣 Honeypot Services

| Protocol | Port | Captured Data |
|---|---|---|
| **SSH** | `2022` | Credentials, commands, fingerprints |
| **HTTP** | `2080` | SQLi, XSS, path traversal, headers |
| **FTP** | `2021` | Login attempts, commands |
| **Telnet** | `2023` | Full interactive sessions |
| **SMTP** | `2025` | Spam attempts, email headers |
| **DNS** | `2053` | Queries & tunneling attempts |

---

## 📊 Dashboard Features

- 🌍 Real-Time Global Attack Map
- 📈 Live Threat Analytics
- 🚨 Intelligent Alerting System
- 🧠 Risk Scoring Engine
- 📋 Event Logging
- 📤 CSV Export Support
- 🎨 Modern Glassmorphism UI
- ⚡ Lightweight & Fast

---

## 🛡️ Security Intelligence

- Geolocation Mapping
- Threat Scoring
- Payload Capture
- MITRE ATT&CK Mapping
- Protocol Fingerprinting
- Attack Trend Analysis

---

# 🏗️ Architecture

<details>
<summary><b>Click to Expand Architecture Diagram</b></summary>

```text
┌───────────────────────────────────────────────────────────────┐
│                      PARRYPOT PLATFORM                       │
│                                                               │
│   SSH      HTTP      FTP      TELNET     SMTP      DNS       │
│  :2022    :2080     :2021      :2023     :2025    :2053      │
│                                                               │
├───────────────────────────────────────────────────────────────┤
│                Python Honeypot Engine                        │
│            Multi-threaded Protocol Handlers                  │
├───────────────────────────────────────────────────────────────┤
│                 Shared State & Analytics                     │
│          Events • Alerts • Attackers • Risk Data             │
├───────────────────────────────────────────────────────────────┤
│                Flask Dashboard (Port 5000)                   │
│          Chart.js • Leaflet.js • Real-time UI                │
└───────────────────────────────────────────────────────────────┘
```

</details>

---

# 🚀 Quick Start

## ⚡ One Command Installation

```bash
git clone https://github.com/parrysecurity/parrypot.git

cd parrypot

sudo python3 parrypot.py
```

✅ Your honeypot is now running.

---

## 🌐 Dashboard Access

| Setting | Value |
|---|---|
| URL | `http://localhost:5000` |
| Username | `admin` |
| Password | `admin123` |

---

# 📥 Installation

## 📋 Prerequisites

| Requirement | Specification |
|---|---|
| Python | 3.10+ |
| Package Manager | pip |
| Operating System | Linux / Windows / macOS |
| RAM | 512MB Minimum |
| Storage | 100MB Free Space |

---

## 🐧 Linux / macOS

```bash
# Clone repository
git clone https://github.com/parrysecurity/parrypot.git

# Enter directory
cd parrypot

# Install dependencies
pip3 install -r requirements.txt

# Run ParryPot
sudo python3 parrypot.py
```

---

## 🪟 Windows

```powershell
# Clone repository
git clone https://github.com/parrysecurity/parrypot.git

# Enter directory
cd parrypot

# Install dependencies
pip install -r requirements.txt

# Run as Administrator
python parrypot.py
```

---

# ⚙️ Configuration

Edit the `CONFIG` dictionary inside `parrypot.py`.

```python
CONFIG = {
    "dashboard_port": 5000,
    "ssh_port": 2022,
    "http_port": 2080,
    "ftp_port": 2021,
    "telnet_port": 2023,
    "smtp_port": 2025,
    "dns_port": 2053,

    "admin_user": "admin",
    "admin_pass": "admin123",
}
```

---

# 🔥 Firewall Setup

## Ubuntu / Debian Example

```bash
sudo ufw allow 2022/tcp
sudo ufw allow 2080/tcp
sudo ufw allow 2021/tcp
sudo ufw allow 2023/tcp
sudo ufw allow 2025/tcp
sudo ufw allow 2053/udp
sudo ufw allow 5000/tcp
```

---

# 📊 Dashboard Guide

## 🔐 Login Page

Access via:

```text
http://your-server-ip:5000
```

Default Credentials:

```text
Username: admin
Password: admin123
```

---

## 📈 Statistics Tab

Monitor:

- Total Events
- Alerts
- Attackers
- Risk Scores
- Attack Distribution
- Hourly Trends

---

## 🌍 Attack Map

Features:

- Real-time geolocation
- Interactive heatmaps
- Zoom & pan support
- Threat clustering

---

## 🚨 Alerts & Analytics

- Severity Filtering
- Alert Acknowledgement
- CSV Export
- Attack Trend Analysis

---

# 🧪 Testing the Honeypot

## 🌐 HTTP Honeypot

```bash
curl http://localhost:2080/admin

curl "http://localhost:2080/../../../../etc/passwd"
```

---

## 🔐 SSH Honeypot

```bash
ssh -p 2022 root@localhost
```

---

## 📂 FTP Honeypot

```bash
ftp localhost 2021
```

---

## 📡 Telnet Honeypot

```bash
telnet localhost 2023
```

---

# 🔌 API Reference

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/events` | Get recent events |
| GET | `/api/alerts` | Get alerts |
| GET | `/api/attackers` | Get attacker database |
| GET | `/api/stats` | Platform statistics |
| POST | `/api/clear` | Clear all data |
| POST | `/api/login` | Authenticate user |
| POST | `/api/logout` | Logout user |

---

## Example API Request

```bash
curl http://localhost:5000/api/stats
```

---

# 🚢 Deployment

## Run as Systemd Service (Linux)

### Create Service File

```bash
sudo nano /etc/systemd/system/parrypot.service
```

Paste:

```ini
[Unit]
Description=ParryPot Honeypot Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root/parrypot
ExecStart=/usr/bin/python3 /root/parrypot/parrypot.py

Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

---

## Enable & Start

```bash
sudo systemctl daemon-reload

sudo systemctl enable parrypot

sudo systemctl start parrypot
```

---

## Check Status

```bash
sudo systemctl status parrypot
```

---

# 🔧 Troubleshooting

| Problem | Solution |
|---|---|
| Port already in use | Change port or run `sudo fuser -k 5000/tcp` |
| Permission denied | Run with `sudo` |
| Module not found | Install dependencies |
| Dashboard inaccessible | Open firewall ports |

---

# 🛠️ Project Structure

```text
parrypot/
│
├── parrypot.py
├── requirements.txt
├── templates/
├── static/
├── logs/
├── screenshots/
└── README.md
```

---

# 🤝 Contributing

Contributions are welcome!

## Contribution Steps

```bash
# Fork the repository

# Create feature branch
git checkout -b feature/amazing-feature

# Commit changes
git commit -m "Add amazing feature"

# Push branch
git push origin feature/amazing-feature
```

Then open a Pull Request 🚀

---

# 📄 License

Distributed under the MIT License.

See `LICENSE` for more information.

---

# 🙏 Acknowledgments

Built with:

- Python
- Flask
- Chart.js
- Leaflet.js

Inspired by:

- Modern SOC Platforms
- Threat Intelligence Systems
- Security Research Communities

---

# 📞 Contact & Support

| Platform | Link |
|---|---|
| GitHub | `@parrysecurity` |
| Website | `parrysecurity.online` |
| Email | `securityparry@gmail.com` |

---

# ⭐ Support the Project

If ParryPot helps your security operations:

- ⭐ Star the repository
- 🍴 Fork the project
- 📢 Share with your team
- 🛡️ Contribute improvements

---

<div align="center">

# 🍯 Made with passion by ParrySecurity

### “Catch attackers before they catch you.”

</div>
