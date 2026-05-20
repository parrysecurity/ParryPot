<div align="center">
  
# 🍯 ParryPot

**Enterprise Honeypot Security Platform** *Deploy. Trap. Analyze. Protect.*

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey?style=for-the-badge)](#)
[![Status](https://img.shields.io/badge/Status-Production_Ready-brightgreen?style=for-the-badge)](#)
[![License](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)](#)
[![PRs Welcome](https://img.shields.io/badge/PRs-Welcome-orange?style=for-the-badge)](#contributing)

</div>

<br>

## 📌 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Architecture](#-architecture)
- [Quick Start](#-quick-start)
- [Installation](#-installation)
- [Configuration](#️-configuration)
- [Dashboard Guide](#-dashboard-guide)
- [Testing the Honeypot](#-testing-the-honeypot)
- [API Reference](#-api-reference)
- [Deployment](#-deployment)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)

---

## 🎯 Overview

**ParryPot** is a production‑ready honeypot platform developed by **ParrySecurity** that deploys deceptive services to trap, analyze, and visualize cyber attacks in real‑time. Built for SOC teams, security researchers, and red team operations, ParryPot transforms attacker reconnaissance into actionable threat intelligence.

### What Makes ParryPot Different?

| Feature | ParryPot | Traditional Honeypots |
| :--- | :--- | :--- |
| **Zero False Positives** | ✅ Every connection is malicious | ❌ Often flag legitimate traffic |
| **Real-time Visualization** | ✅ Live attack map with geolocation | ❌ Basic logging only |
| **Multi-Protocol** | ✅ 6 protocols out of the box | ⚠️ Usually single protocol |
| **Beautiful Dashboard** | ✅ Glassmorphism modern UI | ❌ Outdated interfaces |
| **Zero Configuration** | ✅ Run immediately | ⚠️ Complex setup required |

---

## ✨ Features

### 🎣 Honeypot Services

| Protocol | Port | Captured Data |
| :--- | :--- | :--- |
| **SSH** | `2022` | Usernames, passwords, commands, client fingerprints |
| **HTTP** | `2080` | SQL injection, XSS, path traversal, user agents |
| **FTP** | `2021` | Login attempts, file commands, directory listings |
| **Telnet** | `2023` | Full session logs, credentials, commands |
| **SMTP** | `2025` | Spam relay attempts, email headers, recipient data |
| **DNS** | `2053` | Domain queries, DNS tunneling detection |

### 📊 Dashboard Features
* **Live Attack Map** - Real-time geolocation of attackers with Leaflet.js.
* **Glassmorphism UI** - Modern frosted glass design with fluid animations.
* **Intelligent Alerting** - Severity-based alerts (Critical / High / Medium / Low).
* **Attacker Database** - Searchable, filterable, and sortable with export options.
* **Analytics Engine** - Attack trends, protocol distribution, and heatmaps.
* **Event Feed** - Real-time scrolling log of all active connections.

### 🛡️ Security Intelligence
* **Geolocation Mapping** - Plot attackers on a global map.
* **Threat Level Scoring** - Automatic risk assessment per IP address.
* **Protocol Fingerprinting** - Identify specific attack tools and techniques.
* **Payload Capture** - Full attack payloads for forensic analysis.
* **MITRE ATT&CK Mapping** - Map incoming attacks to the standard framework.

---

## 🏗️ Architecture

<details>
<summary><b>Click to view the System Architecture Diagram</b></summary>

```text
┌─────────────────────────────────────────────────────────────────┐
│                      PARRYPOT PLATFORM                          │
│                                                                 │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────────────┐ │
│  │   SSH:2022   │   │   HTTP:2080  │   │   FTP:2021           │ │
│  │   Telnet:2023│   │   SMTP:2025  │   │   DNS:2053           │ │
│  └──────┬───────┘   └──────┬───────┘   └──────────┬───────────┘ │
│         └──────────────────┼──────────────────────┘             │
│                            │                                    │
│         ┌──────────────────▼──────────────────┐                 │
│         │      Python Honeypot Engine         │                 │
│         │    Threaded protocol handlers       │                 │
│         └──────────────────┬──────────────────┘                 │
│                            │                                    │
│         ┌──────────────────▼──────────────────┐                 │
│         │          Shared State (RAM)         │                 │
│         │    Events • Alerts • Attackers      │                 │
│         └──────────────────┬──────────────────┘                 │
│                            │                                    │
│         ┌──────────────────▼──────────────────┐                 │
│         │      Flask/Dashboard (Port 5000)    │                 │
│         │    HTML/CSS/JS with Chart.js        │                 │
│         └─────────────────────────────────────┘                 │
│                            │                                    │
│                  ┌─────────▼─────────┐                          │
│                  │      Browser      │                          │
│                  │     Dashboard     │                          │
│                  └───────────────────┘                          │
└─────────────────────────────────────────────────────────────────┘
🚀 Quick Start
One Command Installation
git clone [https://github.com/parrysecurity/parrypot.git](https://github.com/parrysecurity/parrypot.git)
cd parrypot
sudo python3 parrypot.py
Done! Your honeypot is now running.

Access the dashboard: http://localhost:5000

Login: admin / admin123
📥 InstallationPrerequisitesRequirementSpecificationPython3.10 or higherPackage Managerpip (Latest)OS SupportLinux / Windows / macOSMemory512MB RAM minimumStorage100MB free spaceStep-by-Step InstallationLinux / macOS
# Clone repository
git clone [https://github.com/parrysecurity/parrypot.git](https://github.com/parrysecurity/parrypot.git)
cd parrypot

# Install Python dependencies
pip3 install -r requirements.txt

# Run with sudo (required for low ports)
sudo python3 parrypot.py
Windows
# Clone repository
git clone [https://github.com/parrysecurity/parrypot.git](https://github.com/parrysecurity/parrypot.git)
cd parrypot

# Install dependencies
pip install -r requirements.txt

# Run as Administrator
python parrypot.py
⚙️ Configuration
Edit the CONFIG dictionary in parrypot.py to customize your ports and credentials:
CONFIG = {
    "dashboard_port": 5000,    # Web dashboard
    "ssh_port": 2022,          # SSH honeypot
    "http_port": 2080,         # HTTP honeypot
    "ftp_port": 2021,          # FTP honeypot
    "telnet_port": 2023,       # Telnet honeypot
    "smtp_port": 2025,         # SMTP honeypot
    "dns_port": 2053,          # DNS honeypot
    "admin_user": "admin",     # Dashboard username
    "admin_pass": "admin123",  # Dashboard password
}
Firewall Setup (Ubuntu/Debian Example)
Ensure you allow incoming connections to your honeypot ports:
sudo ufw allow 2022/tcp
sudo ufw allow 2080/tcp
sudo ufw allow 2021/tcp
sudo ufw allow 2023/tcp
sudo ufw allow 2025/tcp
sudo ufw allow 2053/udp
sudo ufw allow 5000/tcp
📊 Dashboard Guide
Login Page: Access via http://your-server-ip:5000 (Default: admin/admin123). Features a 3D animated background with floating particles.

Statistics Tab: View total events, alerts, attackers, risk scores, and attack distributions (Doughnut/Bar charts).

Attack Map Tab: Real-time geolocation of attackers with interactive zoom/pan and heatmap layers.

Alerts & Analytics: Filter by severity, acknowledge individual alerts, export to CSV, and analyze hourly attack trends.

🧪 Testing the Honeypot
Use these commands to simulate attacks and test your setup:
# Test HTTP honeypot
curl http://localhost:2080/admin
curl "http://localhost:2080/../../../../etc/passwd"

# Test SSH honeypot (Accepts any credentials)
ssh -p 2022 root@localhost

# Test FTP honeypot
ftp localhost 2021

# Test Telnet honeypot
telnet localhost 2023
🔌 API ReferenceMethodEndpointDescriptionGET/api/eventsGet recent eventsGET/api/alertsGet security alertsGET/api/attackersGet attacker databaseGET/api/statsGet platform statisticsPOST/api/clearClear all dataPOST/api/loginAuthenticate userPOST/api/logoutLogout userExample API Call:
curl http://localhost:5000/api/stats
🚢 Deployment
Run as Systemd Service (Linux)
Keep ParryPot running permanently in the background:
# Create service file
sudo cat > /etc/systemd/system/parrypot.service << EOF
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
EOF

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable parrypot
sudo systemctl start parrypot
🔧 TroubleshootingIssueSolutionPort already in useChange the port in CONFIG or kill the existing process: sudo fuser -k 5000/tcpPermission deniedRun with sudo (required for binding ports below 1024).Module not foundEnsure you ran pip3 install -r requirements.txt.Dashboard not loadingCheck your firewall settings: sudo ufw allow 5000/tcp.🤝 ContributingWe welcome contributions!Fork the repository.Create a feature branch (git checkout -b feature/amazing-feature).Commit your changes (git commit -m "Add amazing feature").Push to the branch (git push origin feature/amazing-feature).Open a Pull Request.📄 LicenseDistributed under the MIT License. See LICENSE for more information.🙏 AcknowledgmentsBuilt with Python, Chart.js, and Leaflet.js.Inspired by modern SOC requirements.Glassmorphism design elements sourced from the Figma community.📞 Contact & SupportIf ParryPot helps your security operations, please consider showing your support:⭐ Star the repository on GitHub!📢 Share it with your security team.ChannelLinkGitHub@parrysecurityWebsiteparrysecurity.online IssuesReport a BugMade with 🍯 by ParrySecurity Catch attackers before they catch you.
