# 📖 COMPLETE README.md FOR PARRYPOT

```markdown
<div align="center">
  
# 🍯 ParryPot

## Enterprise Honeypot Security Platform

**Deploy. Trap. Analyze. Protect.**

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey)](https://github.com/parrysecurity/parrypot)
[![Status](https://img.shields.io/badge/Status-Production_Ready-brightgreen)](https://github.com/parrysecurity/parrypot)
[![PRs](https://img.shields.io/badge/PRs-Welcome-orange)](https://github.com/parrysecurity/parrypot)

</div>

---

## 📌 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Configuration](#configuration)
- [Dashboard Guide](#dashboard-guide)
- [Testing the Honeypot](#testing-the-honeypot)
- [API Reference](#api-reference)
- [Deployment](#deployment)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

---

## 🎯 Overview

**ParryPot** is a production‑ready honeypot platform developed by **ParrySecurity** that deploys deceptive services to trap, analyze, and visualize cyber attacks in real‑time. Built for SOC teams, security researchers, and red team operations, ParryPot transforms attacker reconnaissance into actionable threat intelligence.

### What Makes ParryPot Different?

| Feature | ParryPot | Traditional Honeypots |
|---------|----------|----------------------|
| **Zero False Positives** | ✅ Every connection is malicious | ❌ Often flag legitimate traffic |
| **Real-time Visualization** | ✅ Live attack map with geolocation | ❌ Basic logging only |
| **Multi-Protocol** | ✅ 6 protocols out of the box | ⚠️ Usually single protocol |
| **Beautiful Dashboard** | ✅ Glassmorphism modern UI | ❌ Outdated interfaces |
| **Zero Configuration** | ✅ Run immediately | ⚠️ Complex setup required |

---

## ✨ Features

### 🎣 Honeypot Services

| Protocol | Port | Captured Data |
|----------|------|---------------|
| **SSH** | 2022 | Usernames, passwords, commands, client fingerprints |
| **HTTP** | 2080 | SQL injection, XSS, path traversal, user agents |
| **FTP** | 2021 | Login attempts, file commands, directory listings |
| **Telnet** | 2023 | Full session logs, credentials, commands |
| **SMTP** | 2025 | Spam relay attempts, email headers, recipient data |
| **DNS** | 2053 | Domain queries, DNS tunneling detection |

### 📊 Dashboard Features

- **Live Attack Map** - Real-time geolocation of attackers with Leaflet.js
- **Glassmorphism UI** - Modern frosted glass design with animations
- **Intelligent Alerting** - Severity-based alerts (Critical/High/Medium/Low)
- **Attacker Database** - Searchable, filterable, sortable with export
- **Analytics Engine** - Attack trends, protocol distribution, heatmaps
- **Event Feed** - Real-time scrolling log of all connections
- **Payload Analysis** - Raw attack payloads with copy/block functionality
- **Export Reports** - CSV/PDF export for compliance

### 🛡️ Security Intelligence

- **Geolocation Mapping** - Plot attackers on world map
- **Threat Level Scoring** - Automatic risk assessment per IP
- **Protocol Fingerprinting** - Identify attack tools and techniques
- **Payload Capture** - Full attack payloads for forensics
- **MITRE ATT&CK Mapping** - Map attacks to framework

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      PARRYPOT PLATFORM                          │
│                                                                 │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────────────┐│
│  │   SSH:2022   │   │   HTTP:2080  │   │   FTP:2021           ││
│  │   Telnet:2023│   │   SMTP:2025  │   │   DNS:2053           ││
│  └──────┬───────┘   └──────┬───────┘   └──────────┬───────────┘│
│         └──────────────────┼──────────────────────┘            │
│                            │                                    │
│         ┌──────────────────▼──────────────────┐                │
│         │      Python Honeypot Engine         │                │
│         │   Threaded protocol handlers        │                │
│         └──────────────────┬──────────────────┘                │
│                            │                                    │
│         ┌──────────────────▼──────────────────┐                │
│         │         Shared State (RAM)          │                │
│         │   Events • Alerts • Attackers       │                │
│         └──────────────────┬──────────────────┘                │
│                            │                                    │
│         ┌──────────────────▼──────────────────┐                │
│         │      Flask/Dashboard (Port 5000)    │                │
│         │   HTML/CSS/JS with Chart.js/Leaflet │                │
│         └─────────────────────────────────────┘                │
│                            │                                    │
│                    ┌───────▼───────┐                           │
│                    │   Browser     │                           │
│                    │   Dashboard   │                           │
│                    └───────────────┘                           │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start

### One Command Installation

```bash
git clone https://github.com/parrysecurity/parrypot.git
cd parrypot
sudo python3 parrypot.py
```

**Done!** Your honeypot is now running.

Access the dashboard: `http://localhost:5000`  
Login: `admin` / `admin123`

---

## 📥 Installation

### Prerequisites

| Requirement | Version |
|-------------|---------|
| Python | 3.10+ |
| pip | Latest |
| OS | Linux/Windows/macOS |
| RAM | 512MB minimum |
| Storage | 100MB |

### Step-by-Step Installation

#### Linux / macOS

```bash
# Clone repository
git clone https://github.com/parrysecurity/parrypot.git
cd parrypot

# Install Python dependencies
pip3 install -r requirements.txt

# Run with sudo (for low ports)
sudo python3 parrypot.py
```

#### Windows

```powershell
# Clone repository
git clone https://github.com/parrysecurity/parrypot.git
cd parrypot

# Install dependencies
pip install -r requirements.txt

# Run as Administrator
python parrypot.py
```

#### Docker (Coming Soon)

```bash
docker run -p 5000:5000 -p 2022:2022 -p 2080:2080 parrysecurity/parrypot
```

---

## ⚙️ Configuration

### Port Configuration

Edit the `CONFIG` dictionary in `parrypot.py`:

```python
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
```

### Changing Admin Credentials

```python
# Change these lines
"admin_user": "your_username",
"admin_pass": "your_strong_password",
```

### Firewall Configuration

Allow incoming connections to honeypot ports:

```bash
# UFW (Ubuntu/Debian)
sudo ufw allow 2022/tcp
sudo ufw allow 2080/tcp
sudo ufw allow 2021/tcp
sudo ufw allow 2023/tcp
sudo ufw allow 2025/tcp
sudo ufw allow 2053/udp
sudo ufw allow 5000/tcp

# iptables
sudo iptables -A INPUT -p tcp --dport 2022 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 2080 -j ACCEPT
# ... repeat for other ports
```

---

## 📊 Dashboard Guide

### Login Page

- URL: `http://your-server-ip:5000`
- Default credentials: `admin` / `admin123`
- 3D animated background with floating particles

### Dashboard Tab

| Widget | Description |
|--------|-------------|
| **Statistics Cards** | Total events, alerts, attackers, risk score |
| **Attack Distribution** | Doughnut chart by protocol |
| **Top Attackers** | Bar chart of most active IPs |
| **Live Event Feed** | Real-time scrolling log |
| **Severity Counters** | Critical/High/Medium/Low breakdown |

### Attack Map Tab

- Real-time geolocation of attackers
- Interactive zoom/pan
- Attack markers with popup details
- Heatmap layer for attack density

### Alerts Tab

- Severity-based alert list
- Filter by severity level
- Acknowledge individual alerts
- Export alerts to CSV

### Attackers Database Tab

- Search by IP address
- Filter by threat level
- Filter by protocol
- Sortable columns
- Export to CSV
- Pagination (20 per page)

### Analytics Tab

- Hourly attack trend chart
- Protocol breakdown (stacked bars)
- Top threat countries
- Captured payloads with copy functionality

### Settings Tab

- Auto-refresh interval control
- Clear all data
- System information display

---

## 🧪 Testing the Honeypot

### Test Commands

```bash
# Test HTTP honeypot
curl http://localhost:2080/admin
curl "http://localhost:2080/?id=1' OR '1'='1"
curl "http://localhost:2080/../../../../etc/passwd"

# Test SSH honeypot
ssh -p 2022 root@localhost
# Try any username/password - it will always accept

# Test FTP honeypot
ftp localhost 2021
# Username: any, Password: any

# Test Telnet honeypot
telnet localhost 2023
# Any login attempt works

# Test SMTP honeypot
echo "QUIT" | nc localhost 2025

# Test DNS honeypot
dig @localhost -p 2053 google.com
```

### Automated Testing Script

```bash
#!/bin/bash
# Save as test_parrypot.sh

echo "Testing ParryPot Honeypot..."

# HTTP Tests
echo "→ Testing HTTP honeypot..."
curl -s http://localhost:2080/admin > /dev/null
echo "  ✓ HTTP request sent"

# SSH Tests
echo "→ Testing SSH honeypot..."
echo "test" | nc -w 2 localhost 2022 > /dev/null
echo "  ✓ SSH connection sent"

# FTP Tests
echo "→ Testing FTP honeypot..."
echo "QUIT" | nc -w 2 localhost 2021 > /dev/null
echo "  ✓ FTP connection sent"

echo ""
echo "✅ All tests complete!"
echo "Open dashboard: http://localhost:5000"
```

---

## 🔌 API Reference

### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/events` | Get recent events |
| GET | `/api/alerts` | Get security alerts |
| GET | `/api/attackers` | Get attacker database |
| GET | `/api/stats` | Get platform statistics |
| POST | `/api/clear` | Clear all data |
| POST | `/api/login` | Authenticate user |
| POST | `/api/logout` | Logout user |

### Example API Calls

```bash
# Get statistics
curl http://localhost:5000/api/stats

# Get recent events
curl http://localhost:5000/api/events

# Get attackers
curl http://localhost:5000/api/attackers

# Clear all data (requires auth)
curl -X POST http://localhost:5000/api/clear \
  -H "Cookie: hp_session=YOUR_TOKEN"
```

---

## 🚢 Deployment

### Deploy on VPS (DigitalOcean, AWS, Linode)

```bash
# 1. Connect to your VPS
ssh root@your-server-ip

# 2. Install Python and git
apt update && apt install -y python3 python3-pip git

# 3. Clone and run
git clone https://github.com/parrysecurity/parrypot.git
cd parrypot
pip3 install -r requirements.txt
sudo python3 parrypot.py
```

### Run as Systemd Service (Linux)

```bash
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

# Check status
sudo systemctl status parrypot
```

### Deploy with Screen

```bash
# Install screen
apt install screen -y

# Start in screen session
screen -S parrypot
sudo python3 parrypot.py

# Detach: Ctrl+A, then D
# Reattach: screen -r parrypot
```

### Deploy on Raspberry Pi

```bash
# Works perfectly on Raspberry Pi 3/4/5
git clone https://github.com/parrysecurity/parrypot.git
cd parrypot
sudo python3 parrypot.py

# Access from network: http://raspberry-pi-ip:5000
```

---

## 🔧 Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| **Port already in use** | Change port in CONFIG or kill existing process: `sudo fuser -k 5000/tcp` |
| **Permission denied** | Run with `sudo` for ports below 1024 |
| **Module not found** | Install dependencies: `pip3 install -r requirements.txt` |
| **Dashboard not loading** | Check firewall: `sudo ufw allow 5000/tcp` |
| **No events showing** | Test with curl commands above |

### View Logs

```bash
# If running in terminal, logs appear directly
# If as service: journalctl -u parrypot -f
```

### Reset Everything

```bash
# Stop service
sudo systemctl stop parrypot

# Clear data via dashboard (Settings → Clear Data)
# Or restart fresh
sudo rm -rf /tmp/parrypot_data
```

---

## 🤝 Contributing

We welcome contributions!

```bash
# Fork the repository
# Then clone your fork
git clone https://github.com/your-username/parrypot.git
cd parrypot

# Create a feature branch
git checkout -b feature/amazing-feature

# Make your changes
# Commit and push
git commit -m "Add amazing feature"
git push origin feature/amazing-feature

# Create a Pull Request
```

### Development Setup

```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/

# Run linting
flake8 parrypot.py
```

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.

```
MIT License

Copyright (c) 2024 ParrySecurity

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction...
```

---

## 🙏 Acknowledgments

- Built with Python, Chart.js, Leaflet.js
- Inspired by modern SOC requirements
- Glassmorphism design from Figma community

---

## 📞 Contact

| Channel | Link |
|---------|------|
| **GitHub** | [@parrysecurity](https://github.com/parrysecurity) |
| **Website** | [parrysecurity.com](https://parrysecurity.com) |
| **Issues** | [GitHub Issues](https://github.com/parrysecurity/parrypot/issues) |

---

## ⭐ Show Your Support

If ParryPot helps your security operations:

- ⭐ Star the repository on GitHub
- 🐛 Report issues
- 🔀 Submit pull requests
- 📢 Share with your security team

---

<div align="center">
  
**Made with 🍯 by ParrySecurity**

*Catch attackers before they catch you.*

</div>
```
