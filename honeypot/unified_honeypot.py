#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║         HONEYPOT SECURITY PLATFORM v3.0                     ║
║   Light-theme SOC dashboard · Real map · Live data only     ║
╚══════════════════════════════════════════════════════════════╝
"""

import socket
import threading
import json
import time
import os
import secrets
import random
from datetime import datetime
from http.server import BaseHTTPRequestHandler
import socketserver
from collections import defaultdict, deque
from urllib.parse import urlparse

# ═══════════════════════════════════════════════════════════
#  CONFIGURATION
# ═══════════════════════════════════════════════════════════

CONFIG = {
    "dashboard_port": 5000,
    "ssh_port":       2022,
    "http_port":      2080,
    "ftp_port":       2021,
    "telnet_port":    2023,
    "smtp_port":      2025,
    "dns_port":       2053,
    "admin_user":     "admin",
    "admin_pass":     "admin123",
    "session_timeout": 3600,
    "max_events":     2000,
    "max_alerts":     500,
    "demo_mode":      True,   # set False for real traffic only
}

# ═══════════════════════════════════════════════════════════
#  SHARED STATE
# ═══════════════════════════════════════════════════════════

events         = deque(maxlen=CONFIG["max_events"])
alerts         = deque(maxlen=CONFIG["max_alerts"])
attackers      = {}
sessions       = {}
hourly_data    = defaultdict(int)
protocol_stats = defaultdict(int)
blocked_ips    = set()
state_lock     = threading.Lock()

# ═══════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════

def get_server_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]; s.close(); return ip
    except:
        return "127.0.0.1"

SERVER_IP = get_server_ip()

FAKE_GEO = {
    "185.220.101": {"country":"Russia",         "city":"Moscow",      "lat":55.75, "lon":37.62,   "flag":"🇷🇺"},
    "91.219.236":  {"country":"Ukraine",        "city":"Kyiv",        "lat":50.45, "lon":30.52,   "flag":"🇺🇦"},
    "103.21.244":  {"country":"China",          "city":"Beijing",     "lat":39.91, "lon":116.39,  "flag":"🇨🇳"},
    "198.199.120": {"country":"United States",  "city":"New York",    "lat":40.71, "lon":-74.00,  "flag":"🇺🇸"},
    "45.33.32":    {"country":"United States",  "city":"Dallas",      "lat":32.78, "lon":-96.80,  "flag":"🇺🇸"},
    "77.88.55":    {"country":"Germany",        "city":"Frankfurt",   "lat":50.11, "lon":8.68,    "flag":"🇩🇪"},
    "51.68.138":   {"country":"France",         "city":"Paris",       "lat":48.85, "lon":2.35,    "flag":"🇫🇷"},
    "178.128.0":   {"country":"Netherlands",    "city":"Amsterdam",   "lat":52.37, "lon":4.89,    "flag":"🇳🇱"},
    "46.101.0":    {"country":"United Kingdom", "city":"London",      "lat":51.51, "lon":-0.13,   "flag":"🇬🇧"},
    "103.103.0":   {"country":"India",          "city":"Mumbai",      "lat":19.08, "lon":72.88,   "flag":"🇮🇳"},
    "43.132.0":    {"country":"Singapore",      "city":"Singapore",   "lat":1.29,  "lon":103.85,  "flag":"🇸🇬"},
    "190.14.37":   {"country":"Brazil",         "city":"São Paulo",   "lat":-23.55,"lon":-46.63,  "flag":"🇧🇷"},
    "41.223.0":    {"country":"Nigeria",        "city":"Lagos",       "lat":6.52,  "lon":3.38,    "flag":"🇳🇬"},
    "192.168.1":   {"country":"Local Network",  "city":"LAN",         "lat":0,     "lon":0,       "flag":"🏠"},
    "10.0.0":      {"country":"Local Network",  "city":"LAN",         "lat":0,     "lon":0,       "flag":"🏠"},
    "61.135.169":  {"country":"China",          "city":"Shanghai",    "lat":31.23, "lon":121.47,  "flag":"🇨🇳"},
    "5.188.10":    {"country":"Russia",         "city":"St Petersburg","lat":59.93,"lon":30.32,   "flag":"🇷🇺"},
    "185.156.73":  {"country":"Romania",        "city":"Bucharest",   "lat":44.43, "lon":26.10,   "flag":"🇷🇴"},
    "196.216.2":   {"country":"South Africa",   "city":"Cape Town",   "lat":-33.93,"lon":18.42,   "flag":"🇿🇦"},
    "203.0.113":   {"country":"Australia",      "city":"Sydney",      "lat":-33.87,"lon":151.21,  "flag":"🇦🇺"},
    "80.82.77":    {"country":"Netherlands",    "city":"Rotterdam",   "lat":51.92, "lon":4.48,    "flag":"🇳🇱"},
    "193.32.127":  {"country":"Sweden",         "city":"Stockholm",   "lat":59.33, "lon":18.07,   "flag":"🇸🇪"},
    "187.59.9":    {"country":"Brazil",         "city":"Rio",         "lat":-22.91,"lon":-43.17,  "flag":"🇧🇷"},
    "211.143.254": {"country":"South Korea",    "city":"Seoul",       "lat":37.57, "lon":126.98,  "flag":"🇰🇷"},
    "117.18.232":  {"country":"Hong Kong",      "city":"Hong Kong",   "lat":22.32, "lon":114.17,  "flag":"🇭🇰"},
}

def get_geo(ip):
    prefix3 = ".".join(ip.split(".")[:3])
    if prefix3 in FAKE_GEO:
        return FAKE_GEO[prefix3]
    prefix2 = ".".join(ip.split(".")[:2])
    for k, v in FAKE_GEO.items():
        if k.startswith(prefix2):
            return v
    return {"country":"Unknown","city":"Unknown","lat":random.uniform(-55,65),"lon":random.uniform(-160,160),"flag":"🌐"}

def compute_threat(count):
    if count >= 50: return "CRITICAL"
    if count >= 20: return "HIGH"
    if count >= 5:  return "MEDIUM"
    return "LOW"

SSH_USERS  = ["root","admin","ubuntu","pi","oracle","postgres","test","deploy","git","jenkins"]
SSH_PASSES = ["password","123456","admin","root","toor","pass","qwerty","letmein","changeme","1q2w3e"]
HTTP_PROBES = [
    "GET /admin HTTP/1.1","GET /wp-admin/admin-ajax.php HTTP/1.1","GET /.env HTTP/1.1",
    "GET /phpmyadmin/ HTTP/1.1","POST /login?user=admin'-- HTTP/1.1","GET /shell.php?cmd=id HTTP/1.1",
    "GET /etc/passwd HTTP/1.1","GET /?id=1 UNION SELECT 1,2,3-- HTTP/1.1","GET /wp-config.php HTTP/1.1",
    "GET /manager/html HTTP/1.1","POST /xmlrpc.php HTTP/1.1","GET /.git/config HTTP/1.1",
    "GET /api/v1/users HTTP/1.1","GET /actuator/env HTTP/1.1","POST /api/auth/login HTTP/1.1",
]
FTP_CMDS  = ["USER anonymous","USER admin","USER root","PASS password","LIST","RETR /etc/passwd","STOR backdoor.php"]
SMTP_CMDS = ["EHLO attacker.com","MAIL FROM:<spam@evil.com>","RCPT TO:<victim@target.com>","VRFY root"]

def classify_http(payload):
    l = payload.lower()
    if "union select" in l or "' or" in l or "1=1" in l: return "SQL Injection"
    if "<script" in l or "javascript:" in l or "onerror=" in l: return "XSS Attempt"
    if "cmd=" in l or "/etc/passwd" in l or "system(" in l: return "Command Injection / RCE"
    if "wp-admin" in l or "phpmyadmin" in l or "/.env" in l or ".git" in l: return "Recon / Path Traversal"
    if "xmlrpc" in l: return "XML-RPC Abuse"
    if "actuator" in l or "/api/" in l: return "API Enumeration"
    if "/admin" in l or "/manager" in l: return "Admin Panel Probe"
    return "HTTP Scanner"

# ═══════════════════════════════════════════════════════════
#  ADD EVENT
# ═══════════════════════════════════════════════════════════

def add_event(protocol, src_ip, details="", payload="", severity=None):
    with state_lock:
        hour_key = datetime.now().strftime("%H")
        hourly_data[hour_key] += 1
        protocol_stats[protocol] += 1
        geo = get_geo(src_ip)

        if src_ip not in attackers:
            attackers[src_ip] = {
                "count": 0, "first_seen": datetime.now().isoformat(),
                "last_seen": datetime.now().isoformat(),
                "protocols": set(), "payloads": [], "geo": geo,
                "threat_level": "LOW", "blocked": src_ip in blocked_ips,
            }
        atk = attackers[src_ip]
        atk["count"] += 1
        atk["last_seen"] = datetime.now().isoformat()
        atk["protocols"].add(protocol)
        if payload:
            atk["payloads"].append(payload[:200])
            if len(atk["payloads"]) > 20: atk["payloads"].pop(0)
        atk["threat_level"] = compute_threat(atk["count"])
        if severity is None: severity = atk["threat_level"]

        event = {
            "id": secrets.token_hex(4),
            "time": datetime.now().strftime("%H:%M:%S"),
            "date": datetime.now().strftime("%Y-%m-%d"),
            "protocol": protocol, "src_ip": src_ip,
            "details": details, "payload": payload[:150] if payload else "",
            "severity": severity, "geo": geo, "timestamp": time.time(),
        }
        events.appendleft(event)

        count = atk["count"]
        if count in (5, 10, 25, 50, 100):
            sev = "CRITICAL" if count >= 50 else "HIGH" if count >= 10 else "MEDIUM"
            titles = {5:"Repeated Connections",10:"Brute Force Detected",25:"Persistent Attacker",50:"Active Campaign",100:"Sustained Attack"}
            alert = {
                "id": secrets.token_hex(4), "time": datetime.now().strftime("%H:%M:%S"),
                "date": datetime.now().strftime("%Y-%m-%d"), "severity": sev,
                "title": titles[count],
                "message": f"{count} attempts from {src_ip} ({geo['country']}) via {protocol}",
                "src_ip": src_ip, "geo": geo, "protocol": protocol,
            }
            alerts.appendleft(alert)
        print(f"  [{protocol:6}] {src_ip:20} {details[:60]}")
        return event

# ═══════════════════════════════════════════════════════════
#  SESSION
# ═══════════════════════════════════════════════════════════

def create_session(username):
    token = secrets.token_hex(32)
    sessions[token] = {"user": username, "created_at": time.time()}
    return token

def validate_session(token):
    if not token or token not in sessions: return False
    if time.time() - sessions[token]["created_at"] > CONFIG["session_timeout"]:
        del sessions[token]; return False
    return True

def get_session_token(handler):
    for part in handler.headers.get("Cookie","").split(";"):
        part = part.strip()
        if part.startswith("hp_session="): return part[len("hp_session="):]
    return None

# ═══════════════════════════════════════════════════════════
#  HONEYPOT SERVERS
# ═══════════════════════════════════════════════════════════

def start_ssh_honeypot(port):
    class H(socketserver.BaseRequestHandler):
        def handle(self):
            ip = self.client_address[0]
            try:
                self.request.settimeout(10)
                self.request.sendall(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n")
                data = self.request.recv(1024).decode("utf-8", errors="replace")
                user = next((u for u in SSH_USERS if u in data), "unknown")
                add_event("SSH", ip, f"SSH brute force – user: {user}", f"USER:{user}")
            except: add_event("SSH", ip, "SSH connection probe")
    _serve_tcp(port, "SSH", H)

def start_http_honeypot(port):
    class H(socketserver.BaseRequestHandler):
        def handle(self):
            ip = self.client_address[0]
            try:
                self.request.settimeout(10)
                data = self.request.recv(4096).decode("utf-8", errors="replace")
                first = data.split("\n")[0].strip() if data else "empty"
                atype = classify_http(data)
                sev = "HIGH" if any(x in atype for x in ["Injection","RCE","XSS"]) else "MEDIUM"
                add_event("HTTP", ip, atype, first, sev)
                self.request.sendall(b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.54\r\nContent-Type: text/html\r\n\r\n<h1>It works!</h1>")
            except: add_event("HTTP", ip, "HTTP probe")
    _serve_tcp(port, "HTTP", H)

def start_ftp_honeypot(port):
    class H(socketserver.BaseRequestHandler):
        def handle(self):
            ip = self.client_address[0]
            try:
                self.request.settimeout(15)
                self.request.sendall(b"220 ProFTPD 1.3.5 Server ready.\r\n")
                user = "unknown"
                for _ in range(8):
                    data = self.request.recv(1024).decode("utf-8", errors="replace").strip()
                    if not data: break
                    if data.upper().startswith("USER"):
                        user = data[5:].strip()
                        add_event("FTP", ip, f"FTP login – user: {user}", data)
                        self.request.sendall(b"331 Password required.\r\n")
                    elif data.upper().startswith("PASS"):
                        add_event("FTP", ip, "FTP password attempt", f"USER:{user}", "HIGH")
                        self.request.sendall(b"530 Login incorrect.\r\n"); break
                    elif data.upper() in ("QUIT","BYE"): break
                    else:
                        add_event("FTP", ip, f"FTP command: {data[:50]}", data)
                        self.request.sendall(b"500 Unknown command.\r\n")
            except: add_event("FTP", ip, "FTP probe")
    _serve_tcp(port, "FTP", H)

def start_telnet_honeypot(port):
    class H(socketserver.BaseRequestHandler):
        def handle(self):
            ip = self.client_address[0]
            try:
                self.request.settimeout(15)
                self.request.sendall(b"\r\nUbuntu 22.04.3 LTS\r\n\r\nlogin: ")
                user = self.request.recv(256).decode("utf-8", errors="replace").strip()
                add_event("Telnet", ip, f"Telnet login – user: {user}", user)
                self.request.sendall(b"Password: ")
                pwd = self.request.recv(256).decode("utf-8", errors="replace").strip()
                add_event("Telnet", ip, "Telnet password attempt", f"{user}:{pwd[:20]}", "HIGH")
                self.request.sendall(b"\r\nLogin incorrect\r\n")
            except: add_event("Telnet", ip, "Telnet probe")
    _serve_tcp(port, "Telnet", H)

def start_smtp_honeypot(port):
    class H(socketserver.BaseRequestHandler):
        def handle(self):
            ip = self.client_address[0]
            try:
                self.request.settimeout(15)
                self.request.sendall(b"220 mail.company.com ESMTP Postfix\r\n")
                for _ in range(15):
                    data = self.request.recv(1024).decode("utf-8", errors="replace").strip()
                    if not data: break
                    up = data.upper()
                    if up.startswith("EHLO") or up.startswith("HELO"):
                        add_event("SMTP", ip, f"SMTP: {data[:60]}", data)
                        self.request.sendall(b"250 OK\r\n")
                    elif up.startswith("MAIL FROM"):
                        add_event("SMTP", ip, f"SMTP MAIL FROM: {data[10:50]}", data, "MEDIUM")
                        self.request.sendall(b"250 OK\r\n")
                    elif up.startswith("RCPT TO"):
                        add_event("SMTP", ip, "SMTP relay attempt", data, "HIGH")
                        self.request.sendall(b"250 OK\r\n")
                    elif up.startswith("DATA"):
                        self.request.sendall(b"354 End with <CR><LF>.<CR><LF>\r\n")
                    elif up in ("QUIT","."): break
                    else: self.request.sendall(b"500 Unknown\r\n")
            except: add_event("SMTP", ip, "SMTP probe")
    _serve_tcp(port, "SMTP", H)

def start_dns_honeypot(port):
    class H(socketserver.BaseRequestHandler):
        def handle(self):
            ip = self.client_address[0]
            data = self.request[0]
            domain = "unknown"
            try:
                offset, parts = 12, []
                while offset < len(data):
                    l = data[offset]
                    if l == 0: break
                    parts.append(data[offset+1:offset+1+l].decode("utf-8", errors="replace"))
                    offset += 1 + l
                domain = ".".join(parts)
            except: pass
            add_event("DNS", ip, f"DNS query: {domain}", domain)
    try:
        with socketserver.UDPServer(("0.0.0.0", port), H) as server:
            print(f"  ✓ DNS:{port}"); server.serve_forever()
    except OSError as e: print(f"  ✗ DNS:{port} – {e}")

def _serve_tcp(port, name, handler_class):
    try:
        socketserver.TCPServer.allow_reuse_address = True
        with socketserver.TCPServer(("0.0.0.0", port), handler_class) as server:
            print(f"  ✓ {name}:{port}"); server.serve_forever()
    except OSError as e: print(f"  ✗ {name}:{port} – {e}")

# ═══════════════════════════════════════════════════════════
#  DEMO GENERATOR  (only runs when demo_mode=True)
# ═══════════════════════════════════════════════════════════

def demo_event_generator():
    demo_ips = list({".".join(k.split(".")[:3])+"."+str(random.randint(1,254)) for k in FAKE_GEO.keys()})
    tick = 0
    while True:
        time.sleep(random.uniform(1.2, 3.5))
        tick += 1
        ip = random.choice(demo_ips)
        roll = tick % 7
        if roll == 0:
            u = random.choice(SSH_USERS)
            add_event("SSH", ip, f"SSH brute force – user: {u}", f"USER:{u} PASS:{random.choice(SSH_PASSES)}", "HIGH")
        elif roll == 1:
            a = random.choice(HTTP_PROBES)
            add_event("HTTP", ip, classify_http(a), a)
        elif roll == 2:
            c = random.choice(FTP_CMDS)
            add_event("FTP", ip, f"FTP: {c}", c)
        elif roll == 3:
            u = random.choice(SSH_USERS)
            add_event("Telnet", ip, f"Telnet attempt: {u}", f"{u}:{random.choice(SSH_PASSES)}", "HIGH")
        elif roll == 4:
            c = random.choice(SMTP_CMDS)
            add_event("SMTP", ip, f"SMTP: {c}", c)
        elif roll == 5:
            add_event("DNS", ip, "DNS amplification probe", "ANY example.com", "MEDIUM")
        else:
            add_event("HTTP", ip, "Web scanner / crawler", "GET / HTTP/1.1", "LOW")

# ═══════════════════════════════════════════════════════════
#  HTML PAGES
# ═══════════════════════════════════════════════════════════

LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetWatch · Secure Login</title>
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@300;400;500;600&family=DM+Mono:wght@400;500&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --bg:#f0f4ff;--card:#ffffff;--border:#dde3f0;
  --accent:#4f46e5;--accent2:#06b6d4;--danger:#ef4444;
  --text:#1e2235;--text2:#6b7280;--muted:#9ca3af;
  --green:#10b981;--orange:#f59e0b;
}
body{font-family:'DM Sans',sans-serif;background:var(--bg);min-height:100vh;
  display:flex;align-items:center;justify-content:center;position:relative;overflow:hidden}
.bg-grid{position:fixed;inset:0;
  background-image:linear-gradient(rgba(79,70,229,0.04) 1px,transparent 1px),
    linear-gradient(90deg,rgba(79,70,229,0.04) 1px,transparent 1px);
  background-size:40px 40px;z-index:0}
.orb{position:fixed;border-radius:50%;filter:blur(80px);opacity:.35;z-index:0;pointer-events:none}
.orb1{width:500px;height:500px;background:radial-gradient(circle,#c7d2fe,transparent);top:-100px;right:-100px}
.orb2{width:400px;height:400px;background:radial-gradient(circle,#a5f3fc,transparent);bottom:-80px;left:-80px}
.card{position:relative;z-index:1;background:var(--card);border:1px solid var(--border);
  border-radius:24px;padding:48px 44px;width:440px;max-width:95vw;
  box-shadow:0 20px 60px rgba(79,70,229,0.1),0 1px 0 rgba(255,255,255,0.8) inset}
.logo-wrap{text-align:center;margin-bottom:36px}
.logo{width:60px;height:60px;border-radius:18px;margin:0 auto 16px;
  background:linear-gradient(135deg,var(--accent),var(--accent2));
  display:flex;align-items:center;justify-content:center;
  box-shadow:0 8px 24px rgba(79,70,229,0.3)}
.logo i{color:#fff;font-size:24px}
.logo-wrap h1{font-size:1.5rem;font-weight:600;color:var(--text);letter-spacing:-.3px}
.logo-wrap p{color:var(--text2);font-size:.85rem;margin-top:4px}
.status{display:flex;align-items:center;gap:8px;background:#f0fdf4;border:1px solid #bbf7d0;
  border-radius:10px;padding:10px 14px;margin-bottom:28px;font-size:.8rem;
  font-family:'DM Mono',monospace;color:#16a34a}
.dot{width:8px;height:8px;border-radius:50%;background:#22c55e;animation:blink 1.2s infinite}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.2}}
.field{margin-bottom:16px}
.field label{display:block;font-size:.8rem;font-weight:500;color:var(--text2);margin-bottom:6px}
.inp-wrap{position:relative}
.inp-wrap i{position:absolute;left:14px;top:50%;transform:translateY(-50%);color:var(--muted);font-size:.85rem}
input{width:100%;background:#f8faff;border:1.5px solid var(--border);border-radius:12px;
  padding:12px 14px 12px 40px;color:var(--text);font-family:'DM Sans',sans-serif;font-size:.95rem;
  outline:none;transition:border-color .2s,box-shadow .2s}
input:focus{border-color:var(--accent);box-shadow:0 0 0 4px rgba(79,70,229,.1)}
.btn{width:100%;padding:14px;border:none;border-radius:12px;cursor:pointer;
  background:linear-gradient(135deg,var(--accent),#6366f1);color:#fff;
  font-family:'DM Sans',sans-serif;font-weight:600;font-size:1rem;
  box-shadow:0 4px 16px rgba(79,70,229,.35);transition:opacity .2s,transform .1s;margin-top:8px}
.btn:hover{opacity:.92}.btn:active{transform:scale(.98)}
.err{color:var(--danger);font-size:.82rem;margin-top:12px;text-align:center;display:none;
  font-family:'DM Mono',monospace}
.hint{text-align:center;font-size:.78rem;color:var(--muted);margin-top:20px}
.hint strong{color:var(--accent)}
</style>
</head>
<body>
<div class="bg-grid"></div>
<div class="orb orb1"></div>
<div class="orb orb2"></div>
<div class="card">
  <div class="logo-wrap">
    <div class="logo"><i class="fas fa-shield-halved"></i></div>
    <h1>NetWatch SOC</h1>
    <p>Security Operations Center · v3.0</p>
  </div>
  <div class="status"><span class="dot"></span>All sensors online — system ready</div>
  <div class="field"><label>Username</label><div class="inp-wrap"><i class="fas fa-user"></i><input type="text" id="u" placeholder="admin"></div></div>
  <div class="field"><label>Password</label><div class="inp-wrap"><i class="fas fa-lock"></i><input type="password" id="p" placeholder="••••••••"></div></div>
  <button class="btn" onclick="doLogin()"><i class="fas fa-arrow-right-to-bracket"></i> &nbsp;Sign In</button>
  <div class="err" id="err"><i class="fas fa-circle-exclamation"></i> &nbsp;Invalid credentials</div>
  <div class="hint">Default: <strong>admin</strong> / <strong>admin123</strong></div>
</div>
<script>
async function doLogin(){
  const u=document.getElementById('u').value, p=document.getElementById('p').value;
  const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u,password:p})});
  const d=await r.json();
  if(d.success) window.location.href='/';
  else document.getElementById('err').style.display='block';
}
document.addEventListener('keydown',e=>{if(e.key==='Enter')doLogin()});
</script>
</body>
</html>"""

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetWatch SOC — Dashboard</title>
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@300;400;500;600;700&family=DM+Mono:wght@400;500&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --bg:#f0f4ff;--sidebar:#1e2235;--card:#ffffff;--border:#e2e8f4;
  --accent:#4f46e5;--accent2:#06b6d4;--accent3:#8b5cf6;
  --red:#ef4444;--orange:#f59e0b;--yellow:#eab308;--green:#10b981;
  --text:#1e2235;--text2:#6b7280;--muted:#9ca3af;--light:#f8faff;
  --sev-critical:#ef4444;--sev-high:#f59e0b;--sev-medium:#3b82f6;--sev-low:#10b981;
  --sidebar-w:240px;--topbar-h:60px;
}
body{font-family:'DM Sans',sans-serif;background:var(--bg);color:var(--text);
  display:flex;height:100vh;overflow:hidden;font-size:14px}
::-webkit-scrollbar{width:4px}::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:#d1d5db;border-radius:10px}
/* ── SIDEBAR ── */
#sidebar{width:var(--sidebar-w);flex-shrink:0;background:var(--sidebar);
  display:flex;flex-direction:column;z-index:50;transition:transform .3s}
.sb-brand{padding:20px 20px 16px;border-bottom:1px solid rgba(255,255,255,.08)}
.sb-logo{display:flex;align-items:center;gap:12px}
.sb-icon{width:36px;height:36px;border-radius:10px;
  background:linear-gradient(135deg,var(--accent),var(--accent2));
  display:flex;align-items:center;justify-content:center;flex-shrink:0}
.sb-icon i{color:#fff;font-size:16px}
.sb-title{font-weight:700;font-size:.95rem;color:#fff;letter-spacing:-.2px}
.sb-sub{font-size:.68rem;color:rgba(255,255,255,.4);margin-top:1px;font-family:'DM Mono',monospace}
.sb-nav{flex:1;padding:16px 10px;overflow-y:auto}
.nav-grp{font-size:.65rem;letter-spacing:2px;text-transform:uppercase;color:rgba(255,255,255,.25);
  padding:14px 10px 6px;font-family:'DM Mono',monospace}
.nav-item{display:flex;align-items:center;gap:10px;padding:9px 12px;border-radius:10px;
  cursor:pointer;color:rgba(255,255,255,.5);font-size:.88rem;font-weight:500;
  transition:all .2s;margin-bottom:1px}
.nav-item:hover{background:rgba(255,255,255,.07);color:rgba(255,255,255,.9)}
.nav-item.active{background:rgba(79,70,229,.35);color:#fff;
  box-shadow:inset 0 0 0 1px rgba(99,102,241,.3)}
.nav-item i{width:18px;text-align:center;font-size:.85rem}
.nav-badge{margin-left:auto;background:var(--red);color:#fff;font-size:.65rem;
  padding:1px 7px;border-radius:20px;font-family:'DM Mono',monospace}
.sb-footer{padding:14px;border-top:1px solid rgba(255,255,255,.08)}
.live-chip{display:flex;align-items:center;gap:8px;background:rgba(16,185,129,.12);
  border:1px solid rgba(16,185,129,.25);border-radius:30px;padding:7px 14px;
  font-size:.72rem;font-family:'DM Mono',monospace;color:#34d399}
.live-dot{width:7px;height:7px;border-radius:50%;background:#10b981;animation:blink 1.2s infinite}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.2}}
/* ── MAIN ── */
#main{flex:1;display:flex;flex-direction:column;overflow:hidden;min-width:0}
.topbar{height:var(--topbar-h);display:flex;align-items:center;gap:12px;padding:0 24px;
  background:var(--card);border-bottom:1px solid var(--border);flex-shrink:0}
.topbar-title{font-size:1.05rem;font-weight:600;color:var(--text);flex:1;letter-spacing:-.2px}
.topbar-title span{color:var(--accent)}
.tp-chip{display:flex;align-items:center;gap:6px;background:var(--light);
  border:1px solid var(--border);border-radius:8px;padding:5px 12px;
  font-family:'DM Mono',monospace;font-size:.72rem;color:var(--text2)}
.btn-icon{width:34px;height:34px;border-radius:8px;border:1px solid var(--border);
  background:transparent;color:var(--text2);cursor:pointer;
  display:flex;align-items:center;justify-content:center;transition:all .2s}
.btn-icon:hover{color:var(--accent);background:rgba(79,70,229,.06);border-color:rgba(79,70,229,.3)}
#content{flex:1;overflow-y:auto;padding:24px;background:var(--bg)}
.section{display:none;animation:fadeIn .25s ease}
.section.active{display:block}
@keyframes fadeIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}
/* ── STAT CARDS ── */
.stat-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(175px,1fr));gap:14px;margin-bottom:20px}
.stat-card{background:var(--card);border:1px solid var(--border);border-radius:16px;
  padding:18px 20px;transition:transform .2s,box-shadow .2s;position:relative;overflow:hidden}
.stat-card:hover{transform:translateY(-3px);box-shadow:0 8px 24px rgba(30,34,53,.08)}
.stat-card::before{content:'';position:absolute;top:0;left:0;right:0;height:3px;border-radius:16px 16px 0 0}
.stat-card.c-accent::before{background:linear-gradient(90deg,var(--accent),var(--accent2))}
.stat-card.c-red::before{background:linear-gradient(90deg,var(--red),#f97316)}
.stat-card.c-orange::before{background:linear-gradient(90deg,var(--orange),#fbbf24)}
.stat-card.c-green::before{background:linear-gradient(90deg,var(--green),#34d399)}
.stat-card.c-purple::before{background:linear-gradient(90deg,var(--accent3),#a78bfa)}
.stat-card.c-blue::before{background:linear-gradient(90deg,#3b82f6,#60a5fa)}
.stat-icon{width:36px;height:36px;border-radius:10px;display:flex;align-items:center;
  justify-content:center;margin-bottom:12px;font-size:16px}
.c-accent .stat-icon{background:#ede9fe;color:var(--accent)}
.c-red    .stat-icon{background:#fee2e2;color:var(--red)}
.c-orange .stat-icon{background:#fef3c7;color:var(--orange)}
.c-green  .stat-icon{background:#d1fae5;color:var(--green)}
.c-purple .stat-icon{background:#ede9fe;color:var(--accent3)}
.c-blue   .stat-icon{background:#dbeafe;color:#3b82f6}
.stat-val{font-size:1.9rem;font-weight:700;color:var(--text);font-family:'DM Mono',monospace;letter-spacing:-1px}
.stat-lbl{color:var(--text2);font-size:.75rem;margin-top:4px;font-weight:500}
.stat-delta{position:absolute;top:16px;right:16px;font-size:.72rem;font-family:'DM Mono',monospace;
  color:var(--green);background:#d1fae5;padding:2px 7px;border-radius:20px}
/* ── CARDS ── */
.card{background:var(--card);border:1px solid var(--border);border-radius:16px;
  padding:20px;margin-bottom:16px}
.card-hdr{display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;flex-wrap:wrap;gap:8px}
.card-title{font-size:.9rem;font-weight:600;display:flex;align-items:center;gap:8px;color:var(--text)}
.card-title i{color:var(--accent);font-size:.85rem}
.card-sub{font-size:.75rem;color:var(--text2);font-family:'DM Mono',monospace}
.grid-2{display:grid;grid-template-columns:1fr 1fr;gap:16px}
@media(max-width:900px){.grid-2{grid-template-columns:1fr}}
/* ── EVENT FEED ── */
.evt-list{max-height:340px;overflow-y:auto;display:flex;flex-direction:column;gap:4px}
.evt-row{display:flex;align-items:center;gap:10px;padding:8px 12px;border-radius:8px;
  background:var(--light);border:1px solid var(--border);font-size:.78rem;
  transition:background .15s;cursor:default;flex-wrap:wrap}
.evt-row:hover{background:#eef2ff}
.evt-row.CRITICAL{border-left:3px solid var(--sev-critical);border-radius:0 8px 8px 0}
.evt-row.HIGH    {border-left:3px solid var(--sev-high);border-radius:0 8px 8px 0}
.evt-row.MEDIUM  {border-left:3px solid var(--sev-medium);border-radius:0 8px 8px 0}
.evt-row.LOW,.evt-row.INFO{border-left:3px solid var(--sev-low);border-radius:0 8px 8px 0}
.evt-time{color:var(--muted);width:54px;flex-shrink:0;font-family:'DM Mono',monospace}
.evt-proto{font-weight:600;width:58px;flex-shrink:0;text-align:center;
  padding:2px 6px;border-radius:5px;font-size:.68rem;font-family:'DM Mono',monospace}
.proto-SSH   {background:#fee2e2;color:#ef4444}
.proto-HTTP  {background:#fef3c7;color:#d97706}
.proto-FTP   {background:#dbeafe;color:#2563eb}
.proto-Telnet{background:#ede9fe;color:#7c3aed}
.proto-SMTP  {background:#d1fae5;color:#059669}
.proto-DNS   {background:#fce7f3;color:#db2777}
.proto-default{background:#f3f4f6;color:#6b7280}
.evt-ip{color:var(--accent);width:125px;flex-shrink:0;font-family:'DM Mono',monospace;font-size:.75rem}
.evt-flag{flex-shrink:0;font-size:.9rem}
.evt-detail{color:var(--text);flex:1;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-size:.78rem}
.sev-badge{font-size:.63rem;padding:2px 7px;border-radius:20px;font-weight:600;
  flex-shrink:0;font-family:'DM Mono',monospace}
.sev-badge.CRITICAL{background:#fee2e2;color:var(--sev-critical)}
.sev-badge.HIGH    {background:#fef3c7;color:#d97706}
.sev-badge.MEDIUM  {background:#dbeafe;color:#2563eb}
.sev-badge.LOW,.sev-badge.INFO{background:#d1fae5;color:#059669}
/* ── ALERTS ── */
.alert-item{border-radius:12px;padding:14px 16px;margin-bottom:10px;
  border:1px solid transparent;cursor:default;transition:transform .15s}
.alert-item:hover{transform:translateX(3px)}
.alert-item.CRITICAL{background:#fff5f5;border-color:#fecaca}
.alert-item.HIGH    {background:#fffbeb;border-color:#fde68a}
.alert-item.MEDIUM  {background:#eff6ff;border-color:#bfdbfe}
.alert-item.LOW,.alert-item.INFO{background:#f0fdf4;border-color:#bbf7d0}
.alert-hdr{display:flex;align-items:center;gap:8px;margin-bottom:4px;flex-wrap:wrap}
.alert-ttl{font-weight:600;font-size:.88rem;color:var(--text)}
.alert-msg{color:var(--text2);font-size:.8rem;font-family:'DM Mono',monospace}
.alert-meta{font-size:.72rem;color:var(--muted);margin-top:4px}
/* ── TABLE ── */
.tbl{width:100%;border-collapse:collapse}
.tbl th{text-align:left;font-size:.7rem;letter-spacing:1px;text-transform:uppercase;
  color:var(--text2);padding:8px 10px;border-bottom:1.5px solid var(--border);font-weight:600}
.tbl td{padding:9px 10px;border-bottom:1px solid var(--border);font-size:.8rem}
.tbl tr:hover td{background:#f8faff}
.tbl tr:last-child td{border:none}
.threat-pill{padding:3px 10px;border-radius:20px;font-size:.68rem;font-weight:600;font-family:'DM Mono',monospace}
.threat-pill.CRITICAL{background:#fee2e2;color:var(--sev-critical)}
.threat-pill.HIGH    {background:#fef3c7;color:#d97706}
.threat-pill.MEDIUM  {background:#dbeafe;color:#2563eb}
.threat-pill.LOW     {background:#d1fae5;color:#059669}
.proto-tag{display:inline-block;padding:2px 7px;border-radius:4px;font-size:.65rem;
  margin:1px;background:var(--light);border:1px solid var(--border);color:var(--text2);font-family:'DM Mono',monospace}
/* ── MAP ── */
#worldMap{width:100%;height:460px;background:var(--light);border-radius:12px;border:1px solid var(--border)}
.map-legend{display:flex;gap:16px;flex-wrap:wrap;margin-top:12px}
.legend-item{display:flex;align-items:center;gap:6px;font-size:.75rem;color:var(--text2)}
.legend-dot{width:10px;height:10px;border-radius:50%}
/* ── PROTO BARS ── */
.proto-bar-row{display:flex;align-items:center;gap:12px;margin-bottom:10px}
.proto-bar-lbl{width:60px;font-family:'DM Mono',monospace;font-size:.75rem;color:var(--text2)}
.proto-bar-track{flex:1;height:8px;background:var(--light);border-radius:10px;overflow:hidden;border:1px solid var(--border)}
.proto-bar-fill{height:100%;border-radius:10px;transition:width .6s ease}
.proto-bar-val{font-family:'DM Mono',monospace;font-size:.72rem;color:var(--text2);width:32px;text-align:right}
/* ── SETTINGS ── */
.setting-row{display:flex;align-items:center;justify-content:space-between;
  padding:14px 0;border-bottom:1px solid var(--border);gap:10px;flex-wrap:wrap}
.setting-row:last-child{border:none}
.setting-lbl{font-weight:600;font-size:.88rem;color:var(--text)}
.setting-desc{color:var(--text2);font-size:.78rem;margin-top:2px}
.inp{background:var(--light);border:1.5px solid var(--border);border-radius:8px;
  padding:7px 12px;color:var(--text);font-family:'DM Mono',monospace;font-size:.85rem;
  outline:none;width:160px;transition:border-color .2s}
.inp:focus{border-color:var(--accent)}
.btn-danger{padding:8px 18px;background:#fff5f5;border:1px solid #fecaca;color:var(--red);
  border-radius:8px;cursor:pointer;font-family:'DM Sans',sans-serif;font-weight:600;font-size:.85rem;
  transition:all .2s}
.btn-danger:hover{background:#fee2e2}
/* ── EMPTY STATE ── */
.empty{text-align:center;padding:40px 20px;color:var(--muted)}
.empty i{font-size:2rem;margin-bottom:8px;display:block;opacity:.4}
.empty p{font-size:.85rem}
/* ── RESPONSIVE ── */
@media(max-width:700px){
  #sidebar{position:fixed;height:100%;transform:translateX(-100%)}
  #sidebar.open{transform:translateX(0)}
  #content{padding:14px}
  .topbar{padding:0 14px}
}
/* ── CHART CONTAINER override ── */
.chart-wrap{position:relative}
</style>
</head>
<body>

<!-- SIDEBAR -->
<div id="sidebar">
  <div class="sb-brand">
    <div class="sb-logo">
      <div class="sb-icon"><i class="fas fa-shield-halved"></i></div>
      <div><div class="sb-title">NetWatch SOC</div><div class="sb-sub">v3.0 · PLATFORM</div></div>
    </div>
  </div>
  <div class="sb-nav">
    <div class="nav-grp">Monitoring</div>
    <div class="nav-item active" data-section="dashboard"><i class="fas fa-gauge-high"></i>Dashboard</div>
    <div class="nav-item" data-section="attackmap"><i class="fas fa-earth-americas"></i>Attack Map</div>
    <div class="nav-item" data-section="alerts"><i class="fas fa-bell"></i>Alerts<span class="nav-badge" id="alertBadge">0</span></div>
    <div class="nav-grp">Intelligence</div>
    <div class="nav-item" data-section="attackers"><i class="fas fa-user-secret"></i>Attackers DB</div>
    <div class="nav-item" data-section="analytics"><i class="fas fa-chart-line"></i>Analytics</div>
    <div class="nav-item" data-section="payloads"><i class="fas fa-code"></i>Payloads</div>
    <div class="nav-grp">System</div>
    <div class="nav-item" data-section="settings"><i class="fas fa-sliders"></i>Settings</div>
    <div class="nav-item" onclick="logout()"><i class="fas fa-right-from-bracket"></i>Logout</div>
  </div>
  <div class="sb-footer">
    <div class="live-chip"><span class="live-dot"></span>LIVE MONITORING</div>
  </div>
</div>

<!-- MAIN -->
<div id="main">
  <div class="topbar">
    <button class="btn-icon" onclick="toggleSidebar()"><i class="fas fa-bars"></i></button>
    <div class="topbar-title" id="pageTitle">Security <span>Dashboard</span></div>
    <div class="tp-chip"><i class="fas fa-server" style="color:var(--accent)"></i><span id="serverIp">—</span></div>
    <div class="tp-chip"><i class="fas fa-clock" style="color:var(--accent2)"></i><span id="clockVal">--:--:--</span></div>
    <button class="btn-icon" onclick="fetchAll()" title="Refresh"><i class="fas fa-rotate-right"></i></button>
  </div>

  <div id="content">

    <!-- ═══ DASHBOARD ═══ -->
    <div class="section active" id="sec-dashboard">
      <div class="stat-grid">
        <div class="stat-card c-accent"><div class="stat-icon"><i class="fas fa-bolt"></i></div><div class="stat-val" id="statEvents">0</div><div class="stat-lbl">Total Events</div><div class="stat-delta" id="deltaEvents">+0</div></div>
        <div class="stat-card c-red">   <div class="stat-icon"><i class="fas fa-bell"></i></div><div class="stat-val" id="statAlerts">0</div><div class="stat-lbl">Active Alerts</div></div>
        <div class="stat-card c-orange"><div class="stat-icon"><i class="fas fa-users"></i></div><div class="stat-val" id="statAttackers">0</div><div class="stat-lbl">Unique Attackers</div></div>
        <div class="stat-card c-purple"><div class="stat-icon"><i class="fas fa-fire-flame-curved"></i></div><div class="stat-val" id="statRisk">0</div><div class="stat-lbl">Risk Score</div></div>
        <div class="stat-card c-red">   <div class="stat-icon"><i class="fas fa-skull"></i></div><div class="stat-val" id="statCrit">0</div><div class="stat-lbl">Critical</div></div>
        <div class="stat-card c-orange"><div class="stat-icon"><i class="fas fa-circle-exclamation"></i></div><div class="stat-val" id="statHigh">0</div><div class="stat-lbl">High</div></div>
        <div class="stat-card c-blue">  <div class="stat-icon"><i class="fas fa-triangle-exclamation"></i></div><div class="stat-val" id="statMed">0</div><div class="stat-lbl">Medium</div></div>
        <div class="stat-card c-green"> <div class="stat-icon"><i class="fas fa-circle-check"></i></div><div class="stat-val" id="statLow">0</div><div class="stat-lbl">Low / Info</div></div>
      </div>
      <div class="grid-2">
        <div class="card">
          <div class="card-hdr"><div class="card-title"><i class="fas fa-chart-pie"></i>Protocol Distribution</div></div>
          <div class="chart-wrap"><canvas id="chartProto" height="220"></canvas></div>
        </div>
        <div class="card">
          <div class="card-hdr"><div class="card-title"><i class="fas fa-ranking-star"></i>Top Attackers</div></div>
          <div class="chart-wrap"><canvas id="chartTop" height="220"></canvas></div>
        </div>
      </div>
      <div class="card">
        <div class="card-hdr">
          <div class="card-title"><i class="fas fa-satellite-dish"></i>Live Event Feed</div>
          <div class="card-sub">Auto-refresh every 2s</div>
        </div>
        <div class="evt-list" id="evtFeed"></div>
      </div>
    </div>

    <!-- ═══ ATTACK MAP ═══ -->
    <div class="section" id="sec-attackmap">
      <div class="card">
        <div class="card-hdr">
          <div class="card-title"><i class="fas fa-earth-americas"></i>Global Attack Origins</div>
          <div class="card-sub" id="mapCount">0 unique source IPs plotted</div>
        </div>
        <canvas id="worldMap"></canvas>
        <div class="map-legend">
          <div class="legend-item"><div class="legend-dot" style="background:#ef4444"></div>Critical</div>
          <div class="legend-item"><div class="legend-dot" style="background:#f59e0b"></div>High</div>
          <div class="legend-item"><div class="legend-dot" style="background:#3b82f6"></div>Medium</div>
          <div class="legend-item"><div class="legend-dot" style="background:#10b981"></div>Low</div>
          <div class="legend-item"><div class="legend-dot" style="background:#4f46e5;border:2px solid #4f46e5"></div>Your Server</div>
        </div>
      </div>
      <div class="card">
        <div class="card-hdr"><div class="card-title"><i class="fas fa-map-pin"></i>Recent Attack Sources</div></div>
        <div class="evt-list" id="mapFeed"></div>
      </div>
    </div>

    <!-- ═══ ALERTS ═══ -->
    <div class="section" id="sec-alerts">
      <div class="stat-grid" style="grid-template-columns:repeat(4,1fr)">
        <div class="stat-card c-red">   <div class="stat-icon"><i class="fas fa-skull"></i></div><div class="stat-val" id="aCrit">0</div><div class="stat-lbl">Critical</div></div>
        <div class="stat-card c-orange"><div class="stat-icon"><i class="fas fa-fire"></i></div><div class="stat-val" id="aHigh">0</div><div class="stat-lbl">High</div></div>
        <div class="stat-card c-blue">  <div class="stat-icon"><i class="fas fa-triangle-exclamation"></i></div><div class="stat-val" id="aMed">0</div><div class="stat-lbl">Medium</div></div>
        <div class="stat-card c-green"> <div class="stat-icon"><i class="fas fa-circle-check"></i></div><div class="stat-val" id="aLow">0</div><div class="stat-lbl">Low</div></div>
      </div>
      <div class="card">
        <div class="card-hdr"><div class="card-title"><i class="fas fa-bell"></i>All Security Alerts</div></div>
        <div style="max-height:520px;overflow-y:auto" id="alertFeed"></div>
      </div>
    </div>

    <!-- ═══ ATTACKERS DB ═══ -->
    <div class="section" id="sec-attackers">
      <div class="card">
        <div class="card-hdr">
          <div class="card-title"><i class="fas fa-database"></i>Attacker Intelligence</div>
          <div class="card-sub"><span id="atkCount">0</span> IPs tracked</div>
        </div>
        <div style="overflow-x:auto">
          <table class="tbl">
            <thead><tr><th>IP Address</th><th>Location</th><th>Attempts</th><th>Protocols</th><th>Threat</th><th>First Seen</th><th>Last Seen</th></tr></thead>
            <tbody id="atkTable"></tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- ═══ ANALYTICS ═══ -->
    <div class="section" id="sec-analytics">
      <div class="card">
        <div class="card-hdr"><div class="card-title"><i class="fas fa-chart-line"></i>Hourly Attack Volume (24h)</div></div>
        <div class="chart-wrap"><canvas id="chartHourly" height="160"></canvas></div>
      </div>
      <div class="grid-2">
        <div class="card">
          <div class="card-hdr"><div class="card-title"><i class="fas fa-network-wired"></i>Protocol Breakdown</div></div>
          <div id="protoBreakdown" style="margin-top:4px"></div>
        </div>
        <div class="card">
          <div class="card-hdr"><div class="card-title"><i class="fas fa-flag"></i>Top Threat Countries</div></div>
          <div class="chart-wrap"><canvas id="chartCountry" height="210"></canvas></div>
        </div>
      </div>
    </div>

    <!-- ═══ PAYLOADS ═══ -->
    <div class="section" id="sec-payloads">
      <div class="card">
        <div class="card-hdr"><div class="card-title"><i class="fas fa-terminal"></i>Captured Payloads</div><div class="card-sub">Raw data from honeypot connections</div></div>
        <div class="evt-list" style="max-height:600px" id="payloadFeed"></div>
      </div>
    </div>

    <!-- ═══ SETTINGS ═══ -->
    <div class="section" id="sec-settings">
      <div class="card">
        <div class="card-hdr"><div class="card-title"><i class="fas fa-sliders"></i>Configuration</div></div>
        <div class="setting-row">
          <div><div class="setting-lbl">Auto-Refresh Interval</div><div class="setting-desc">How often to pull fresh data (seconds)</div></div>
          <input class="inp" type="number" value="2" min="1" max="60" id="refreshInterval">
        </div>
        <div class="setting-row">
          <div><div class="setting-lbl">Clear All Data</div><div class="setting-desc">Wipe events, alerts, and attacker records</div></div>
          <button class="btn-danger" onclick="clearData()"><i class="fas fa-trash"></i> Clear Data</button>
        </div>
      </div>
      <div class="card">
        <div class="card-hdr"><div class="card-title"><i class="fas fa-circle-info"></i>System Information</div></div>
        <table class="tbl">
          <tr><td style="color:var(--text2);width:200px">Server IP</td><td style="font-family:'DM Mono',monospace" id="infoIp">—</td></tr>
          <tr><td style="color:var(--text2)">Platform</td><td>NetWatch SOC v3.0</td></tr>
          <tr><td style="color:var(--text2)">Active Honeypots</td><td>SSH · HTTP · FTP · Telnet · SMTP · DNS</td></tr>
          <tr><td style="color:var(--text2)">Dashboard Port</td><td style="font-family:'DM Mono',monospace" id="infoPort">5000</td></tr>
        </table>
      </div>
    </div>

  </div><!-- /content -->
</div><!-- /main -->

<script>
/* ── state ── */
let charts = {};
let prevCount = 0;
let attackerData = [];
let mapAnimFrame = null;
let mapPoints = [];

/* ── clock ── */
function tickClock(){ document.getElementById('clockVal').textContent = new Date().toLocaleTimeString(); }
setInterval(tickClock, 1000); tickClock();

/* ── nav ── */
function showSection(id){
  document.querySelectorAll('.section').forEach(s=>s.classList.remove('active'));
  document.querySelectorAll('.nav-item[data-section]').forEach(n=>n.classList.remove('active'));
  const sec = document.getElementById('sec-'+id);
  if(sec) sec.classList.add('active');
  const nav = document.querySelector(`.nav-item[data-section="${id}"]`);
  if(nav) nav.classList.add('active');
  const titles = {
    dashboard:'Security <span>Dashboard</span>',
    attackmap:'Attack <span>Map</span>',
    alerts:'Security <span>Alerts</span>',
    attackers:'Attacker <span>Database</span>',
    analytics:'<span>Analytics</span>',
    payloads:'Captured <span>Payloads</span>',
    settings:'Platform <span>Settings</span>'
  };
  document.getElementById('pageTitle').innerHTML = titles[id] || id;
  if(id === 'attackmap') renderWorldMap();
}
document.querySelectorAll('.nav-item[data-section]').forEach(el=>{
  el.addEventListener('click', ()=>showSection(el.dataset.section));
});

function toggleSidebar(){ document.getElementById('sidebar').classList.toggle('open'); }
async function clearData(){ if(!confirm('Clear all collected data?')) return; await fetch('/api/clear',{method:'POST'}); fetchAll(); }
async function logout(){ await fetch('/api/logout',{method:'POST'}); window.location.href='/login'; }

/* ── fetch all ── */
async function fetchAll(){
  try{
    const [evR,stR,alR,akR] = await Promise.all([
      fetch('/api/events').then(r=>r.json()),
      fetch('/api/stats').then(r=>r.json()),
      fetch('/api/alerts').then(r=>r.json()),
      fetch('/api/attackers').then(r=>r.json()),
    ]);
    updateAll(evR.events||[], stR, alR.alerts||[], akR.attackers||[]);
  }catch(e){ console.error(e); }
}

function updateAll(evts, stats, alts, atks){
  attackerData = atks;
  /* server info */
  if(stats.server_ip){
    document.getElementById('serverIp').textContent = stats.server_ip;
    document.getElementById('infoIp').textContent   = stats.server_ip;
  }
  /* severity counts */
  const sev = {CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0,INFO:0};
  evts.forEach(e=>{ const k=e.severity||'INFO'; sev[k]=(sev[k]||0)+1; });
  const total = stats.total_events || evts.length;
  const delta = total - prevCount;
  prevCount = total;
  setText('statEvents', total);
  setText('deltaEvents', (delta>=0?'+':'')+delta);
  setText('statAlerts',    stats.total_alerts||alts.length);
  setText('statAttackers', stats.unique_attackers||atks.length);
  const risk = Math.min(100, Math.round(sev.CRITICAL*10 + sev.HIGH*5 + sev.MEDIUM*2 + total*.1));
  setText('statRisk', risk);
  setText('statCrit', sev.CRITICAL||0);
  setText('statHigh', sev.HIGH||0);
  setText('statMed',  sev.MEDIUM||0);
  setText('statLow',  (sev.LOW||0)+(sev.INFO||0));
  setText('alertBadge', alts.length);
  /* badge color */
  setText('aCrit', alts.filter(a=>a.severity==='CRITICAL').length);
  setText('aHigh', alts.filter(a=>a.severity==='HIGH').length);
  setText('aMed',  alts.filter(a=>a.severity==='MEDIUM').length);
  setText('aLow',  alts.filter(a=>!['CRITICAL','HIGH','MEDIUM'].includes(a.severity)).length);

  renderFeed('evtFeed', evts.slice(0,60));
  renderAlerts(alts);
  renderAtkTable(atks);
  setText('atkCount', atks.length);

  const proto = stats.protocols || {};
  updateProtoChart(proto);
  updateTopChart(atks);
  updateAnalytics(evts, stats, atks);

  /* map feed */
  renderFeed('mapFeed', evts.filter(e=>e.geo&&e.geo.country!=='Local Network').slice(0,30));
  mapPoints = atks.filter(a=>a.geo&&a.geo.lat!==0).map(a=>({lat:a.geo.lat,lon:a.geo.lon,level:a.threat_level,ip:a.ip,country:a.geo.country}));
  setText('mapCount', mapPoints.length + ' unique source IPs plotted');

  renderPayloads(evts);
}

/* ── helpers ── */
function setText(id, v){ const el=document.getElementById(id); if(el) el.textContent=v; }
function esc(s){ return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function fmtTime(iso){ if(!iso) return '—'; try{ return new Date(iso).toLocaleTimeString(); }catch(e){ return iso; } }
function protoClass(p){ const m={SSH:'proto-SSH',HTTP:'proto-HTTP',FTP:'proto-FTP',Telnet:'proto-Telnet',SMTP:'proto-SMTP',DNS:'proto-DNS'}; return m[p]||'proto-default'; }

/* ── feed ── */
function renderFeed(id, evts){
  const el = document.getElementById(id);
  if(!evts.length){ el.innerHTML = '<div class="empty"><i class="fas fa-satellite-dish"></i><p>No events captured yet</p></div>'; return; }
  el.innerHTML = evts.map(e=>`
    <div class="evt-row ${e.severity||'INFO'}">
      <span class="evt-time">${e.time}</span>
      <span class="evt-proto ${protoClass(e.protocol)}">${e.protocol}</span>
      <span class="evt-flag">${e.geo?e.geo.flag:''}</span>
      <span class="evt-ip">${e.src_ip}</span>
      <span class="evt-detail">${esc(e.details)}${e.payload?' <span style="color:var(--muted)">'+esc(e.payload.slice(0,50))+'</span>':''}</span>
      <span class="sev-badge ${e.severity||'INFO'}">${e.severity||'INFO'}</span>
    </div>`).join('');
}

/* ── alerts ── */
function renderAlerts(alts){
  const el = document.getElementById('alertFeed');
  if(!alts.length){ el.innerHTML = '<div class="empty"><i class="fas fa-bell-slash"></i><p>No alerts yet</p></div>'; return; }
  el.innerHTML = alts.map(a=>`
    <div class="alert-item ${a.severity}">
      <div class="alert-hdr">
        <span class="sev-badge ${a.severity}">${a.severity}</span>
        <span class="alert-ttl">${esc(a.title)}</span>
        <span style="margin-left:auto;font-family:'DM Mono',monospace;font-size:.72rem;color:var(--muted)">${a.time}</span>
      </div>
      <div class="alert-msg">${esc(a.message)}</div>
      <div class="alert-meta">Protocol: ${a.protocol||'—'} &nbsp;·&nbsp; ${a.geo?a.geo.flag+' '+a.geo.country:'Unknown'} &nbsp;·&nbsp; ${a.date||'—'}</div>
    </div>`).join('');
}

/* ── attacker table ── */
function renderAtkTable(atks){
  const el = document.getElementById('atkTable');
  if(!atks.length){ el.innerHTML = '<tr><td colspan="7" class="empty"><i class="fas fa-user-secret"></i><p>No attackers recorded</p></td></tr>'; return; }
  el.innerHTML = atks.map(a=>`
    <tr>
      <td style="font-family:'DM Mono',monospace;color:var(--accent)">${a.ip}</td>
      <td>${a.geo?a.geo.flag+' '+a.geo.country:'Unknown'}</td>
      <td style="font-weight:600;color:var(--text)">${a.count}</td>
      <td>${(a.protocols||[]).map(p=>`<span class="proto-tag">${p}</span>`).join('')}</td>
      <td><span class="threat-pill ${a.threat_level}">${a.threat_level}</span></td>
      <td style="color:var(--muted);font-family:'DM Mono',monospace;font-size:.72rem">${fmtTime(a.first_seen)}</td>
      <td style="color:var(--muted);font-family:'DM Mono',monospace;font-size:.72rem">${fmtTime(a.last_seen)}</td>
    </tr>`).join('');
}

/* ── payloads ── */
function renderPayloads(evts){
  const with_payload = evts.filter(e=>e.payload).slice(0,100);
  const el = document.getElementById('payloadFeed');
  if(!el) return;
  if(!with_payload.length){ el.innerHTML = '<div class="empty"><i class="fas fa-terminal"></i><p>No payloads captured yet</p></div>'; return; }
  el.innerHTML = with_payload.map(e=>`
    <div class="evt-row ${e.severity||'INFO'}">
      <span class="evt-time">${e.time}</span>
      <span class="evt-proto ${protoClass(e.protocol)}">${e.protocol}</span>
      <span class="evt-flag">${e.geo?e.geo.flag:''}</span>
      <span class="evt-ip">${e.src_ip}</span>
      <span class="evt-detail" style="color:var(--orange);font-family:'DM Mono',monospace">${esc(e.payload)}</span>
    </div>`).join('');
}

/* ── charts ── */
const PROTO_COLORS = {SSH:'#ef4444',HTTP:'#f59e0b',FTP:'#3b82f6',Telnet:'#8b5cf6',DNS:'#ec4899',SMTP:'#10b981'};
const BAR_COLORS   = ['#4f46e5','#06b6d4','#10b981','#f59e0b','#ef4444','#8b5cf6','#ec4899','#3b82f6'];
const CHART_DEFAULTS = {
  font: { family:"'DM Mono', monospace", size:11 },
  gridColor: 'rgba(0,0,0,0.05)',
  tickColor: '#9ca3af',
};

function mkChart(id, type, data, options){
  const ctx = document.getElementById(id);
  if(!ctx) return null;
  return new Chart(ctx, {type, data, options});
}

function updateProtoChart(proto){
  const labels = Object.keys(proto), values = Object.values(proto);
  const bg = labels.map(l=>PROTO_COLORS[l]||'#9ca3af');
  if(!charts.proto){
    charts.proto = mkChart('chartProto','doughnut',
      {labels, datasets:[{data:values, backgroundColor:bg, borderWidth:2, borderColor:'#fff', hoverOffset:6}]},
      {plugins:{legend:{position:'right',labels:{color:'#6b7280',font:{family:"'DM Mono',monospace",size:11},padding:12,usePointStyle:true}}},
       cutout:'62%', animation:{duration:500}});
  } else {
    charts.proto.data.labels = labels;
    charts.proto.data.datasets[0].data = values;
    charts.proto.data.datasets[0].backgroundColor = bg;
    charts.proto.update('none');
  }
}

function updateTopChart(atks){
  const top = atks.slice(0,8);
  const labels = top.map(a=>a.ip);
  const data   = top.map(a=>a.count);
  const bg     = top.map(a=>({CRITICAL:'#ef4444',HIGH:'#f59e0b',MEDIUM:'#3b82f6',LOW:'#10b981'}[a.threat_level]||'#9ca3af'));
  if(!charts.top){
    charts.top = mkChart('chartTop','bar',
      {labels, datasets:[{label:'Attempts',data,backgroundColor:bg,borderRadius:6,borderSkipped:false}]},
      {plugins:{legend:{display:false}},
       scales:{
         x:{ticks:{color:'#9ca3af',font:{family:"'DM Mono',monospace",size:10},maxRotation:30},grid:{display:false}},
         y:{ticks:{color:'#9ca3af',font:{family:"'DM Mono',monospace"}},grid:{color:'rgba(0,0,0,0.05)'}}
       }, animation:{duration:400}});
  } else {
    charts.top.data.labels = labels;
    charts.top.data.datasets[0].data = data;
    charts.top.data.datasets[0].backgroundColor = bg;
    charts.top.update('none');
  }
}

function updateAnalytics(evts, stats, atks){
  /* hourly */
  const hours = Array.from({length:24},(_,i)=>String(i).padStart(2,'0'));
  const hData = stats.hourly||{};
  const hVals = hours.map(h=>hData[h]||0);
  if(!charts.hourly){
    charts.hourly = mkChart('chartHourly','line',
      {labels:hours.map(h=>h+':00'),
       datasets:[{label:'Events',data:hVals,borderColor:'#4f46e5',backgroundColor:'rgba(79,70,229,0.08)',
         fill:true,tension:.4,pointRadius:3,pointBackgroundColor:'#4f46e5',pointBorderColor:'#fff',pointBorderWidth:2}]},
      {plugins:{legend:{display:false}},
       scales:{
         x:{ticks:{color:'#9ca3af',font:{family:"'DM Mono',monospace",size:9}},grid:{color:'rgba(0,0,0,0.04)'}},
         y:{ticks:{color:'#9ca3af',font:{family:"'DM Mono',monospace"}},grid:{color:'rgba(0,0,0,0.04)'}}
       }, animation:{duration:400}});
  } else {
    charts.hourly.data.datasets[0].data = hVals;
    charts.hourly.update('none');
  }
  /* proto bars */
  const proto = stats.protocols||{};
  const total = Object.values(proto).reduce((a,b)=>a+b,0)||1;
  document.getElementById('protoBreakdown').innerHTML =
    Object.entries(proto).sort((a,b)=>b[1]-a[1]).map(([p,c],i)=>`
    <div class="proto-bar-row">
      <div class="proto-bar-lbl">${p}</div>
      <div class="proto-bar-track"><div class="proto-bar-fill" style="width:${Math.round(c/total*100)}%;background:${BAR_COLORS[i%BAR_COLORS.length]}"></div></div>
      <div class="proto-bar-val">${c}</div>
    </div>`).join('');
  /* country chart */
  const cc={};
  atks.forEach(a=>{ if(a.geo&&a.geo.country&&a.geo.country!=='Local Network') cc[a.geo.country]=(cc[a.geo.country]||0)+a.count; });
  const topC = Object.entries(cc).sort((a,b)=>b[1]-a[1]).slice(0,8);
  if(!charts.country){
    charts.country = mkChart('chartCountry','bar',
      {labels:topC.map(([c])=>c), datasets:[{label:'Attacks',data:topC.map(([,v])=>v),backgroundColor:BAR_COLORS,borderRadius:5,borderSkipped:false}]},
      {indexAxis:'y',plugins:{legend:{display:false}},
       scales:{
         x:{ticks:{color:'#9ca3af',font:{family:"'DM Mono',monospace",size:9}},grid:{color:'rgba(0,0,0,0.04)'}},
         y:{ticks:{color:'#6b7280',font:{family:"'DM Sans',sans-serif",size:11}},grid:{display:false}}
       }, animation:{duration:400}});
  } else {
    charts.country.data.labels = topC.map(([c])=>c);
    charts.country.data.datasets[0].data = topC.map(([,v])=>v);
    charts.country.update('none');
  }
}

/* ═══════════════════════════════════════
   WORLD MAP (Equirectangular flat map)
═══════════════════════════════════════ */
function renderWorldMap(){
  const cvs = document.getElementById('worldMap');
  if(!cvs) return;
  if(mapAnimFrame){ cancelAnimationFrame(mapAnimFrame); mapAnimFrame=null; }

  const ctx = cvs.getContext('2d');
  cvs.width  = cvs.offsetWidth  || 800;
  cvs.height = cvs.offsetHeight || 460;

  const W = cvs.width, H = cvs.height;
  const padL=40, padR=20, padT=20, padB=30;
  const mapW = W-padL-padR, mapH = H-padT-padB;

  function lonToX(lon){ return padL + (lon+180)/360 * mapW; }
  function latToY(lat){ return padT + (90-lat)/180 * mapH; }

  const threatColor = {CRITICAL:'#ef4444',HIGH:'#f59e0b',MEDIUM:'#3b82f6',LOW:'#10b981'};

  /* animate pulsing rings */
  let frame = 0;
  function draw(){
    mapAnimFrame = requestAnimationFrame(draw);
    frame++;
    ctx.clearRect(0,0,W,H);

    /* background */
    ctx.fillStyle = '#f8faff';
    ctx.fillRect(0,0,W,H);

    /* grid lines */
    ctx.strokeStyle = 'rgba(79,70,229,0.07)';
    ctx.lineWidth = .8;
    /* meridians */
    for(let lon=-180;lon<=180;lon+=30){
      ctx.beginPath();
      ctx.moveTo(lonToX(lon), padT);
      ctx.lineTo(lonToX(lon), padT+mapH);
      ctx.stroke();
    }
    /* parallels */
    for(let lat=-90;lat<=90;lat+=30){
      ctx.beginPath();
      ctx.moveTo(padL, latToY(lat));
      ctx.lineTo(padL+mapW, latToY(lat));
      ctx.stroke();
    }

    /* continent outlines (simplified polygons) */
    ctx.fillStyle = 'rgba(79,70,229,0.06)';
    ctx.strokeStyle = 'rgba(79,70,229,0.18)';
    ctx.lineWidth = 1;

    const continents = [
      /* North America */
      [[-140,70],[-55,70],[-55,25],[-80,25],[-80,10],[-92,16],[-117,32],[-140,60]],
      /* South America */
      [[-80,12],[-35,5],[-35,-55],[-70,-55],[-80,-10],[-80,12]],
      /* Europe */
      [[-10,70],[40,70],[40,36],[28,36],[28,41],[10,43],[-10,44],[-10,70]],
      /* Africa */
      [[-17,15],[52,15],[52,-35],[-18,-35],[-17,15]],
      /* Asia */
      [[26,70],[145,70],[145,10],[100,1],[80,10],[60,22],[26,38],[26,70]],
      /* Australia */
      [[114,-22],[154,-22],[154,-44],[114,-44],[114,-22]],
      /* Greenland */
      [[-73,83],[-10,83],[-10,76],[-73,76],[-73,83]],
    ];

    continents.forEach(poly=>{
      ctx.beginPath();
      poly.forEach(([lon,lat],i)=>{
        const x=lonToX(lon), y=latToY(lat);
        i===0 ? ctx.moveTo(x,y) : ctx.lineTo(x,y);
      });
      ctx.closePath();
      ctx.fill();
      ctx.stroke();
    });

    /* axis labels */
    ctx.fillStyle = '#9ca3af';
    ctx.font = "10px 'DM Mono',monospace";
    ctx.textAlign = 'center';
    for(let lon=-180;lon<=180;lon+=60){
      ctx.fillText(lon+'°', lonToX(lon), H-8);
    }
    ctx.textAlign = 'right';
    for(let lat=-60;lat<=90;lat+=30){
      ctx.fillText(lat+'°', padL-4, latToY(lat)+4);
    }

    /* attacker points */
    mapPoints.forEach(pt=>{
      const x=lonToX(pt.lon), y=latToY(pt.lat);
      const c = threatColor[pt.level]||'#9ca3af';
      const pulse = (frame%80)/80;

      /* pulsing ring */
      if(pt.level==='CRITICAL'||pt.level==='HIGH'){
        ctx.beginPath();
        ctx.arc(x,y, 6+pulse*14, 0, Math.PI*2);
        ctx.strokeStyle = c+(Math.round((1-pulse)*80)).toString(16).padStart(2,'0');
        ctx.lineWidth = 1.5;
        ctx.stroke();
      }

      /* glow */
      const grd = ctx.createRadialGradient(x,y,0,x,y,10);
      grd.addColorStop(0, c+'cc');
      grd.addColorStop(1, 'transparent');
      ctx.beginPath(); ctx.arc(x,y,10,0,Math.PI*2);
      ctx.fillStyle = grd; ctx.fill();

      /* dot */
      ctx.beginPath(); ctx.arc(x,y,4,0,Math.PI*2);
      ctx.fillStyle = c;
      ctx.shadowColor = c;
      ctx.shadowBlur = 8;
      ctx.fill();
      ctx.shadowBlur = 0;
    });

    /* YOUR SERVER dot (pulsing) */
    const sip = document.getElementById('serverIp').textContent;
    const sx = lonToX(70), sy = latToY(30); /* approx Asia/Middle East default */
    const sp = Math.abs(Math.sin(frame*0.05));
    ctx.beginPath(); ctx.arc(sx,sy, 6+sp*12, 0, Math.PI*2);
    ctx.strokeStyle = `rgba(79,70,229,${0.6*(1-sp)})`;
    ctx.lineWidth = 2; ctx.stroke();
    ctx.beginPath(); ctx.arc(sx,sy, 5, 0, Math.PI*2);
    ctx.fillStyle = '#4f46e5';
    ctx.shadowColor = '#4f46e5'; ctx.shadowBlur = 12;
    ctx.fill(); ctx.shadowBlur=0;

    /* border */
    ctx.strokeStyle = 'rgba(79,70,229,0.15)';
    ctx.lineWidth = 1;
    ctx.strokeRect(padL, padT, mapW, mapH);
  }
  draw();
}

/* ── auto-refresh ── */
fetchAll();
let refreshTimer = setInterval(fetchAll, 2000);
document.getElementById('refreshInterval').addEventListener('change', function(){
  clearInterval(refreshTimer);
  refreshTimer = setInterval(fetchAll, (parseInt(this.value)||2)*1000);
});
</script>
</body>
</html>"""

# ═══════════════════════════════════════════════════════════
#  DASHBOARD HTTP HANDLER
# ═══════════════════════════════════════════════════════════

class DashboardHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args): pass

    def json_response(self, data, code=200):
        body = json.dumps(data, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.end_headers(); self.wfile.write(body)

    def html_response(self, html, code=200):
        body = html.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", len(body))
        self.end_headers(); self.wfile.write(body)

    def redirect(self, loc):
        self.send_response(302)
        self.send_header("Location", loc)
        self.end_headers()

    def read_body(self):
        l = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(l) if l else b""

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/login":
            self.html_response(LOGIN_HTML); return
        if path == "/favicon.ico":
            self.send_response(204); self.end_headers(); return
        if not validate_session(get_session_token(self)):
            self.redirect("/login"); return
        if path == "/":
            self.html_response(DASHBOARD_HTML)
        elif path == "/api/events":
            with state_lock:
                self.json_response({"events": list(events)[:200]})
        elif path == "/api/alerts":
            with state_lock:
                self.json_response({"alerts": list(alerts)[:100]})
        elif path == "/api/attackers":
            with state_lock:
                lst = []
                for ip, d in attackers.items():
                    lst.append({"ip":ip,"count":d["count"],"first_seen":d["first_seen"],
                        "last_seen":d["last_seen"],"protocols":list(d.get("protocols",set())),
                        "geo":d.get("geo",{}),"threat_level":d.get("threat_level","LOW"),
                        "blocked":d.get("blocked",False),"payloads":d.get("payloads",[])[-3:]})
                lst.sort(key=lambda x:x["count"], reverse=True)
                self.json_response({"attackers": lst[:200]})
        elif path == "/api/stats":
            with state_lock:
                self.json_response({
                    "total_events":     len(events),
                    "total_alerts":     len(alerts),
                    "unique_attackers": len(attackers),
                    "protocols":        dict(protocol_stats),
                    "hourly":           dict(hourly_data),
                    "server_ip":        SERVER_IP,
                })
        else:
            self.send_response(404); self.end_headers()

    def do_POST(self):
        path = urlparse(self.path).path
        body = self.read_body()
        if path == "/api/login":
            try:
                d = json.loads(body)
                if d.get("username")==CONFIG["admin_user"] and d.get("password")==CONFIG["admin_pass"]:
                    token = create_session(d["username"])
                    self.send_response(200)
                    self.send_header("Content-Type","application/json")
                    self.send_header("Set-Cookie",f"hp_session={token}; Path=/; Max-Age={CONFIG['session_timeout']}; HttpOnly")
                    self.end_headers()
                    self.wfile.write(json.dumps({"success":True}).encode())
                else:
                    self.json_response({"success":False,"error":"Invalid credentials"},401)
            except Exception as e:
                self.json_response({"success":False,"error":str(e)},400)
            return
        if path == "/api/logout":
            token = get_session_token(self)
            if token and token in sessions: del sessions[token]
            self.send_response(200)
            self.send_header("Content-Type","application/json")
            self.send_header("Set-Cookie","hp_session=; Path=/; Max-Age=0; HttpOnly")
            self.end_headers()
            self.wfile.write(json.dumps({"success":True}).encode())
            return
        if not validate_session(get_session_token(self)):
            self.json_response({"error":"Unauthorized"},401); return
        if path == "/api/clear":
            with state_lock:
                events.clear(); alerts.clear(); attackers.clear()
                hourly_data.clear(); protocol_stats.clear()
            self.json_response({"success":True})
        else:
            self.send_response(404); self.end_headers()

def start_dashboard(port):
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer(("0.0.0.0", port), DashboardHandler) as server:
        print(f"  ✓ Dashboard  :{port}  →  http://{SERVER_IP}:{port}")
        server.serve_forever()

# ═══════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════

def main():
    print("=" * 62)
    print("  NETWATCH SOC — HONEYPOT SECURITY PLATFORM v3.0")
    print("=" * 62)
    print(f"  Server IP  : {SERVER_IP}")
    print(f"  Dashboard  : http://{SERVER_IP}:{CONFIG['dashboard_port']}")
    print(f"  Login      : {CONFIG['admin_user']} / {CONFIG['admin_pass']}")
    print(f"  Demo Mode  : {'ON (simulated traffic)' if CONFIG['demo_mode'] else 'OFF (real traffic only)'}")
    print("=" * 62)
    print("  Starting services…\n")

    services = [
        (start_ssh_honeypot,    (CONFIG["ssh_port"],)),
        (start_http_honeypot,   (CONFIG["http_port"],)),
        (start_ftp_honeypot,    (CONFIG["ftp_port"],)),
        (start_telnet_honeypot, (CONFIG["telnet_port"],)),
        (start_smtp_honeypot,   (CONFIG["smtp_port"],)),
        (start_dns_honeypot,    (CONFIG["dns_port"],)),
        (start_dashboard,       (CONFIG["dashboard_port"],)),
    ]
    if CONFIG["demo_mode"]:
        services.append((demo_event_generator, ()))

    threads = []
    for fn, args in services:
        t = threading.Thread(target=fn, args=args, daemon=True)
        t.start(); threads.append(t); time.sleep(0.1)

    print("\n" + "=" * 62)
    print("  ALL SERVICES ACTIVE")
    print("=" * 62)
    print(f"\n  Browser →  http://{SERVER_IP}:{CONFIG['dashboard_port']}")
    print(f"  Creds   →  {CONFIG['admin_user']} / {CONFIG['admin_pass']}\n")
    print("  Honeypot Ports:")
    print(f"    SSH     : {CONFIG['ssh_port']}")
    print(f"    HTTP    : {CONFIG['http_port']}")
    print(f"    FTP     : {CONFIG['ftp_port']}")
    print(f"    Telnet  : {CONFIG['telnet_port']}")
    print(f"    SMTP    : {CONFIG['smtp_port']}")
    print(f"    DNS/UDP : {CONFIG['dns_port']}")
    print("\n  Test commands:")
    print(f"    curl http://localhost:{CONFIG['http_port']}/admin")
    print(f"    ssh -p {CONFIG['ssh_port']} root@localhost")
    print(f"    ftp -n localhost {CONFIG['ftp_port']}")
    print("\n  Set demo_mode=False in CONFIG for real traffic only.")
    print("=" * 62)
    print("  Press Ctrl+C to stop\n")

    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        print("\n  Shutting down…")

if __name__ == "__main__":
    main()
