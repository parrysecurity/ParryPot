#!/usr/bin/env python3
"""Simple Working Honeypot - All-in-One"""

import asyncio
import socket
import threading
import json
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
import socketserver

# Simple HTTP Dashboard Handler
class DashboardHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # Suppress logging
    
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            html = '''<!DOCTYPE html>
<html>
<head>
    <title>Honeypot Security Dashboard</title>
    <meta charset="UTF-8">
    <meta http-equiv="refresh" content="5">
    <style>
        body { font-family: monospace; background: #0a0e27; color: #0f0; padding: 20px; margin: 0; }
        h1 { color: #0f0; border-bottom: 2px solid #0f0; padding-bottom: 10px; }
        .container { max-width: 1200px; margin: auto; }
        .panel { background: #1a1a3e; border-radius: 8px; padding: 20px; margin: 20px 0; border: 1px solid #2a2a4e; }
        .panel h2 { margin-top: 0; color: #0f0; }
        .port-list { display: flex; flex-wrap: wrap; gap: 10px; margin: 15px 0; }
        .port-item { background: #0a0e27; padding: 8px 15px; border-radius: 5px; font-size: 14px; border-left: 3px solid #0f0; }
        .event { background: #0a0e27; padding: 10px; margin: 5px 0; border-radius: 3px; font-size: 12px; }
        .alert { background: #2a0a0a; border-left: 3px solid #f00; padding: 10px; margin: 5px 0; }
        .critical { color: #f00; }
        .high { color: #f60; }
        .ip-address { font-size: 18px; color: #ff0; background: #0a0e27; padding: 10px; border-radius: 5px; }
        .footer { text-align: center; color: #666; margin-top: 30px; font-size: 12px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { text-align: left; padding: 8px; border-bottom: 1px solid #2a2a4e; }
        th { color: #0f0; }
    </style>
</head>
<body>
<div class="container">
    <h1>🔒 All-In-One Honeypot Platform</h1>
    <div class="panel">
        <h2>📡 Server Information</h2>
        <div class="ip-address">Server IP: <span id="server_ip">Loading...</span></div>
        <div class="port-list" id="ports"></div>
    </div>
    <div class="panel">
        <h2>🚨 Recent Alerts</h2>
        <div id="alerts">No alerts yet...</div>
    </div>
    <div class="panel">
        <h2>📊 Connection Log</h2>
        <div id="events">No connections yet...</div>
    </div>
    <div class="footer">
        Security Research Environment - All access is monitored and logged
    </div>
</div>
<script>
    fetch('/api/info')
        .then(r => r.json())
        .then(data => {
            document.getElementById('server_ip').innerText = data.server_ip;
            const portsDiv = document.getElementById('ports');
            data.ports.forEach(p => {
                portsDiv.innerHTML += `<div class="port-item">${p.name}:${p.port}</div>`;
            });
        });
    function refreshData() {
        fetch('/api/events')
            .then(r => r.json())
            .then(data => {
                const eventsDiv = document.getElementById('events');
                if (data.events && data.events.length > 0) {
                    eventsDiv.innerHTML = '<table><tr><th>Time</th><th>Protocol</th><th>Source IP</th><th>Details</th></tr>' + 
                        data.events.map(e => `<tr><td>${e.time}</td><td>${e.protocol}</td><td>${e.src_ip}</td><td>${e.details || ''}</td></tr>`).join('') + 
                        '</table>';
                } else {
                    eventsDiv.innerHTML = 'No connections yet...';
                }
            });
        fetch('/api/alerts')
            .then(r => r.json())
            .then(data => {
                const alertsDiv = document.getElementById('alerts');
                if (data.alerts && data.alerts.length > 0) {
                    alertsDiv.innerHTML = data.alerts.map(a => `<div class="alert ${a.severity.toLowerCase()}">[${a.severity}] ${a.message} - ${a.src_ip} at ${a.time}</div>`).join('');
                } else {
                    alertsDiv.innerHTML = 'No alerts yet...';
                }
            });
    }
    refreshData();
    setInterval(refreshData, 3000);
</script>
</body>
</html>'''
            self.wfile.write(html.encode())
        elif self.path == '/api/info':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            info = {'server_ip': HoneypotServer.SERVER_IP, 'ports': HoneypotServer.PORTS}
            self.wfile.write(json.dumps(info).encode())
        elif self.path == '/api/events':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            events = HoneypotServer.get_events()
            self.wfile.write(json.dumps({'events': events[-50:]}).encode())
        elif self.path == '/api/alerts':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            alerts = HoneypotServer.get_alerts()
            self.wfile.write(json.dumps({'alerts': alerts[-30:]}).encode())
        else:
            self.send_response(404)
            self.end_headers()

class HoneypotServer:
    SERVER_IP = None
    PORTS = [
        {'name': 'SSH', 'port': 22},
        {'name': 'HTTP', 'port': 80},
        {'name': 'HTTPS', 'port': 443},
        {'name': 'FTP', 'port': 21},
        {'name': 'Telnet', 'port': 23},
        {'name': 'SMTP', 'port': 25},
        {'name': 'DNS', 'port': 53}
    ]
    events = []
    alerts = []
    
    @classmethod
    def get_server_ip(cls):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    @classmethod
    def add_event(cls, protocol, src_ip, details=""):
        event = {
            'time': datetime.now().strftime('%H:%M:%S'),
            'protocol': protocol,
            'src_ip': src_ip,
            'details': details
        }
        cls.events.append(event)
        if len(cls.events) > 100:
            cls.events.pop(0)
        print(f"[{protocol}] Connection from {src_ip} - {details}")
        return event
    
    @classmethod
    def add_alert(cls, severity, message, src_ip):
        alert = {
            'time': datetime.now().strftime('%H:%M:%S'),
            'severity': severity,
            'message': message,
            'src_ip': src_ip
        }
        cls.alerts.append(alert)
        if len(cls.alerts) > 50:
            cls.alerts.pop(0)
        print(f"🚨 ALERT [{severity}] {message} from {src_ip}")
    
    @classmethod
    def get_events(cls):
        return cls.events
    
    @classmethod
    def get_alerts(cls):
        return cls.alerts

# TCP Handler for all protocols
class TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        client_ip = self.client_address[0]
        protocol = self.server.protocol_name
        
        HoneypotServer.add_event(protocol, client_ip, f"Connection attempt")
        
        # Send fake banner
        banners = {
            'SSH': b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n",
            'FTP': b"220 FTP Server Ready\r\n",
            'Telnet': b"\r\nWelcome to Ubuntu 22.04 LTS\r\nlogin: ",
            'SMTP': b"220 honeypot.local ESMTP Honeypot\r\n",
        }
        
        if protocol in banners:
            try:
                self.request.sendall(banners[protocol])
            except:
                pass

# DNS UDP Handler
class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, socket = self.request
        client_ip = self.client_address[0]
        HoneypotServer.add_event('DNS', client_ip, f"DNS query received")

def start_tcp_server(port, protocol_name):
    class CustomTCPHandler(TCPHandler):
        pass
    
    try:
        with socketserver.TCPServer(("0.0.0.0", port), CustomTCPHandler) as server:
            server.protocol_name = protocol_name
            print(f"  ✓ {protocol_name} listener on port {port}")
            server.serve_forever()
    except OSError as e:
        if "Address already in use" in str(e):
            print(f"  ⚠ Port {port} is in use, trying alt port {port+2000}")
            with socketserver.TCPServer(("0.0.0.0", port+2000), CustomTCPHandler) as server:
                server.protocol_name = f"{protocol_name}(alt)"
                print(f"  ✓ {protocol_name} listener on port {port+2000}")
                server.serve_forever()
        else:
            print(f"  ✗ Failed to start {protocol_name}: {e}")

def start_http_dashboard():
    try:
        with socketserver.TCPServer(("0.0.0.0", 5000), DashboardHandler) as server:
            print(f"  ✓ Dashboard on port 5000")
            server.serve_forever()
    except OSError:
        print(f"  ✓ Dashboard on port 5001 (alt)")
        with socketserver.TCPServer(("0.0.0.0", 5001), DashboardHandler) as server:
            server.serve_forever()

def start_dns_server():
    try:
        with socketserver.UDPServer(("0.0.0.0", 53), DNSHandler) as server:
            print(f"  ✓ DNS listener on port 53")
            server.serve_forever()
    except OSError:
        print(f"  ⚠ DNS port 53 in use")

def main():
    print("=" * 60)
    print("All-In-One Honeypot Platform v1.0")
    print("=" * 60)
    
    # Get server IP
    HoneypotServer.SERVER_IP = HoneypotServer.get_server_ip()
    print(f"Server IP: {HoneypotServer.SERVER_IP}")
    print(f"Dashboard: http://{HoneypotServer.SERVER_IP}:5000 or http://{HoneypotServer.SERVER_IP}:5001")
    print("=" * 60)
    print("Starting listeners...")
    
    # Start all listeners in threads
    threads = []
    
    # TCP Listeners
    tcp_ports = [
        (21, "FTP"),
        (22, "SSH"),
        (23, "Telnet"),
        (25, "SMTP"),
        (80, "HTTP"),
        (443, "HTTPS"),
    ]
    
    for port, name in tcp_ports:
        t = threading.Thread(target=start_tcp_server, args=(port, name), daemon=True)
        t.start()
        threads.append(t)
    
    # DNS UDP
    try:
        dns_thread = threading.Thread(target=start_dns_server, daemon=True)
        dns_thread.start()
        threads.append(dns_thread)
    except Exception as e:
        print(f"  ✗ Failed to start DNS: {e}")
    
    # Dashboard
    dashboard_thread = threading.Thread(target=start_http_dashboard, daemon=True)
    dashboard_thread.start()
    threads.append(dashboard_thread)
    
    print("=" * 60)
    print("✅ HONEYPOT IS RUNNING!")
    print(f"📊 Open browser: http://{HoneypotServer.SERVER_IP}:5000")
    print("=" * 60)
    print("Press Ctrl+C to stop")
    
    try:
        while True:
            import time
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down...")
        print("Goodbye!")

if __name__ == "__main__":
    main()
