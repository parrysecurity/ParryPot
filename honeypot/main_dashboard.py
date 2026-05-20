#!/usr/bin/env python3
"""Honeypot Security Platform - Professional Dashboard"""

import socket
import threading
import json
import time
import os
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
import socketserver

# Global data storage
events = []
alerts = []
attackers = {}

# Port configuration (alternative ports to avoid conflicts)
PORT_CONFIG = [
    (2022, 'SSH'),
    (2080, 'HTTP'),
    (2021, 'FTP'),
    (2023, 'Telnet'),
    (2025, 'SMTP'),
    (2053, 'DNS'),
]

def get_server_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

SERVER_IP = get_server_ip()

def add_event(protocol, src_ip, details=""):
    event = {
        'time': datetime.now().strftime('%H:%M:%S'),
        'protocol': protocol,
        'src_ip': src_ip,
        'details': details,
        'severity': 'INFO'
    }
    events.insert(0, event)
    if len(events) > 500:
        events.pop()
    
    # Track attacker
    if src_ip not in attackers:
        attackers[src_ip] = {'count': 0, 'first_seen': datetime.now().strftime('%H:%M:%S')}
    attackers[src_ip]['count'] += 1
    
    # Generate alert for suspicious activity
    count = attackers[src_ip]['count']
    if count == 5:
        alert = {
            'time': datetime.now().strftime('%H:%M:%S'),
            'severity': 'MEDIUM',
            'message': f'Suspicious: {count} attempts from {src_ip}',
            'src_ip': src_ip
        }
        alerts.insert(0, alert)
        print(f"🚨 [MEDIUM] {alert['message']}")
    elif count == 10:
        alert = {
            'time': datetime.now().strftime('%H:%M:%S'),
            'severity': 'HIGH',
            'message': f'Brute force detected: {count} attempts from {src_ip}',
            'src_ip': src_ip
        }
        alerts.insert(0, alert)
        print(f"🚨 [HIGH] {alert['message']}")
    
    if len(alerts) > 200:
        alerts.pop()
    
    print(f"[{protocol}] {src_ip} - {details}")
    return event

def start_tcp_server(port, protocol_name):
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            client_ip = self.client_address[0]
            add_event(protocol_name, client_ip, f"Connection")
            try:
                banners = {
                    'SSH': b"SSH-2.0-OpenSSH_8.9p1 Ubuntu\r\n",
                    'FTP': b"220 FTP Server Ready\r\n",
                    'Telnet': b"\r\nWelcome to Ubuntu\r\nlogin: ",
                    'SMTP': b"220 ESMTP Honeypot\r\n",
                    'HTTP': b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body><h1>Honeypot Active</h1><p>Your activity is logged</p></body></html>"
                }
                if protocol_name in banners:
                    self.request.sendall(banners[protocol_name])
            except:
                pass
            self.request.close()
    
    try:
        with socketserver.TCPServer(("0.0.0.0", port), Handler) as server:
            print(f"  ✓ {protocol_name}:{port}")
            server.serve_forever()
    except OSError as e:
        print(f"  ✗ {protocol_name}:{port} failed - {e}")

def start_dns_server():
    class DNSHandler(socketserver.BaseRequestHandler):
        def handle(self):
            client_ip = self.client_address[0]
            add_event('DNS', client_ip, "DNS query")
    
    try:
        with socketserver.UDPServer(("0.0.0.0", 2053), DNSHandler) as server:
            print(f"  ✓ DNS:2053")
            server.serve_forever()
    except OSError as e:
        print(f"  ✗ DNS:2053 failed - {e}")

class DashboardHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass
    
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            # Try to load the existing template
            template_path = '/var/www/all-in-one-honeypot/honeypot/dashboard/templates/index.html'
            if os.path.exists(template_path):
                with open(template_path, 'r') as f:
                    html = f.read()
            else:
                html = self.get_fallback_html()
            self.wfile.write(html.encode())
        
        elif self.path == '/api/info':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            info = {
                'server_ip': SERVER_IP,
                'ports': [{'name': name, 'port': port} for port, name in PORT_CONFIG],
                'total_events': len(events),
                'total_alerts': len(alerts),
                'unique_attackers': len(attackers)
            }
            self.wfile.write(json.dumps(info).encode())
        
        elif self.path == '/api/events':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'events': events[:200]}).encode())
        
        elif self.path == '/api/alerts':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'alerts': alerts[:100]}).encode())
        
        elif self.path == '/api/attackers':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            attacker_list = [{'ip': ip, 'count': data['count'], 'first_seen': data['first_seen']} 
                           for ip, data in list(attackers.items())[:50]]
            self.wfile.write(json.dumps({'attackers': attacker_list}).encode())
        
        elif self.path == '/api/stats':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            # Count by protocol
            protocol_count = {}
            for e in events:
                proto = e.get('protocol', 'UNKNOWN')
                protocol_count[proto] = protocol_count.get(proto, 0) + 1
            self.wfile.write(json.dumps({
                'protocols': protocol_count,
                'total': len(events),
                'alerts': len(alerts),
                'attackers': len(attackers)
            }).encode())
        
        else:
            self.send_response(404)
            self.end_headers()
    
    def get_fallback_html(self):
        return '''<!DOCTYPE html>
<html>
<head>
    <title>Honeypot Security Platform</title>
    <meta charset="UTF-8">
    <meta http-equiv="refresh" content="5">
    <style>
        body { font-family: monospace; background: #0a0e27; color: #0f0; padding: 20px; }
        h1 { color: #0f0; }
        .stats { background: #1a1a3e; padding: 20px; border-radius: 10px; margin: 10px 0; }
        .value { font-size: 36px; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; }
        th, td { text-align: left; padding: 8px; border-bottom: 1px solid #333; }
    </style>
</head>
<body>
    <h1>🔒 Honeypot Security Platform</h1>
    <p>Server IP: <strong id="serverIp">''' + SERVER_IP + '''</strong></p>
    <div class="stats" id="stats">
        <div>Total Events: <span class="value" id="totalEvents">0</span></div>
        <div>Total Alerts: <span class="value" id="totalAlerts">0</span></div>
        <div>Unique Attackers: <span class="value" id="uniqueAttackers">0</span></div>
    </div>
    <h2>Recent Events</h2>
    <div id="events"></div>
    <script>
        function fetchData() {
            fetch('/api/info').then(r => r.json()).then(data => {
                document.getElementById('totalEvents').innerText = data.total_events;
                document.getElementById('totalAlerts').innerText = data.total_alerts;
                document.getElementById('uniqueAttackers').innerText = data.unique_attackers;
            });
            fetch('/api/events').then(r => r.json()).then(data => {
                const eventsDiv = document.getElementById('events');
                if (data.events && data.events.length > 0) {
                    eventsDiv.innerHTML = '<table><tr><th>Time</th><th>Protocol</th><th>Source IP</th><th>Details</th></tr>' +
                        data.events.map(e => `<tr><td>${e.time}</td><td>${e.protocol}</td><td>${e.src_ip}</td><td>${e.details}</td></tr>`).join('') +
                        '</table>';
                } else {
                    eventsDiv.innerHTML = 'No events yet...';
                }
            });
        }
        fetchData();
        setInterval(fetchData, 3000);
    </script>
</body>
</html>'''

def start_dashboard():
    with socketserver.TCPServer(("0.0.0.0", 5000), DashboardHandler) as server:
        print(f"  ✓ Dashboard:5000")
        server.serve_forever()

def main():
    print("=" * 60)
    print("🔒 HONEYPOT SECURITY PLATFORM")
    print("=" * 60)
    print(f"Server IP: {SERVER_IP}")
    print(f"Dashboard: http://{SERVER_IP}:5000")
    print("=" * 60)
    print("Starting honeypot services...")
    
    threads = []
    
    # Start TCP servers
    for port, name in PORT_CONFIG:
        t = threading.Thread(target=start_tcp_server, args=(port, name), daemon=True)
        t.start()
        threads.append(t)
        time.sleep(0.2)
    
    # Start DNS
    dns_thread = threading.Thread(target=start_dns_server, daemon=True)
    dns_thread.start()
    threads.append(dns_thread)
    
    # Start Dashboard
    dashboard_thread = threading.Thread(target=start_dashboard, daemon=True)
    dashboard_thread.start()
    threads.append(dashboard_thread)
    
    print("=" * 60)
    print("✅ HONEYPOT ACTIVE")
    print(f"🌐 Dashboard: http://{SERVER_IP}:5000")
    print("=" * 60)
    print("\n📡 Active Honeypot Ports:")
    for port, name in PORT_CONFIG:
        print(f"   {name}:{port}")
    print("=" * 60)
    print("Press Ctrl+C to stop\n")
    
    # Generate some demo events
    def generate_demo_events():
        demo_ips = ['192.168.1.100', '10.0.0.50', '172.16.0.25', '8.8.8.8', '1.1.1.1']
        demo_protocols = ['SSH', 'HTTP', 'FTP', 'Telnet']
        while True:
            time.sleep(15)
            import random
            ip = random.choice(demo_ips)
            proto = random.choice(demo_protocols)
            add_event(proto, ip, "Demo connection")
    
    demo_thread = threading.Thread(target=generate_demo_events, daemon=True)
    demo_thread.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 Shutting down...")
        print("Goodbye!")

if __name__ == "__main__":
    main()
