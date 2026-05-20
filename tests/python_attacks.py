#!/usr/bin/env python3
"""
Python-based attack simulator for honeypot testing
"""

import socket
import threading
import requests
import time
import random
import sys

# Configuration
SERVER_IP = sys.argv[1] if len(sys.argv) > 1 else "localhost"

def ssh_attack():
    """Simulate SSH attack"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((SERVER_IP, 22))
        sock.recv(1024)
        sock.send(b"root\n")
        sock.recv(1024)
        sock.send(b"wrongpassword\n")
        time.sleep(0.5)
        sock.close()
        print(f"✓ SSH attack sent to {SERVER_IP}:22")
    except Exception as e:
        print(f"✗ SSH attack failed: {e}")

def http_attacks():
    """Simulate HTTP attacks"""
    urls = [
        f"http://{SERVER_IP}:80/?id=1' OR '1'='1",
        f"http://{SERVER_IP}:80/../../../../etc/passwd",
        f"http://{SERVER_IP}:80/<script>alert('xss')</script>",
        f"http://{SERVER_IP}:80/admin",
        f"http://{SERVER_IP}:80/wp-login.php",
    ]
    
    for url in urls:
        try:
            requests.get(url, timeout=2)
            print(f"✓ HTTP request to {url[:50]}...")
        except:
            print(f"✗ HTTP request failed")
        time.sleep(0.3)

def ftp_attack():
    """Simulate FTP attack"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((SERVER_IP, 21))
        sock.recv(1024)
        sock.send(b"USER admin\n")
        sock.recv(1024)
        sock.send(b"PASS admin\n")
        time.sleep(0.5)
        sock.close()
        print(f"✓ FTP attack sent to {SERVER_IP}:21")
    except Exception as e:
        print(f"✗ FTP attack failed: {e}")

def dns_attack():
    """Simulate DNS attack (DNS tunneling simulation)"""
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [SERVER_IP]
        domain = f"{random.randint(10000,99999)}.malicious.com"
        resolver.resolve(domain, 'A')
        print(f"✓ DNS query for {domain}")
    except:
        # Use dig command as fallback
        import subprocess
        domain = f"test{random.randint(1,9999)}.evil.com"
        subprocess.run(f"dig @{SERVER_IP} {domain} +short", shell=True, capture_output=True)
        print(f"✓ DNS query for {domain}")

def telnet_attack():
    """Simulate Telnet attack"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((SERVER_IP, 23))
        sock.recv(1024)
        sock.send(b"root\n")
        time.sleep(0.3)
        sock.send(b"wrong\n")
        time.sleep(0.3)
        sock.close()
        print(f"✓ Telnet attack sent to {SERVER_IP}:23")
    except Exception as e:
        print(f"✗ Telnet attack failed: {e}")

def smtp_attack():
    """Simulate SMTP attack"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((SERVER_IP, 25))
        sock.recv(1024)
        sock.send(b"HELO attacker.com\n")
        sock.recv(1024)
        sock.send(b"MAIL FROM: <spammer@evil.com>\n")
        sock.recv(1024)
        sock.send(b"RCPT TO: <victim@target.com>\n")
        sock.recv(1024)
        sock.send(b"QUIT\n")
        sock.close()
        print(f"✓ SMTP attack sent to {SERVER_IP}:25")
    except Exception as e:
        print(f"✗ SMTP attack failed: {e}")

def port_scan():
    """Simulate port scanning"""
    ports = [21, 22, 23, 25, 53, 80, 443, 445, 3306, 5432, 8080, 8443]
    open_ports = []
    
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((SERVER_IP, port))
            if result == 0:
                open_ports.append(port)
                print(f"  Port {port}: OPEN")
            sock.close()
        except:
            pass
    
    print(f"✓ Port scan complete. Found {len(open_ports)} open ports")
    return open_ports

def main():
    print("=" * 50)
    print("Python Honeypot Attack Simulator")
    print(f"Target: {SERVER_IP}")
    print("=" * 50)
    
    attacks = [
        ("SSH Attack", ssh_attack),
        ("HTTP Attacks", http_attacks),
        ("FTP Attack", ftp_attack),
        ("Telnet Attack", telnet_attack),
        ("SMTP Attack", smtp_attack),
        ("DNS Attack", dns_attack),
        ("Port Scan", port_scan),
    ]
    
    for name, attack in attacks:
        print(f"\n[+] Running {name}...")
        attack()
        time.sleep(1)
    
    print("\n" + "=" * 50)
    print("✅ All attacks simulated!")
    print(f"Check dashboard: http://{SERVER_IP}:5000")
    print("=" * 50)

if __name__ == "__main__":
    main()
