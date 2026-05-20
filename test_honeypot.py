#!/usr/bin/env python3
"""Test script to simulate attacks"""

import socket
import sys

def test_ssh():
    print("[TEST] Testing SSH honeypot...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect(('127.0.0.1', 22))
        banner = sock.recv(1024)
        print(f"SSH Response: {banner[:50]}")
        sock.close()
        print("✓ SSH honeypot responding")
    except Exception as e:
        print(f"✗ SSH test failed: {e}")

def test_http():
    print("\n[TEST] Testing HTTP honeypot...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect(('127.0.0.1', 80))
        sock.send(b"GET / HTTP/1.0\r\n\r\n")
        response = sock.recv(1024)
        print(f"HTTP Response: {response[:100]}")
        sock.close()
        print("✓ HTTP honeypot responding")
    except Exception as e:
        print(f"✗ HTTP test failed: {e}")

def test_ftp():
    print("\n[TEST] Testing FTP honeypot...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect(('127.0.0.1', 21))
        banner = sock.recv(1024)
        print(f"FTP Response: {banner[:50]}")
        sock.close()
        print("✓ FTP honeypot responding")
    except Exception as e:
        print(f"✗ FTP test failed: {e}")

def test_dns():
    print("\n[TEST] Testing DNS honeypot...")
    import random
    import struct
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        # Simple DNS query
        transaction_id = random.randint(1, 65535)
        query = struct.pack('>HHHHHH', transaction_id, 0x0100, 1, 0, 0, 0)
        query += b'\x03www\x07example\x03com\x00\x00\x01\x00\x01'
        sock.sendto(query, ('127.0.0.1', 53))
        data, _ = sock.recvfrom(512)
        print(f"DNS Response received: {len(data)} bytes")
        sock.close()
        print("✓ DNS honeypot responding")
    except Exception as e:
        print(f"✗ DNS test failed: {e}")

if __name__ == "__main__":
    print("=" * 50)
    print("All-In-One Honeypot Test Suite")
    print("=" * 50)
    test_ssh()
    test_http()
    test_ftp()
    test_dns()
    print("\n" + "=" * 50)
    print("If all tests passed, your honeypot is working!")
    print("Open browser: http://localhost:5000")
    print("=" * 50)
