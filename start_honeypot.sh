#!/bin/bash

# All-In-One Honeypot Production Launcher

SERVER_IP=$(hostname -I | awk '{print $1}')
echo "========================================="
echo "All-In-One Honeypot Platform"
echo "========================================="
echo "Server IP: $SERVER_IP"
echo "Dashboard: http://$SERVER_IP:5000"
echo "========================================="

# Kill any existing processes on ports
echo "Cleaning up ports..."
for port in 21 22 23 25 53 80 443 445 2222 1080 5000; do
    fuser -k $port/tcp 2>/dev/null
done

# Wait for ports to clear
sleep 2

# Set environment
export PYTHONPATH=$(pwd)
export SERVER_IP=$SERVER_IP

# Start the honeypot
echo "Starting honeypot on $SERVER_IP..."
sudo python3 -m honeypot.main
