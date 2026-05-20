#!/bin/bash

SERVER="${1:-localhost}"
INTERVAL="${2:-5}"

echo "========================================="
echo "Continuous Honeypot Test"
echo "Target: $SERVER"
echo "Interval: ${INTERVAL}s"
echo "Press Ctrl+C to stop"
echo "========================================="

counter=0
while true; do
    counter=$((counter + 1))
    echo ""
    echo "[$(date +%H:%M:%S)] Test #$counter"
    
    # Send different attack each time
    case $((counter % 5)) in
        0)
            echo "  Sending SSH attempt..."
            (echo "test"; sleep 0.3; echo "pass"; sleep 0.3; echo "exit") | nc -w 2 $SERVER 22 2>/dev/null
            ;;
        1)
            echo "  Sending HTTP SQL injection..."
            curl -s "http://$SERVER:80/?id=1' OR '1'='1" > /dev/null
            ;;
        2)
            echo "  Sending FTP attempt..."
            (echo "USER admin"; sleep 0.3; echo "PASS admin"; sleep 0.3; echo "QUIT") | nc -w 2 $SERVER 21 2>/dev/null
            ;;
        3)
            echo "  Sending DNS query..."
            dig @$SERVER test$counter.evil.com +short > /dev/null 2>&1
            ;;
        4)
            echo "  Sending port scan..."
            for port in 22 80 443; do
                timeout 1 nc -zv $SERVER $port 2>&1 > /dev/null
            done
            ;;
    esac
    
    echo "  ✓ Test $counter complete"
    sleep $INTERVAL
done
