#!/bin/bash

SERVER="${1:-localhost}"
THREADS="${2:-10}"
DURATION="${3:-30}"

echo "========================================="
echo "Honeypot Load Test"
echo "Target: $SERVER"
echo "Threads: $THREADS"
echo "Duration: ${DURATION}s"
echo "========================================="

# Function to send random attacks
send_attack() {
    local id=$1
    local end_time=$((SECONDS + DURATION))
    
    while [ $SECONDS -lt $end_time ]; do
        attack_type=$((RANDOM % 8))
        
        case $attack_type in
            0)
                (echo "user$id"; sleep 0.1; echo "pass$id"; sleep 0.1; echo "exit") | nc -w 1 $SERVER 22 2>/dev/null
                ;;
            1)
                curl -s -X GET "http://$SERVER:80/?id=$RANDOM" > /dev/null
                ;;
            2)
                (echo "USER user$id"; sleep 0.1; echo "PASS pass$id"; sleep 0.1; echo "QUIT") | nc -w 1 $SERVER 21 2>/dev/null
                ;;
            3)
                dig @$SERVER random$RANDOM.com +short > /dev/null 2>&1
                ;;
            4)
                (echo "root"; sleep 0.1; echo "wrong"; sleep 0.1) | nc -w 1 $SERVER 23 2>/dev/null
                ;;
            5)
                curl -s -X POST "http://$SERVER:80/login" -d "user=admin&pass=admin" > /dev/null
                ;;
            6)
                echo "QUIT" | nc -w 1 $SERVER 25 2>/dev/null
                ;;
            7)
                for p in 22 80 443; do
                    timeout 1 nc -zv $SERVER $p 2>&1 > /dev/null
                done
                ;;
        esac
        
        sleep 0.$((RANDOM % 10))
    done
}

# Start attacks in parallel
echo "Starting $THREADS attack threads..."
for i in $(seq 1 $THREADS); do
    send_attack $i &
    pids[$i]=$!
done

# Wait for completion
echo "Running for ${DURATION} seconds..."
sleep $DURATION

# Stop all threads
echo "Stopping threads..."
for i in $(seq 1 $THREADS); do
    kill ${pids[$i]} 2>/dev/null
done

echo ""
echo "========================================="
echo "✅ Load test complete!"
echo "Total attacks sent: ~$((THREADS * DURATION * 5))"
echo "Check dashboard for results"
echo "========================================="
