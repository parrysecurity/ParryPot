#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
SERVER="${1:-localhost}"
DELAY="${2:-1}"

echo -e "${CYAN}========================================="
echo "🔴 HONEYPOT ATTACK SIMULATOR"
echo "=========================================${NC}"
echo -e "${YELLOW}Target: $SERVER${NC}"
echo -e "${YELLOW}Ports: SSH:2022, HTTP:2080, FTP:2021, Telnet:2023, SMTP:2025, DNS:2053${NC}"
echo -e "${CYAN}=========================================${NC}"
echo ""

# Function to test SSH
test_ssh() {
    echo -e "${BLUE}[TEST 1] SSH Brute Force Simulation${NC}"
    for i in {1..15}; do
        (
            echo "root"
            sleep 0.2
            echo "wrongpass$i"
            sleep 0.2
            echo "exit"
        ) | nc -w 3 $SERVER 2022 2>/dev/null &
        echo -n "."
    done
    wait
    echo -e "\n${GREEN}✓ SSH: 15 brute force attempts sent${NC}"
    sleep $DELAY
}

# Function to test HTTP
test_http() {
    echo -e "\n${BLUE}[TEST 2] HTTP Attack Simulation${NC}"
    
    # SQL Injection
    curl -s "http://$SERVER:2080/?id=1' OR '1'='1" > /dev/null
    echo -n "✓ SQL Injection sent"
    
    # XSS
    curl -s "http://$SERVER:2080/?search=<script>alert(1)</script>" > /dev/null
    echo -n " | XSS sent"
    
    # Path Traversal
    curl -s "http://$SERVER:2080/../../../../etc/passwd" > /dev/null
    echo -n " | Path Traversal sent"
    
    # Directory Bruteforce
    for dir in admin wp-admin phpmyadmin cpanel webmail; do
        curl -s -o /dev/null "http://$SERVER:2080/$dir"
    done
    echo -n " | Directory scan sent"
    
    echo -e "\n${GREEN}✓ HTTP: Multiple attack vectors tested${NC}"
    sleep $DELAY
}

# Function to test FTP
test_ftp() {
    echo -e "\n${BLUE}[TEST 3] FTP Attack Simulation${NC}"
    
    credentials=(
        "admin:admin"
        "root:toor"
        "ftp:ftp"
        "user:password"
        "test:test"
        "administrator:admin123"
        "webmaster:webmaster"
    )
    
    for cred in "${credentials[@]}"; do
        IFS=':' read -r user pass <<< "$cred"
        (
            echo "USER $user"
            sleep 0.3
            echo "PASS $pass"
            sleep 0.3
            echo "QUIT"
        ) | nc -w 3 $SERVER 2021 2>/dev/null &
        echo -n "."
    done
    wait
    echo -e "\n${GREEN}✓ FTP: ${#credentials[@]} login attempts sent${NC}"
    sleep $DELAY
}

# Function to test Telnet
test_telnet() {
    echo -e "\n${BLUE}[TEST 4] Telnet Attack Simulation${NC}"
    
    for user in root admin test oracle; do
        (
            echo "$user"
            sleep 0.5
            echo "wrongpass"
            sleep 0.5
            echo "exit"
        ) | nc -w 3 $SERVER 2023 2>/dev/null &
        echo -n "."
    done
    wait
    echo -e "\n${GREEN}✓ Telnet: 4 login attempts sent${NC}"
    sleep $DELAY
}

# Function to test SMTP
test_smtp() {
    echo -e "\n${BLUE}[TEST 5] SMTP Attack Simulation${NC}"
    
    # Open relay test
    (
        echo "HELO attacker.com"
        sleep 0.3
        echo "MAIL FROM: <spammer@evil.com>"
        sleep 0.3
        echo "RCPT TO: <victim@target.com>"
        sleep 0.3
        echo "DATA"
        sleep 0.3
        echo "Subject: Test Spam"
        sleep 0.3
        echo "This is a test email"
        sleep 0.3
        echo "."
        sleep 0.3
        echo "QUIT"
    ) | nc -w 5 $SERVER 2025 2>/dev/null
    
    echo -e "${GREEN}✓ SMTP: Open relay test completed${NC}"
    sleep $DELAY
}

# Function to test DNS
test_dns() {
    echo -e "\n${BLUE}[TEST 6] DNS Attack Simulation${NC}"
    
    # DNS queries
    for i in {1..10}; do
        dig @$SERVER -p 2053 "test$i.evil.com" +short > /dev/null 2>&1 &
        echo -n "."
    done
    wait
    
    # Long domain (DNS tunneling simulation)
    LONG_DOMAIN=$(python3 -c "print('a'*50 + '.evil.com')")
    dig @$SERVER -p 2053 $LONG_DOMAIN +short > /dev/null 2>&1
    
    echo -e "\n${GREEN}✓ DNS: 11 queries sent (including tunneling test)${NC}"
    sleep $DELAY
}

# Function to test Port Scan
test_portscan() {
    echo -e "\n${BLUE}[TEST 7] Port Scan Simulation${NC}"
    
    ports=(2021 2022 2023 2025 2080 2053 3000 3306 5432 8080)
    
    for port in "${ports[@]}"; do
        timeout 1 nc -zv $SERVER $port 2>&1 | grep -q succeeded && echo "  Port $port: OPEN" || echo "  Port $port: CLOSED"
    done
    
    echo -e "${GREEN}✓ Port scan completed${NC}"
    sleep $DELAY
}

# Function to test Web Shell Uploads
test_webshell() {
    echo -e "\n${BLUE}[TEST 8] Web Shell Upload Simulation${NC}"
    
    shells=("cmd.php" "shell.asp" "backdoor.jsp" "webshell.aspx" "rce.php")
    
    for shell in "${shells[@]}"; do
        curl -s -X POST "http://$SERVER:2080/upload" -F "file=@/dev/null" -F "filename=$shell" > /dev/null
        echo -n "."
    done
    
    echo -e "\n${GREEN}✓ Web shell: ${#shells[@]} upload attempts sent${NC}"
    sleep $DELAY
}

# Function to test Credential Stuffing
test_credstuff() {
    echo -e "\n${BLUE}[TEST 9] Credential Stuffing Simulation${NC}"
    
    common_creds=(
        "admin:password"
        "root:password123"
        "user:user123"
        "test:test123"
        "admin:admin123"
    )
    
    for cred in "${common_creds[@]}"; do
        IFS=':' read -r user pass <<< "$cred"
        curl -s -X POST "http://$SERVER:2080/login" -d "username=$user&password=$pass" > /dev/null
        echo -n "."
    done
    
    echo -e "\n${GREEN}✓ Credential stuffing: ${#common_creds[@]} attempts sent${NC}"
    sleep $DELAY
}

# Function to test Load/Stress
test_load() {
    echo -e "\n${BLUE}[TEST 10] Load Test (Concurrent)${NC}"
    
    send_request() {
        curl -s "http://$SERVER:2080/" > /dev/null
        (echo "test"; sleep 0.1; echo "pass"; sleep 0.1) | nc -w 2 $SERVER 2022 2>/dev/null
    }
    
    for i in {1..20}; do
        send_request &
        echo -n "#"
    done
    wait
    
    echo -e "\n${GREEN}✓ Load test: 20 concurrent requests sent${NC}"
}

# Main execution
main() {
    echo -e "${CYAN}Starting attack simulations...${NC}\n"
    
    test_ssh
    test_http
    test_ftp
    test_telnet
    test_smtp
    test_dns
    test_portscan
    test_webshell
    test_credstuff
    test_load
    
    echo -e "\n${CYAN}========================================="
    echo -e "${GREEN}✅ ALL TESTS COMPLETE!${NC}"
    echo -e "${CYAN}=========================================${NC}"
    echo ""
    echo -e "${YELLOW}📊 Check your dashboard:${NC}"
    echo -e "   http://$SERVER:5000"
    echo ""
    echo -e "${YELLOW}📈 Summary of attacks sent:${NC}"
    echo "   - SSH: 15 brute force attempts"
    echo "   - HTTP: SQLi, XSS, Path Traversal, Directory scan"
    echo "   - FTP: 7 credential attempts"
    echo "   - Telnet: 4 login attempts"
    echo "   - SMTP: Open relay test"
    echo "   - DNS: 11 queries (including tunneling)"
    echo "   - Port scan: 10 ports scanned"
    echo "   - Web shell: 5 upload attempts"
    echo "   - Credential stuffing: 5 attempts"
    echo "   - Load test: 20 concurrent requests"
    echo -e "${CYAN}=========================================${NC}"
}

main "$@"
