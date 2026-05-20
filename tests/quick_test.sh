#!/bin/bash

SERVER="${1:-localhost}"
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo "========================================="
echo "Quick Honeypot Connectivity Test"
echo "Target: $SERVER"
echo "========================================="

# Test SSH
echo -n "SSH (port 22): "
timeout 2 nc -zv $SERVER 22 2>&1 | grep -q succeeded && echo -e "${GREEN}✓ OPEN${NC}" || echo -e "${RED}✗ CLOSED${NC}"

# Test HTTP
echo -n "HTTP (port 80): "
timeout 2 nc -zv $SERVER 80 2>&1 | grep -q succeeded && echo -e "${GREEN}✓ OPEN${NC}" || echo -e "${RED}✗ CLOSED${NC}"

# Test HTTPS
echo -n "HTTPS (port 443): "
timeout 2 nc -zv $SERVER 443 2>&1 | grep -q succeeded && echo -e "${GREEN}✓ OPEN${NC}" || echo -e "${RED}✗ CLOSED${NC}"

# Test FTP
echo -n "FTP (port 21): "
timeout 2 nc -zv $SERVER 21 2>&1 | grep -q succeeded && echo -e "${GREEN}✓ OPEN${NC}" || echo -e "${RED}✗ CLOSED${NC}"

# Test Telnet
echo -n "Telnet (port 23): "
timeout 2 nc -zv $SERVER 23 2>&1 | grep -q succeeded && echo -e "${GREEN}✓ OPEN${NC}" || echo -e "${RED}✗ CLOSED${NC}"

# Test SMTP
echo -n "SMTP (port 25): "
timeout 2 nc -zv $SERVER 25 2>&1 | grep -q succeeded && echo -e "${GREEN}✓ OPEN${NC}" || echo -e "${RED}✗ CLOSED${NC}"

# Test DNS
echo -n "DNS (port 53): "
timeout 2 nc -zvu $SERVER 53 2>&1 | grep -q succeeded && echo -e "${GREEN}✓ OPEN${NC}" || echo -e "${RED}✗ CLOSED${NC}"

# Test Dashboard
echo -n "Dashboard (port 5000): "
timeout 2 nc -zv $SERVER 5000 2>&1 | grep -q succeeded && echo -e "${GREEN}✓ OPEN${NC}" || echo -e "${RED}✗ CLOSED${NC}"

echo ""
echo "========================================="
echo "To run full attack simulation:"
echo "  ./attack_simulator.sh $SERVER"
echo "========================================="
