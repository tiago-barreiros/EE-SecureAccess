#!/bin/bash

echo "Setting firewall configuration..."

sudo apt install iptables-persistent

# Flush existing rules
sudo iptables -X
sudo iptables -Z
sudo iptables -F

# Set default policies
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT DROP

# Allow localhost traffic
sudo iptables -A INPUT -i lo -j ACCEPT
sudo iptables -A OUTPUT -o lo -j ACCEPT

# Allow incoming connections from the API server on port 5432 (PostgreSQL)
sudo iptables -A INPUT -p tcp --dport 5432 -s 192.168.1.254 -j ACCEPT
sudo iptables -A OUTPUT -p tcp --sport 5432 -d 192.168.1.254 -j ACCEPT

sudo sh -c 'iptables-save > /etc/iptables/rules.v4'
sudo systemctl enable netfilter-persistent.service