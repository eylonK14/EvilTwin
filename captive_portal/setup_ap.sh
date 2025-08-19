#!/bin/bash

# Setup Access Point Script
# Usage: ./setup_ap.sh <interface> <ssid> <channel>

INTERFACE=$1
SSID=$2
CHANNEL=$3

if [ -z "$INTERFACE" ] || [ -z "$SSID" ] || [ -z "$CHANNEL" ]; then
    echo "[ERROR] Usage: $0 <interface> <ssid> <channel>"
    exit 1
fi

echo "[*] Setting up AP on $INTERFACE with SSID '$SSID' on channel $CHANNEL"

# Stop channel hopping on monitoring interface first
echo "[*] Stopping any channel hopping..."
pkill -f "iwconfig.*channel" 2>/dev/null

# Only stop NetworkManager's control of the AP interface
echo "[*] Releasing $INTERFACE from NetworkManager..."
nmcli device set $INTERFACE managed no 2>/dev/null

# Stop services that might interfere with AP
echo "[*] Stopping conflicting services..."
systemctl stop systemd-resolved 2>/dev/null
killall wpa_supplicant 2>/dev/null

# Kill any existing AP services
killall hostapd 2>/dev/null
killall dnsmasq 2>/dev/null

# Make sure the AP interface is not in monitor mode
echo "[*] Ensuring $INTERFACE is in managed mode..."
iw dev $INTERFACE set type managed 2>/dev/null

# Configure ONLY the AP interface (don't touch other interfaces!)
echo "[*] Configuring interface $INTERFACE..."
ip link set $INTERFACE down
ip addr flush dev $INTERFACE
ip link set $INTERFACE up
ip addr add 10.0.0.1/24 dev $INTERFACE

# Enable IP forwarding
echo "[*] Enabling IP forwarding..."
echo 1 > /proc/sys/net/ipv4/ip_forward

# Clear and setup iptables
echo "[*] Setting up firewall rules..."
iptables --flush
iptables --table nat --flush
iptables --delete-chain
iptables --table nat --delete-chain
iptables -P FORWARD ACCEPT

# Add NAT rules for captive portal
iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination 10.0.0.1:80
iptables -t nat -A PREROUTING -p tcp --dport 443 -j DNAT --to-destination 10.0.0.1:80
iptables -t nat -A POSTROUTING -j MASQUERADE

# Create temporary config files with actual values
echo "[*] Creating configuration files..."

# Create hostapd config
cat > /tmp/hostapd_runtime.conf << EOF
interface=$INTERFACE
driver=nl80211
ssid=$SSID
hw_mode=g
channel=$CHANNEL
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
EOF

# Create dnsmasq config
cat > /tmp/dnsmasq_runtime.conf << EOF
interface=$INTERFACE
dhcp-range=10.0.0.10,10.0.0.250,12h
dhcp-option=3,10.0.0.1
dhcp-option=6,10.0.0.1
server=8.8.8.8
log-queries
listen-address=10.0.0.1
address=/#/10.0.0.1
EOF

# Kill anything on port 53 that might conflict
fuser -k 53/udp 2>/dev/null
sleep 0.5

# Start DHCP and DNS server
echo "[*] Starting DHCP/DNS server..."
dnsmasq -C /tmp/dnsmasq_runtime.conf &
DNSMASQ_PID=$!

# Small delay to ensure dnsmasq is ready
sleep 1

# Check if dnsmasq started successfully
if ! kill -0 $DNSMASQ_PID 2>/dev/null; then
    echo "[ERROR] Failed to start dnsmasq"
    exit 1
fi

# Start hostapd in background
echo "[*] Starting hostapd..."
hostapd /tmp/hostapd_runtime.conf -B &
HOSTAPD_PID=$!

# Wait for hostapd to initialize
sleep 2

# Check if hostapd started successfully
if ! pgrep hostapd > /dev/null; then
    echo "[ERROR] Failed to start hostapd"
    kill $DNSMASQ_PID 2>/dev/null
    exit 1
fi

echo "[✓] Access Point setup complete!"
echo "[*] AP '$SSID' is broadcasting on $INTERFACE"
echo "[*] DHCP server running with PID $DNSMASQ_PID"
