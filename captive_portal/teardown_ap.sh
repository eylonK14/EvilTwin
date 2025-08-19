#!/bin/bash

# Teardown Access Point and Restore System Script
# Usage: ./teardown_ap.sh [interface]

# Optional: specify which interface to reset (default: wlan0)
AP_INTERFACE=${1:-wlan0}

echo "[*] Stopping Access Point and restoring system..."

# Stop services
echo "[*] Stopping AP services..."
killall hostapd 2>/dev/null
killall dnsmasq 2>/dev/null

# Stop any Python HTTP servers on port 80
echo "[*] Stopping web server..."
fuser -k 80/tcp 2>/dev/null

# Small delay to ensure services are stopped
sleep 0.5

# Clear iptables rules
echo "[*] Clearing firewall rules..."
iptables --flush
iptables --table nat --flush
iptables --delete-chain
iptables --table nat --delete-chain
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

# Disable IP forwarding
echo "[*] Disabling IP forwarding..."
echo 0 > /proc/sys/net/ipv4/ip_forward

# Reset ONLY the AP interface (don't touch monitoring interface!)
echo "[*] Resetting AP interface $AP_INTERFACE..."
ip link set $AP_INTERFACE down 2>/dev/null
ip addr flush dev $AP_INTERFACE 2>/dev/null
iw dev $AP_INTERFACE set type managed 2>/dev/null
ip link set $AP_INTERFACE up 2>/dev/null

# Return interface to NetworkManager control
nmcli device set $AP_INTERFACE managed yes 2>/dev/null

# Restart network services
echo "[*] Restarting network services..."
systemctl start systemd-resolved 2>/dev/null
systemctl restart NetworkManager 2>/dev/null

# Clean temporary files
echo "[*] Cleaning temporary files..."
rm -f /tmp/hostapd_runtime.conf 2>/dev/null
rm -f /tmp/dnsmasq_runtime.conf 2>/dev/null

# Wait for services to stabilize
sleep 2

echo "[✓] System restored to normal!"
echo ""
echo "If WiFi is not working properly on $AP_INTERFACE:"
echo "  1. Try: nmcli device set $AP_INTERFACE managed yes"
echo "  2. Or: sudo systemctl restart NetworkManager"
echo "  3. Or: sudo ifconfig $AP_INTERFACE up"
