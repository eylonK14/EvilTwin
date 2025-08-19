#!/bin/bash

# Teardown Access Point and Restore System Script
# Usage: ./teardown_ap.sh

echo "[*] Stopping Access Point and restoring system..."

# Stop services
echo "[*] Stopping AP services..."
service hostapd stop 2>/dev/null
service dnsmasq stop 2>/dev/null
killall hostapd 2>/dev/null
killall dnsmasq 2>/dev/null

# Stop any Python HTTP servers on port 80
echo "[*] Stopping web server..."
fuser -k 80/tcp 2>/dev/null

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

# Reset all wireless interfaces
echo "[*] Resetting wireless interfaces..."
for interface in $(ls /sys/class/net | grep -E '^wl'); do
    echo "  - Resetting $interface"
    ip link set $interface down 2>/dev/null
    ip addr flush dev $interface 2>/dev/null
    iw dev $interface set type managed 2>/dev/null
    ip link set $interface up 2>/dev/null
done

# Restart network services
echo "[*] Restarting network services..."
systemctl enable systemd-resolved 2>/dev/null
systemctl start systemd-resolved 2>/dev/null
systemctl enable NetworkManager 2>/dev/null
systemctl start NetworkManager 2>/dev/null
service network-manager start 2>/dev/null
systemctl enable wpa_supplicant 2>/dev/null
systemctl start wpa_supplicant 2>/dev/null

# Clean temporary files
echo "[*] Cleaning temporary files..."
rm -f /tmp/hostapd_runtime.conf 2>/dev/null
rm -f /tmp/dnsmasq_runtime.conf 2>/dev/null
rm -f /tmp/evil_twin* 2>/dev/null
rm -f /tmp/captive* 2>/dev/null

# Wait for services to stabilize
sleep 3

# Restart NetworkManager again to ensure all interfaces are managed
echo "[*] Finalizing network restoration..."
systemctl restart NetworkManager 2>/dev/null

echo "[✓] System restored to normal!"
echo ""
echo "If WiFi is not working properly:"
echo "  1. Try: nmcli radio wifi on"
echo "  2. Or: sudo systemctl restart NetworkManager"
echo "  3. Or reboot the system"