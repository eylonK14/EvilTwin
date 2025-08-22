#!/bin/bash

echo "=== AP CONNECTIVITY DEBUG SCRIPT ==="
echo "Run this while your AP is running and a device is connected"
echo ""

# Get internet interface
INTERNET_IFACE=$(ip route | grep '^default' | grep -o 'dev [^ ]*' | head -1 | cut -d' ' -f2)
echo "Internet interface: $INTERNET_IFACE"

# Check basic connectivity from AP host
echo ""
echo "=== 1. HOST CONNECTIVITY ==="
echo "Testing internet from AP host..."
if ping -c 2 8.8.8.8 >/dev/null 2>&1; then
    echo "✓ AP host can reach internet"
else
    echo "✗ AP host CANNOT reach internet - this is the problem!"
    exit 1
fi

# Check IP forwarding
echo ""
echo "=== 2. IP FORWARDING ==="
forwarding=$(cat /proc/sys/net/ipv4/ip_forward)
echo "IP forwarding: $forwarding"
if [ "$forwarding" != "1" ]; then
    echo "✗ IP forwarding is disabled!"
    echo "Run: echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward"
fi

# Check firewall rules
echo ""
echo "=== 3. FIREWALL RULES ==="
echo "NAT rules:"
if command -v iptables >/dev/null; then
    iptables -t nat -L POSTROUTING -n | grep -E "(MASQUERADE|$INTERNET_IFACE)" || echo "No MASQUERADE rules found"
    echo ""
    echo "FORWARD rules:"
    iptables -L FORWARD -n | grep -E "(ACCEPT|wlan0|$INTERNET_IFACE)" || echo "No FORWARD rules found"
fi

if command -v nft >/dev/null; then
    echo ""
    echo "nftables NAT rules:"
    nft list table nat 2>/dev/null || echo "No nftables NAT table found"
fi

# Check interface configuration
echo ""
echo "=== 4. INTERFACE CONFIGURATION ==="
echo "wlan0 configuration:"
ip addr show wlan0 | grep inet || echo "wlan0 has no IP address!"

echo ""
echo "$INTERNET_IFACE configuration:"
ip addr show $INTERNET_IFACE | grep inet || echo "$INTERNET_IFACE has no IP address!"

# Check if processes are running
echo ""
echo "=== 5. RUNNING PROCESSES ==="
echo "hostapd processes:"
pgrep -f hostapd || echo "No hostapd running"

echo ""
echo "dnsmasq processes:"
pgrep -f dnsmasq || echo "No dnsmasq running"

# Check DHCP leases
echo ""
echo "=== 6. DHCP LEASES ==="
if [ -f /var/lib/dhcp/dhcpd.leases ]; then
    echo "DHCP leases:"
    tail -5 /var/lib/dhcp/dhcpd.leases
elif [ -f /tmp/dhcp.leases ]; then
    echo "DHCP leases:"
    cat /tmp/dhcp.leases
else
    echo "No DHCP lease file found"
fi

# Test packet forwarding manually
echo ""
echo "=== 7. MANUAL CONNECTIVITY TEST ==="
echo "Testing if packets can be forwarded..."

# Check if we can see traffic on interfaces
echo "Checking for traffic on wlan0 (run for 5 seconds):"
timeout 5 tcpdump -i wlan0 -c 5 icmp 2>/dev/null | head -3 || echo "No ICMP traffic seen on wlan0"

echo ""
echo "=== RECOMMENDED FIXES ==="
echo ""

if [ "$forwarding" != "1" ]; then
    echo "1. Enable IP forwarding:"
    echo "   echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward"
    echo ""
fi

echo "2. Clear and reset firewall rules:"
echo "   sudo iptables -t nat -F"
echo "   sudo iptables -F FORWARD"
echo "   sudo iptables -t nat -A POSTROUTING -o $INTERNET_IFACE -j MASQUERADE"
echo "   sudo iptables -A FORWARD -i wlan0 -o $INTERNET_IFACE -j ACCEPT"
echo "   sudo iptables -A FORWARD -i $INTERNET_IFACE -o wlan0 -m state --state RELATED,ESTABLISHED -j ACCEPT"
echo "   sudo iptables -P FORWARD ACCEPT"
echo ""

echo "3. Test connectivity from connected device:"
echo "   From your phone, try to ping 192.168.0.1 (should work)"
echo "   From your phone, try to ping 8.8.8.8 (this is what's probably failing)"
echo ""

echo "4. If still not working, the issue might be:"
echo "   - Your internet interface ($INTERNET_IFACE) doesn't actually have internet"
echo "   - ISP/router is blocking traffic forwarding"
echo "   - Network configuration conflict"