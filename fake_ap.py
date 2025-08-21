#!/usr/bin/env python3
"""
Fake AP with Connectivity Check Support
This version handles connectivity checks from Windows, Android, iOS, etc.
to show proper "connected" status instead of "no internet" warning
"""

import subprocess
import sys
import os
import time
import signal
import argparse
import threading
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler

# Global variables
hostapd_process = None
dnsmasq_process = None
connectivity_server = None
cleanup_done = False

class ConnectivityCheckHandler(BaseHTTPRequestHandler):
    """Handle connectivity check requests from various devices"""
    
    def log_message(self, format, *args):
        """Suppress HTTP server logs"""
        pass
    
    def do_GET(self):
        """Handle GET requests for connectivity checks"""
        
        # Windows connectivity check
        if self.path == '/connecttest.txt' or self.path == '/ncsi.txt':
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'Microsoft NCSI')
            return
        
        # Android connectivity checks
        if 'generate_204' in self.path or 'gen_204' in self.path:
            self.send_response(204)
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        
        # Apple/iOS connectivity check
        if self.path == '/hotspot-detect.html' or 'captive.apple.com' in self.headers.get('Host', ''):
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(b'<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>')
            return
        
        # Firefox connectivity check
        if 'detectportal.firefox.com' in self.headers.get('Host', ''):
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'success')
            return
        
        # Default response
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(b'<html><body><h1>Connected</h1></body></html>')
    
    def do_POST(self):
        """Handle POST requests"""
        self.do_GET()

def run_command(cmd, shell=False, check=True):
    """Run a command and return result"""
    try:
        if shell:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=check)
        else:
            result = subprocess.run(cmd, capture_output=True, text=True, check=check)
        return result
    except subprocess.CalledProcessError as e:
        if check:
            print(f"[ERROR] Command failed: {' '.join(cmd) if isinstance(cmd, list) else cmd}")
            print(f"[ERROR] {e.stderr}")
        return e

def start_connectivity_server(ap_ip):
    """Start HTTP server to handle connectivity checks"""
    global connectivity_server
    
    def run_server():
        global connectivity_server
        try:
            server_address = (ap_ip, 80)
            connectivity_server = HTTPServer(server_address, ConnectivityCheckHandler)
            print(f"[✓] Connectivity check server started on {ap_ip}:80")
            connectivity_server.serve_forever()
        except Exception as e:
            print(f"[WARNING] Could not start connectivity server: {e}")
    
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()
    time.sleep(1)

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    print("\n[!] Shutting down fake AP...")
    cleanup()
    sys.exit(0)

def cleanup():
    """Clean up everything"""
    global hostapd_process, dnsmasq_process, connectivity_server, cleanup_done
    
    if cleanup_done:
        return
    cleanup_done = True
    
    print("\n[*] Cleaning up...")
    
    # Stop connectivity server
    if connectivity_server:
        connectivity_server.shutdown()
    
    # Kill processes
    if hostapd_process:
        hostapd_process.terminate()
        try:
            hostapd_process.wait(timeout=2)
        except:
            hostapd_process.kill()
    
    if dnsmasq_process:
        dnsmasq_process.terminate()
        try:
            dnsmasq_process.wait(timeout=2)
        except:
            dnsmasq_process.kill()
    
    # Kill any remaining processes
    run_command(['sudo', 'killall', 'hostapd'], check=False)
    run_command(['sudo', 'killall', 'dnsmasq'], check=False)
    
    # Clear firewall rules
    print("[*] Removing firewall rules...")
    run_command(['sudo', 'iptables', '-t', 'nat', '-F'], check=False)
    run_command(['sudo', 'iptables', '-F', 'FORWARD'], check=False)
    
    # Disable IP forwarding
    run_command('echo "0" | sudo tee /proc/sys/net/ipv4/ip_forward > /dev/null', shell=True, check=False)
    
    # Clean up interface
    run_command(['sudo', 'ip', 'addr', 'flush', 'dev', 'wlan0'], check=False)
    run_command(['sudo', 'ip', 'link', 'set', 'wlan0', 'down'], check=False)
    
    # Restart NetworkManager
    print("[*] Restarting NetworkManager...")
    run_command(['sudo', 'systemctl', 'restart', 'NetworkManager'], check=False)
    run_command(['sudo', 'systemctl', 'enable', 'systemd-resolved'], check=False)
    run_command(['sudo', 'systemctl', 'start', 'systemd-resolved'], check=False)
    
    print("[✓] Cleanup complete")

def check_ap_support(interface='wlan0'):
    """Check if interface supports AP mode"""
    print(f"[*] Checking if {interface} supports AP mode...")
    
    # Get PHY interface
    result = run_command(['sudo', 'airmon-ng'], check=False)
    if result.returncode != 0:
        print("[WARNING] airmon-ng not found, skipping AP mode check")
        return True
    
    # Parse PHY from output
    phy = None
    for line in result.stdout.split('\n'):
        if interface in line:
            parts = line.split()
            if len(parts) > 0:
                phy = parts[0]
                break
    
    if not phy:
        print(f"[WARNING] Could not find PHY for {interface}")
        return True
    
    # Check supported modes
    result = run_command(['sudo', 'iw', phy, 'info'], check=False)
    if 'AP' in result.stdout:
        print(f"[✓] {interface} supports AP mode")
        return True
    else:
        print(f"[ERROR] {interface} does not support AP mode")
        return False

def stop_network_managers():
    """Stop network managers that interfere with AP"""
    print("[*] Stopping network managers...")
    run_command(['sudo', 'systemctl', 'disable', 'systemd-resolved'], check=False)
    run_command(['sudo', 'systemctl', 'stop', 'systemd-resolved'], check=False)
    run_command(['sudo', 'systemctl', 'stop', 'NetworkManager'], check=False)
    run_command(['sudo', 'systemctl', 'stop', 'wpa_supplicant'], check=False)
    run_command(['sudo', 'killall', 'wpa_supplicant'], check=False)
    time.sleep(1)

def setup_ip_forwarding():
    """Enable IP forwarding"""
    print("[*] Enabling IP forwarding...")
    run_command('echo "1" | sudo tee /proc/sys/net/ipv4/ip_forward > /dev/null', shell=True)
    run_command(['sudo', 'sysctl', '-w', 'net.ipv4.ip_forward=1'], check=False)

def setup_interface(interface, ip_address):
    """Configure the AP interface with static IP"""
    print(f"[*] Configuring {interface} with IP {ip_address}...")
    run_command(['sudo', 'ip', 'link', 'set', interface, 'up'])
    run_command(['sudo', 'ip', 'addr', 'flush', 'dev', interface])
    run_command(['sudo', 'ip', 'addr', 'add', f'{ip_address}/24', 'dev', interface])

def setup_firewall_with_redirects(ap_interface, internet_interface, ap_ip):
    """Setup firewall rules with connectivity check redirects"""
    print("[*] Setting up firewall rules with connectivity check support...")
    
    # Clear existing rules
    run_command(['sudo', 'iptables', '-F'], check=False)
    run_command(['sudo', 'iptables', '-t', 'nat', '-F'], check=False)
    run_command(['sudo', 'iptables', '-t', 'mangle', '-F'], check=False)
    
    # Basic NAT for internet sharing
    run_command(['sudo', 'iptables', '-t', 'nat', '-A', 'POSTROUTING', 
                 '-o', internet_interface, '-j', 'MASQUERADE'], check=False)
    
    # Forward traffic
    run_command(['sudo', 'iptables', '-A', 'FORWARD', '-i', ap_interface, 
                 '-o', internet_interface, '-j', 'ACCEPT'], check=False)
    run_command(['sudo', 'iptables', '-A', 'FORWARD', '-i', internet_interface, 
                 '-o', ap_interface, '-m', 'state', '--state', 'ESTABLISHED,RELATED', 
                 '-j', 'ACCEPT'], check=False)
    
    # Redirect connectivity check domains to our server (port 80)
    connectivity_domains = [
        'connectivitycheck.gstatic.com',
        'connectivitycheck.android.com',
        'clients3.google.com',
        'captive.apple.com',
        'www.msftconnecttest.com',
        'www.msftncsi.com',
        'detectportal.firefox.com'
    ]
    
    # Add iptables rules to redirect connectivity checks to our local server
    for domain in connectivity_domains:
        # This would need DNS spoofing, so we'll handle it in dnsmasq instead
        pass
    
    print("[✓] Firewall rules configured")

def create_dnsmasq_config(ip_address, dns_server='8.8.8.8'):
    """Create dnsmasq configuration with connectivity check support"""
    network = '.'.join(ip_address.split('.')[:-1])
    
    config = f"""# Basic configuration
interface=wlan0
bind-interfaces
listen-address={ip_address}

# DHCP settings
dhcp-range={network}.50,{network}.150,12h
dhcp-option=3,{ip_address}
dhcp-option=6,{ip_address},{dns_server}

# DNS settings
server={dns_server}
server=8.8.4.4
no-resolv

# Connectivity check redirects
address=/connectivitycheck.gstatic.com/{ip_address}
address=/connectivitycheck.android.com/{ip_address}
address=/clients3.google.com/{ip_address}
address=/captive.apple.com/{ip_address}
address=/www.msftconnecttest.com/{ip_address}
address=/www.msftncsi.com/{ip_address}
address=/detectportal.firefox.com/{ip_address}
address=/www.google.com/142.250.185.46

# General settings
domain-needed
bogus-priv
no-hosts
expand-hosts
log-queries
log-facility=/tmp/dnsmasq.log
"""
    
    config_file = '/tmp/fake_ap_dnsmasq.conf'
    with open(config_file, 'w') as f:
        f.write(config)
    
    return config_file

def create_hostapd_config(interface, ssid, channel, password=None):
    """Create hostapd configuration"""
    
    config = f"""interface={interface}
driver=nl80211
ssid={ssid}
hw_mode=g
channel={channel}
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wmm_enabled=1
ieee80211n=1
"""
    
    if password:
        config += f"""wpa=2
wpa_passphrase={password}
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
"""
    
    config_file = '/tmp/fake_ap_hostapd.conf'
    with open(config_file, 'w') as f:
        f.write(config)
    
    return config_file

def start_dnsmasq(config_file):
    """Start dnsmasq"""
    global dnsmasq_process
    
    print("[*] Starting dnsmasq...")
    
    # Kill any existing dnsmasq
    run_command(['sudo', 'killall', 'dnsmasq'], check=False)
    time.sleep(1)
    
    dnsmasq_process = subprocess.Popen(
        ['sudo', 'dnsmasq', '-C', config_file, '-d'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    # Check if it started
    time.sleep(2)
    if dnsmasq_process.poll() is None:
        print("[✓] dnsmasq started successfully")
        return True
    else:
        stderr = dnsmasq_process.stderr.read().decode()
        print(f"[ERROR] dnsmasq failed to start: {stderr}")
        return False

def start_hostapd(config_file):
    """Start hostapd"""
    global hostapd_process
    
    print("[*] Starting hostapd...")
    hostapd_process = subprocess.Popen(
        ['sudo', 'hostapd', config_file],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    # Wait for AP to be enabled
    time.sleep(3)
    
    # Check output for success
    if hostapd_process.poll() is None:
        print("[✓] hostapd started successfully")
        return True
    else:
        stderr = hostapd_process.stderr.read().decode()
        print(f"[ERROR] hostapd failed: {stderr}")
        return False

def get_internet_interface():
    """Try to detect the internet interface"""
    # Check default route
    result = run_command(['ip', 'route', 'show', 'default'], check=False)
    if result.returncode == 0:
        for line in result.stdout.split('\n'):
            if 'default' in line:
                parts = line.split()
                for i, part in enumerate(parts):
                    if part == 'dev' and i+1 < len(parts):
                        return parts[i+1]
    
    # Fallback to common interfaces
    for iface in ['eth0', 'enp0s3', 'ens33', 'wlan1']:
        result = run_command(['ip', 'link', 'show', iface], check=False)
        if result.returncode == 0:
            return iface
    
    return 'eth0'  # Default fallback

def main():
    parser = argparse.ArgumentParser(description='Set up a fake WiFi access point with proper connectivity detection')
    parser.add_argument('--ssid', '-s', default='FreeWiFi', help='SSID to broadcast (default: FreeWiFi)')
    parser.add_argument('--channel', '-c', type=int, default=6, help='WiFi channel 1-11 (default: 6)')
    parser.add_argument('--password', '-p', help='WPA2 password (leave empty for open network)')
    parser.add_argument('--ap-interface', '-a', default='wlan0', help='AP interface (default: wlan0)')
    parser.add_argument('--internet-interface', '-i', help='Internet interface (auto-detect if not specified)')
    parser.add_argument('--ap-ip', default='192.168.1.1', help='AP IP address (default: 192.168.1.1)')
    parser.add_argument('--no-internet', action='store_true', help='Create AP without Internet sharing')
    
    args = parser.parse_args()
    
    # Check if running as root
    if os.geteuid() != 0:
        print("[ERROR] This script must be run as root (use sudo)")
        sys.exit(1)
    
    # Register signal handler
    signal.signal(signal.SIGINT, signal_handler)
    
    print(f"\n{'='*60}")
    print(f"  FAKE AP WITH CONNECTIVITY CHECK SUPPORT")
    print(f"{'='*60}")
    print(f"SSID: {args.ssid}")
    print(f"Channel: {args.channel}")
    print(f"Security: {'WPA2' if args.password else 'Open'}")
    print(f"AP Interface: {args.ap_interface}")
    
    # Check AP support
    if not check_ap_support(args.ap_interface):
        print("[ERROR] Interface does not support AP mode")
        sys.exit(1)
    
    # Stop network managers
    stop_network_managers()
    
    # Setup interface
    setup_interface(args.ap_interface, args.ap_ip)
    
    # Start connectivity check server FIRST
    print("[*] Starting connectivity check handler...")
    start_connectivity_server(args.ap_ip)
    
    # Setup Internet sharing if requested
    if not args.no_internet:
        # Detect internet interface
        if not args.internet_interface:
            args.internet_interface = get_internet_interface()
        
        print(f"Internet Interface: {args.internet_interface}")
        
        # Enable IP forwarding
        setup_ip_forwarding()
        
        # Setup firewall with redirects
        setup_firewall_with_redirects(args.ap_interface, args.internet_interface, args.ap_ip)
        
        # Ensure internet interface has connectivity
        print(f"[*] Ensuring {args.internet_interface} has connectivity...")
        run_command(['sudo', 'dhclient', args.internet_interface], check=False)
    
    # Create configs
    dnsmasq_config = create_dnsmasq_config(args.ap_ip)
    hostapd_config = create_hostapd_config(args.ap_interface, args.ssid, args.channel, args.password)
    
    # Start services
    if not start_dnsmasq(dnsmasq_config):
        cleanup()
        sys.exit(1)
    
    if not start_hostapd(hostapd_config):
        cleanup()
        sys.exit(1)
    
    print(f"\n{'='*60}")
    print(f"[✓] FAKE AP '{args.ssid}' IS RUNNING!")
    print(f"{'='*60}")
    print(f"IP Range: {'.'.join(args.ap_ip.split('.')[:-1])}.50-150")
    print(f"DNS Server: {args.ap_ip} -> 8.8.8.8")
    print(f"Connectivity Check: Enabled (devices will show 'connected')")
    if not args.no_internet:
        print(f"Internet: Shared from {args.internet_interface}")
    print("\n[*] The AP will now show as 'Connected' on devices!")
    print("[*] Monitor logs: tail -f /tmp/dnsmasq.log")
    print("[*] Press Ctrl+C to stop\n")
    
    try:
        # Keep running and show some output
        while True:
            time.sleep(5)
            # Check if processes are still running
            if hostapd_process.poll() is not None:
                print("\n[ERROR] hostapd stopped unexpectedly")
                break
            if dnsmasq_process.poll() is not None:
                print("\n[ERROR] dnsmasq stopped unexpectedly")
                break
    except KeyboardInterrupt:
        pass
    
    cleanup()

if __name__ == '__main__':
    main()
