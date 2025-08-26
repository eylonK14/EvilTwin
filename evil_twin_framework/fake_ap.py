#!/usr/bin/env python3
"""
Fake AP Setup Script - Creates a functional access point with DHCP and DNS
Designed to work with the captive portal script
"""

import subprocess
import sys
import os
import time
import signal
from pathlib import Path

# Global variables for cleanup
hostapd_process = None
dnsmasq_process = None
cleanup_done = False

def run_command(cmd, shell=False, check=True, verbose=False):
    """Run a command and return result"""
    try:
        if verbose:
            print(f"[CMD] {cmd if shell else ' '.join(cmd)}")
        
        if shell:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=check)
        else:
            result = subprocess.run(cmd, capture_output=True, text=True, check=check)
        
        if verbose and result.stdout:
            print(f"[OUT] {result.stdout}")
        
        return result
    except subprocess.CalledProcessError as e:
        if check:
            print(f"[ERROR] Command failed: {' '.join(cmd) if isinstance(cmd, list) else cmd}")
            if e.stderr:
                print(f"[ERROR] {e.stderr}")
        return e

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    print("\n[!] Received interrupt signal...")
    cleanup()
    sys.exit(0)

def cleanup():
    """Clean up everything"""
    global hostapd_process, dnsmasq_process, cleanup_done
    
    if cleanup_done:
        return
    cleanup_done = True
    
    print("\n[*] Starting cleanup...")
    
    # Kill processes
    if hostapd_process:
        print("[*] Stopping hostapd...")
        hostapd_process.terminate()
        try:
            hostapd_process.wait(timeout=2)
        except:
            hostapd_process.kill()
    
    if dnsmasq_process:
        print("[*] Stopping dnsmasq...")
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
    run_command(['sudo', 'iptables', '-P', 'FORWARD', 'ACCEPT'], check=False)
    
    # Disable IP forwarding
    run_command('echo "0" | sudo tee /proc/sys/net/ipv4/ip_forward > /dev/null', shell=True, check=False)
    
    # Clean up interface
    print("[*] Resetting network interface...")
    run_command(['sudo', 'ip', 'addr', 'flush', 'dev', 'wlan0'], check=False)
    run_command(['sudo', 'ip', 'link', 'set', 'wlan0', 'down'], check=False)
    
    # Remove config files
    run_command(['sudo', 'rm', '-f', '/tmp/fake_ap_hostapd.conf'], check=False)
    run_command(['sudo', 'rm', '-f', '/tmp/fake_ap_dnsmasq.conf'], check=False)
    
    # Restart NetworkManager
    print("[*] Restarting NetworkManager...")
    run_command(['sudo', 'systemctl', 'restart', 'NetworkManager'], check=False)
    run_command(['sudo', 'systemctl', 'enable', 'systemd-resolved'], check=False)
    run_command(['sudo', 'systemctl', 'start', 'systemd-resolved'], check=False)
    
    print("[✓] Cleanup complete")

def stop_network_managers():
    """Stop network managers that interfere with AP"""
    print("[*] Stopping network managers...")
    services = ['systemd-resolved', 'NetworkManager', 'wpa_supplicant']
    
    for service in services:
        run_command(['sudo', 'systemctl', 'stop', service], check=False)
    
    run_command(['sudo', 'killall', 'wpa_supplicant'], check=False)
    time.sleep(1)

def setup_ip_forwarding():
    """Enable IP forwarding"""
    print("[*] Enabling IP forwarding...")
    result = run_command('echo "1" | sudo tee /proc/sys/net/ipv4/ip_forward', shell=True)
    
    # Verify it's enabled
    result = run_command(['cat', '/proc/sys/net/ipv4/ip_forward'], check=False)
    if result.stdout.strip() == "1":
        print("[✓] IP forwarding enabled")
    else:
        print("[!] Warning: IP forwarding may not be enabled")

def setup_interface(interface, ip_address):
    """Configure the AP interface with static IP"""
    print(f"[*] Configuring {interface} with IP {ip_address}...")
    
    # Bring interface down first
    run_command(['sudo', 'ip', 'link', 'set', interface, 'down'], check=False)
    time.sleep(0.5)
    
    # Flush any existing addresses
    run_command(['sudo', 'ip', 'addr', 'flush', 'dev', interface], check=False)
    
    # Bring interface up
    run_command(['sudo', 'ip', 'link', 'set', interface, 'up'])
    
    # Add IP address
    run_command(['sudo', 'ip', 'addr', 'add', f'{ip_address}/24', 'dev', interface])
    
    # Verify
    result = run_command(['ip', 'addr', 'show', interface], check=False)
    if ip_address in result.stdout:
        print(f"[✓] Interface {interface} configured with {ip_address}")
    else:
        print(f"[!] Warning: Interface configuration may have failed")

def setup_firewall_rules(ap_interface, internet_interface, ap_ip):
    """Setup firewall rules for captive portal"""
    print("[*] Setting up firewall rules...")
    
    # Clear existing rules first
    run_command(['sudo', 'iptables', '-t', 'nat', '-F'], check=False)
    run_command(['sudo', 'iptables', '-F', 'FORWARD'], check=False)
    
    rules = [
        # Enable NAT/masquerading for internet access (if needed)
        ['sudo', 'iptables', '-t', 'nat', '-A', 'POSTROUTING', '-o', internet_interface, '-j', 'MASQUERADE'],
        
        # Allow DNS queries (port 53)
        ['sudo', 'iptables', '-A', 'FORWARD', '-i', ap_interface, '-p', 'udp', '--dport', '53', '-j', 'ACCEPT'],
        ['sudo', 'iptables', '-A', 'FORWARD', '-i', ap_interface, '-p', 'tcp', '--dport', '53', '-j', 'ACCEPT'],
        
        # Allow DHCP
        ['sudo', 'iptables', '-A', 'FORWARD', '-i', ap_interface, '-p', 'udp', '--dport', '67:68', '-j', 'ACCEPT'],
        
        # Redirect HTTP traffic to captive portal
        ['sudo', 'iptables', '-t', 'nat', '-A', 'PREROUTING', '-i', ap_interface, '-p', 'tcp', '--dport', '80', '-j', 'DNAT', '--to-destination', f'{ap_ip}:80'],
        
        # Allow traffic to captive portal
        ['sudo', 'iptables', '-A', 'FORWARD', '-i', ap_interface, '-p', 'tcp', '--dport', '80', '-d', ap_ip, '-j', 'ACCEPT'],
        
        # Allow established connections
        ['sudo', 'iptables', '-A', 'FORWARD', '-m', 'state', '--state', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'],
        
        # Drop all other forwarded traffic from AP (forces captive portal)
        ['sudo', 'iptables', '-A', 'FORWARD', '-i', ap_interface, '-j', 'DROP'],
        
        # Set default forward policy
        ['sudo', 'iptables', '-P', 'FORWARD', 'DROP']
    ]
    
    success_count = 0
    for rule in rules:
        result = run_command(rule, check=False)
        if result.returncode == 0:
            success_count += 1
    
    print(f"[✓] Applied {success_count}/{len(rules)} firewall rules")

def create_dnsmasq_config(ap_interface, ap_ip, dhcp_start, dhcp_end):
    """Create dnsmasq configuration for DHCP and DNS"""
    
    config = f"""# Fake AP dnsmasq configuration
interface={ap_interface}
bind-interfaces
listen-address={ap_ip}

# DHCP settings
dhcp-range={dhcp_start},{dhcp_end},255.255.255.0,12h
dhcp-option=3,{ap_ip}  # Default gateway
dhcp-option=6,{ap_ip}  # DNS server

# DNS settings - redirect all domains to our captive portal
address=/#/{ap_ip}
no-resolv
no-poll

# Logging (comment out for less verbose output)
log-queries
log-dhcp
"""
    
    config_file = '/tmp/fake_ap_dnsmasq.conf'
    with open(config_file, 'w') as f:
        f.write(config)
    
    return config_file

def create_hostapd_config(interface, ssid, channel):
    """Create hostapd configuration for the access point"""
    
    config = f"""# Fake AP hostapd configuration
interface={interface}
driver=nl80211
ssid={ssid}
hw_mode=g
channel={channel}
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0

# No encryption (open network)
wpa=0

# Logging (comment out for less verbose output)
logger_stdout=-1
logger_stdout_level=2
"""
    
    config_file = '/tmp/fake_ap_hostapd.conf'
    with open(config_file, 'w') as f:
        f.write(config)
    
    return config_file

def start_dnsmasq(config_file):
    """Start dnsmasq daemon"""
    global dnsmasq_process
    
    print("[*] Starting dnsmasq...")
    
    # Kill any existing dnsmasq
    run_command(['sudo', 'killall', 'dnsmasq'], check=False)
    time.sleep(0.5)
    
    dnsmasq_process = subprocess.Popen(
        ['sudo', 'dnsmasq', '-C', config_file, '-d', '--log-facility=-'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    # Check if it started
    time.sleep(1)
    if dnsmasq_process.poll() is None:
        print("[✓] dnsmasq started successfully")
        return True
    else:
        stderr = dnsmasq_process.stderr.read().decode() if dnsmasq_process.stderr else ""
        print(f"[ERROR] dnsmasq failed to start: {stderr}")
        return False

def start_hostapd(config_file):
    """Start hostapd daemon"""
    global hostapd_process
    
    print("[*] Starting hostapd...")
    
    # Kill any existing hostapd
    run_command(['sudo', 'killall', 'hostapd'], check=False)
    time.sleep(0.5)
    
    hostapd_process = subprocess.Popen(
        ['sudo', 'hostapd', config_file],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    # Wait for AP to initialize
    time.sleep(3)
    
    # Check if it's still running
    if hostapd_process.poll() is None:
        print("[✓] hostapd started successfully")
        return True
    else:
        stderr = hostapd_process.stderr.read().decode() if hostapd_process.stderr else ""
        stdout = hostapd_process.stdout.read().decode() if hostapd_process.stdout else ""
        print(f"[ERROR] hostapd failed:")
        if stderr:
            print(f"  STDERR: {stderr}")
        if stdout:
            print(f"  STDOUT: {stdout}")
        return False

def get_internet_interface():
    """Try to detect the internet interface"""
    print("[*] Detecting internet interface...")
    
    # Check default route
    result = run_command(['ip', 'route', 'show', 'default'], check=False)
    if result.returncode == 0:
        for line in result.stdout.split('\n'):
            if 'default' in line:
                parts = line.split()
                for i, part in enumerate(parts):
                    if part == 'dev' and i+1 < len(parts):
                        interface = parts[i+1]
                        print(f"[✓] Found internet interface: {interface}")
                        return interface
    
    # Try common interface names
    common_interfaces = ['eth0', 'eth1', 'enp0s3', 'ens33', 'wlan1']
    for iface in common_interfaces:
        result = run_command(['ip', 'link', 'show', iface], check=False)
        if result.returncode == 0 and 'state UP' in result.stdout:
            print(f"[✓] Found active interface: {iface}")
            return iface
    
    # Default fallback
    print("[!] Could not detect internet interface, using eth0 as default")
    return 'eth0'

def create_fake_ap(ssid="Free WiFi", 
                  channel=6, 
                  ap_interface="wlan0",
                  ap_ip="192.168.0.1",
                  dhcp_start="192.168.0.100",
                  dhcp_end="192.168.0.200",
                  internet_interface=None):
    """
    Create a fake access point
    
    Args:
        ssid: Network name to broadcast
        channel: WiFi channel (1-11)
        ap_interface: Wireless interface to use for AP
        ap_ip: IP address for the AP
        dhcp_start: Start of DHCP range
        dhcp_end: End of DHCP range
        internet_interface: Interface with internet (auto-detect if None)
    """
    
    # Register signal handler
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    print("\n" + "="*60)
    print("  FAKE ACCESS POINT SETUP")
    print("="*60)
    print(f"SSID: {ssid}")
    print(f"Channel: {channel}")
    print(f"AP Interface: {ap_interface}")
    print(f"AP IP: {ap_ip}")
    print(f"DHCP Range: {dhcp_start} - {dhcp_end}")
    print("="*60 + "\n")
    
    # Check if running as root
    if os.geteuid() != 0:
        print("[ERROR] This script must be run as root (use sudo)")
        sys.exit(1)
    
    # Stop network managers
    stop_network_managers()
    
    # Setup interface
    setup_interface(ap_interface, ap_ip)
    
    # Detect internet interface if not specified
    if internet_interface is None:
        internet_interface = get_internet_interface()
    
    print(f"[*] Internet Interface: {internet_interface}")
    
    # Enable IP forwarding
    setup_ip_forwarding()
    
    # Setup firewall rules
    setup_firewall_rules(ap_interface, internet_interface, ap_ip)
    
    # Create configuration files
    dnsmasq_config = create_dnsmasq_config(ap_interface, ap_ip, dhcp_start, dhcp_end)
    hostapd_config = create_hostapd_config(ap_interface, ssid, channel)
    
    # Start services
    if not start_dnsmasq(dnsmasq_config):
        cleanup()
        sys.exit(1)
    
    if not start_hostapd(hostapd_config):
        cleanup()
        sys.exit(1)
    
    print("\n" + "="*60)
    print(f"[✓] FAKE AP '{ssid}' IS RUNNING!")
    print("="*60)
    print("\n[!] IMPORTANT: Now run the captive portal in another terminal:")
    print(f"    sudo python3 captive_portal.py")
    print("\n[*] The captive portal will handle web requests on {ap_ip}:80")
    print("[*] Press Ctrl+C to stop the AP\n")
    
    try:
        # Monitor processes
        while True:
            time.sleep(5)
            
            # Check if processes are still running
            if hostapd_process and hostapd_process.poll() is not None:
                print("\n[ERROR] hostapd stopped unexpectedly")
                break
            
            if dnsmasq_process and dnsmasq_process.poll() is not None:
                print("\n[ERROR] dnsmasq stopped unexpectedly")
                break
                
    except KeyboardInterrupt:
        pass
    
    cleanup()
