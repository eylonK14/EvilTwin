#!/usr/bin/env python3

def display_networks(networks, clients):
    """Display discovered networks"""
    print("\nDiscovered Networks:")
    print(f"{'Index':<6}{'BSSID':<20}{'SSID':<35}{'Signal':<8}{'Sec':<13}{'Clients':<10}{'Channel'}")
    for idx, (bssid, det) in enumerate(networks.items()):
        count = len(clients[bssid])
        print(f"{idx:<6}{bssid:<20}{det['SSID']:<35}{det['Signal']:<8}{det['Security']:<13}{count:<10}{det['Channel']}")

def display_clients(bssid, clients):
    """Display clients for a specific BSSID"""
    print(f"\nClients for BSSID {bssid}:")
    print(f"{'Index':<6}{'MAC':<20}{'Packets':<10}{'Last Seen'}")
    for idx, (mac, info) in enumerate(clients[bssid].items()):
        print(f"{idx:<6}{mac:<20}{info['pkt_count']:<10}{info['last_seen']}")

def display_selected_ap(info, bssid):
    """Display selected AP information"""
    print(f"\nSelected AP:\n  SSID: {info['SSID']}\n  BSSID: {bssid}\n  Signal: {info['Signal']}\n  Security: {info['Security']}")

def display_selected_client(client_mac, cinfo):
    """Display selected client information"""
    print(f"\nChosen Client:\n  MAC: {client_mac}\n  Packets Seen: {cinfo['pkt_count']}\n  Last Seen: {cinfo['last_seen']}")

def display_final_selection(info, bssid, client_mac, cinfo):
    """Display final selection summary"""
    print("\n--- Selection Complete ---")
    display_selected_ap(info, bssid)
    display_selected_client(client_mac, cinfo)