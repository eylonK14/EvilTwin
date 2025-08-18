#!/usr/bin/env python3

import os
import time
import threading
from collections import defaultdict
from scapy.all import AsyncSniffer, Dot11, Dot11Beacon, Dot11Elt, get_if_list

# Global data stores
networks = {}  # BSSID -> {SSID, Signal, Security}
clients = defaultdict(lambda: defaultdict(lambda: {'last_seen': None, 'pkt_count': 0}))
stop_sniff = threading.Event()
sniffer = None

def get_channel(pkt):
    """Extract channel information from packet"""
    elt = pkt.getlayer(Dot11Elt)
    while elt:
        if elt.ID == 3:  # DS Parameter Set (Channel)
            return int.from_bytes(elt.info, byteorder='little')
        elt = elt.payload.getlayer(Dot11Elt)
    return None

def channel_hopper(iface):
    """Hop through WiFi channels"""
    while not stop_sniff.is_set():
        for ch in range(1, 14):  # Channels 1-13
            if stop_sniff.is_set():
                break
            os.system(f"iwconfig {iface} channel {ch}")
            time.sleep(0.5)

def packet_handler(pkt):
    """Handle sniffed packets: update networks and clients info."""
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
    # Beacon frames: discover networks
    if pkt.haslayer(Dot11Beacon):
        bssid = pkt[Dot11].addr2  # BSSID of the AP
        ssid = pkt[Dot11Elt].info.decode(errors='ignore') if pkt[Dot11Elt].info else '<Hidden>'  # SSID
        signal = pkt.dBm_AntSignal if hasattr(pkt, 'dBm_AntSignal') else 'N/A'  # Signal strength
        cap = pkt.sprintf('{Dot11Beacon:%Dot11Beacon.cap%}')
        security = 'Encrypted' if 'privacy' in cap.lower() else 'Open'  # Security type
        channel = get_channel(pkt)
        prev = networks.get(bssid)  # Previous info for this BSSID
        if not prev or (signal != 'N/A' and prev['Signal'] != 'N/A' and signal > prev['Signal']):
            networks[bssid] = {'SSID': ssid, 'Signal': signal, 'Security': security, 'Channel': channel}
    # Data frames: track clients under AP
    elif pkt.haslayer(Dot11) and pkt.type == 2:
        fcf = pkt.FCfield
        to_ds = pkt.FCfield & 0x1 != 0
        from_ds = pkt.FCfield & 0x2 != 0
        
        if to_ds and not from_ds and pkt.addr1:
            bssid, client = pkt.addr1, pkt.addr2
        elif from_ds and not to_ds and pkt.addr2:
            bssid, client = pkt.addr2, pkt.addr1
        else:
            return
        
        # Filter out broadcast/multicast and invalid MACs
        if client and bssid in networks:
            # Skip broadcast
            if client.lower() == "ff:ff:ff:ff:ff:ff":
                return
            # Skip multicast (first bit of first byte is 1)
            if int(client[0:2], 16) & 0x01:
                return
            # Skip your AP's MAC appearing as client
            if client == bssid:
                return
                
            info = clients[bssid][client]
            info['last_seen'] = timestamp
            info['pkt_count'] += 1

def start_sniff(iface):
    """Starts continuous sniffing in background until stop is signaled."""
    global sniffer
    threading.Thread(target=channel_hopper, args=(iface,), daemon=True).start()
    sniffer = AsyncSniffer(iface=iface, prn=packet_handler, store=False)
    sniffer.start()
    try:
        while not stop_sniff.is_set():
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        if sniffer and sniffer.running:
            sniffer.stop()

def stop_sniffing():
    """Stop the sniffing process"""
    global stop_sniff, sniffer
    stop_sniff.set()
    # Give the sniff thread time to stop cleanly
    time.sleep(0.5)
    if sniffer and sniffer.running:
        sniffer.stop()

def select_interface():
    """Let user select network interface"""
    ifaces = get_if_list()
    print("Available interfaces:")
    for idx, iface in enumerate(ifaces):
        print(f"[{idx}] {iface}")
    while True:
        try:
            choice = int(input("Select interface number: "))
            if 0 <= choice < len(ifaces):
                return ifaces[choice]
        except ValueError:
            pass
        print("Invalid selection, try again.")

def get_networks():
    """Get the networks dictionary"""
    return networks

def get_clients():
    """Get the clients dictionary"""
    return clients

def get_network_by_index(idx):
    """Get network BSSID and info by index"""
    if idx < len(networks):
        bssid_list = list(networks.keys())
        bssid = bssid_list[idx]
        return bssid, networks[bssid]
    return None, None

def get_client_by_index(bssid, idx):
    """Get client MAC and info by index"""
    if bssid in clients and idx < len(clients[bssid]):
        client_list = list(clients[bssid].keys())
        client_mac = client_list[idx]
        return client_mac, clients[bssid][client_mac]
    return None, None
