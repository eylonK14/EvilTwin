#!/usr/bin/env python3

from scapy.all import *
import os
import threading
import time

interface = 'wlxe84e06afb969'

aps = {}       # BSSID: (SSID, Channel)
stations = {}  # STA MAC: associated BSSID

def get_channel(pkt):
    elt = pkt.getlayer(Dot11Elt)
    while elt:
        if elt.ID == 3:  # DS Parameter Set (Channel)
            return int.from_bytes(elt.info, byteorder='little')
        elt = elt.payload.getlayer(Dot11Elt)
    return None

def channel_hopper():
    while True:
        for ch in range(1, 14):  # Channels 1-13
            os.system(f"iwconfig {interface} channel {ch}")
            time.sleep(0.5)

def callback(pkt):
    if pkt.haslayer(Dot11):

        # Identify Access Points from Beacon and Probe Response frames
        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            bssid = pkt[Dot11].addr2
            ssid = pkt[Dot11Elt].info.decode(errors='ignore')
            channel = get_channel(pkt)
            if bssid and bssid not in aps:
                aps[bssid] = (ssid, channel)
                print(f"[AP]    BSSID: {bssid}, SSID: {ssid}, Channel: {channel}")

        # Data frames for STA discovery
        if pkt.type == 2:  # Data frame
            to_ds = pkt.FCfield & 0x1 != 0
            from_ds = pkt.FCfield & 0x2 != 0

            if to_ds and not from_ds:
                # STA ➜ AP
                sta_mac = pkt.addr2  # Source = Station
                bssid = pkt.addr1    # Destination = AP
            elif from_ds and not to_ds:
                # AP ➜ STA
                sta_mac = pkt.addr1  # Destination = Station
                bssid = pkt.addr2    # Source = AP
            else:
                return

            if sta_mac and bssid and sta_mac not in stations:
                stations[sta_mac] = bssid
                print(f"[STA]   Station: {sta_mac}, BSSID: {bssid}")

                

# Start channel hopper thread
threading.Thread(target=channel_hopper, daemon=True).start()

# Begin sniffing
sniff(iface=interface, prn=callback, store=0)
