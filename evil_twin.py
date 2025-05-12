#!/usr/bin/env python3

from scapy.all import *

interface = 'wlxe84e06afb969'

aps = {}       # BSSID: (SSID, Channel)
stations = {}  # STA MAC: associated BSSID

def get_channel(pkt):
    elt = pkt.getlayer(Dot11Elt)
    while elt:
        if elt.ID == 3:  # DS Parameter Set
            return int.from_bytes(elt.info, byteorder='little')
        elt = elt.payload.getlayer(Dot11Elt)
    return None

def callback(pkt):
    print(pkt.show())
    if pkt.haslayer(Dot11):
        # Identify Access Points from Beacon/ProbeResp frames
        if pkt.haslayer(Dot11Beacon):
            bssid = pkt[Dot11].addr2
            ssid = pkt[Dot11Elt].info.decode(errors='ignore')
            channel = get_channel(pkt)
            if bssid and bssid not in aps:
                aps[bssid] = (ssid, channel)
                print(f"[AP]    BSSID: {bssid}, SSID: {ssid}, Channel: {channel}")

        # Identify Stations from data frames using toDS/fromDS
        if pkt.type == 2:  # Data frame
            to_ds = pkt.FCfield & 0x1 != 0
            from_ds = pkt.FCfield & 0x2 != 0

            if to_ds and not from_ds:
                # Station ➜ AP
                sta_mac = pkt.addr2  # Source = Station
                bssid = pkt.addr1    # Destination = AP
                if sta_mac and bssid and sta_mac not in stations:
                    stations[sta_mac] = bssid
                    print(f"[STA]   Station: {sta_mac}, BSSID: {bssid}")

            elif from_ds and not to_ds:
                # AP ➜ Station (we don’t use this direction for STA discovery here)
                pass

sniff(iface=interface, prn=callback, store=0)