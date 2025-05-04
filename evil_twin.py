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
    if pkt.haslayer(Dot11):
        # Identify Access Points from Beacon/ProbeResp frames
        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            bssid = pkt[Dot11].addr3
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



# def get_power_constraint(beacon):
#     power_constraint_elem = beacon.getlayer(Dot11Elt, ID=32)
#     if power_constraint_elem:
#         power_constraint = ord(power_constraint_elem.info)
#         return power_constraint
#     return None

# def parse_beacon_frames(packets):
#     beacon_frames = packets.filter(lambda p: p.haslayer(Dot11Beacon))
#     channel_info = {}
#     for beacon in beacon_frames:
#         ssid = beacon.info.decode('utf-8', 'ignore')
#         bssid = beacon.addr3
#         channel = ord(beacon[Dot11Elt:3].info)
#         power_constraint = get_power_constraint(beacon)
#         if channel not in channel_info:
#             channel_info[channel] = []
#         channel_info[channel].append((ssid, bssid, power_constraint))
#     return channel_info

# def parse_management_frames(packets):
#     management_frames = packets.filter(lambda p: p.haslayer(Dot11) and p.type == 0)
#     frame_info = []
#     for frame in management_frames:
#         if frame.subtype != 8:
#             continue

#         source_mac = frame.addr2
#         destination_mac = frame.addr1
#         frame_info.append((frame_type, source_mac, destination_mac))
#     return frame_info

# def get_frame_type_explanation(frame_type):
#     frame_types = {
#         0: "Association Request",
#         1: "Association Response",
#         2: "Reassociation Request",
#         3: "Reassociation Response",
#         4: "Probe Request",
#         5: "Probe Response",
#         8: "Beacon",
#         9: "ATIM",
#         10: "Disassociation",
#         11: "Authentication",
#         12: "Deauthentication",
#         13: "Action"
#     }
#     return frame_types.get(frame_type, "Unknown")

