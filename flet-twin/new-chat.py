import threading, time, os
from collections import defaultdict

from scapy.all import AsyncSniffer, Dot11, Dot11Beacon, Dot11Elt, get_if_list
import flet as ft  # pip install flet

# -- Global Data Stores --
networks = {}  # BSSID -> {SSID, Signal, Security}
clients = defaultdict(lambda: defaultdict(lambda: {'last_seen': None, 'pkt_count': 0}))
stop_sniff = threading.Event()

# -- Channel Hopper --
def channel_hopper(iface: str, delay: float = 0.5):
    while not stop_sniff.is_set():
        for ch in range(1, 14):
            os.system(f"iwconfig {iface} channel {ch} > /dev/null 2>&1")
            time.sleep(delay)

# -- Packet Handler --
def packet_handler(pkt):
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
    if pkt.haslayer(Dot11Beacon):
        bssid = pkt[Dot11].addr2
        elt = pkt.getlayer(Dot11Elt)
        ssid = elt.info.decode(errors='ignore') if elt and elt.info else '<Hidden>'
        signal = getattr(pkt, 'dBm_AntSignal', None)
        cap = pkt.sprintf('{Dot11Beacon:%Dot11Beacon.cap%}')
        security = 'Encrypted' if 'privacy' in cap.lower() else 'Open'
        prev = networks.get(bssid)
        if not prev or (signal is not None and prev['Signal'] is not None and signal > prev['Signal']):
            networks[bssid] = {'SSID': ssid, 'Signal': signal, 'Security': security}
    elif pkt.haslayer(Dot11) and pkt.type == 2:
        fcf = pkt.FCfield
        to_ds, from_ds = bool(fcf & 0x1), bool(fcf & 0x2)
        if to_ds and not from_ds:
            bssid, client = pkt.addr1, pkt.addr2
        elif from_ds and not to_ds:
            bssid, client = pkt.addr2, pkt.addr1
        else:
            return
        if bssid in networks and client:
            info = clients[bssid][client]
            info['last_seen'] = timestamp
            info['pkt_count'] += 1

# -- Start Sniffer + Channel Hopper --
def start_sniff(iface: str):
    sniffer = AsyncSniffer(iface=iface, prn=packet_handler, store=False)
    sniffer.start()
    threading.Thread(target=channel_hopper, args=(iface,), daemon=True).start()
    while not stop_sniff.is_set():
        time.sleep(0.5)
    sniffer.stop()

# -- UI Refresh Thread --
def ui_refresher(page: ft.Page, interval: float = 1.0):
    while not stop_sniff.is_set():
        page.update()
        time.sleep(interval)

# -- Flet App --
def main(page: ft.Page):
    page.title = "Wi-Fi Scanner"
    page.padding = 20

    # Start sniffing
    iface = get_if_list()[0]
    threading.Thread(target=start_sniff, args=(iface,), daemon=True).start()

    # Build UI lists
    networks_list = ft.ListView(expand=True, spacing=5)
    clients_list  = ft.ListView(expand=True, spacing=5)

    def refresh_lists(e=None):
        networks_list.controls.clear()
        for bssid, det in networks.items():
            btn = ft.ElevatedButton(
                text=f"{det['SSID']} [{bssid}]  Clients: {len(clients[bssid])}",
                on_click=lambda e, b=bssid: show_clients(b)
            )
            networks_list.controls.append(btn)
        page.update()

    def show_clients(bssid):
        clients_list.controls.clear()
        for mac, info in clients[bssid].items():
            clients_list.controls.append(
                ft.Text(f"{mac} – pkts: {info['pkt_count']} – last: {info['last_seen']}")
            )
        page.update()

    # Kick off UI refresher thread
    threading.Thread(target=ui_refresher, args=(page,), daemon=True).start()

    # Initial layout
    page.add(
        ft.Row([
            ft.Column([ft.Text("Networks"), networks_list], expand=True),
            ft.Column([ft.Text("Clients"),  clients_list],  expand=True),
        ], expand=True)
    )

ft.app(target=main)

