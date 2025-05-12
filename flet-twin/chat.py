import threading
import time
import os
from collections import defaultdict

from scapy.all import AsyncSniffer, Dot11, Dot11Beacon, Dot11Elt, get_if_list
from flet import (  # pip install flet
    Page,
    ListView,
    Text,
    ElevatedButton,
    Row,
    Column,
    app,
)

# -- Global Data Stores --
networks = {}  # BSSID -> {SSID, Signal, Security}
clients = defaultdict(lambda: defaultdict(lambda: {'last_seen': None, 'pkt_count': 0}))
stop_sniff = threading.Event()
interface = None

# -- Channel Hopper --
def channel_hopper(iface: str, delay: float = 0.5):
    """Continuously hops Wi-Fi channels 1 through 13."""
    while not stop_sniff.is_set():
        for ch in range(1, 14):
            os.system(f"iwconfig {iface} channel {ch} > /dev/null 2>&1")
            time.sleep(delay)

# -- Packet Handler --

def packet_handler(pkt):
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
    # Beacon frames: discover networks
    if pkt.haslayer(Dot11Beacon):
        bssid = pkt[Dot11].addr2
        elt = pkt.getlayer(Dot11Elt)
        ssid = elt.info.decode(errors='ignore') if elt and elt.info else '<Hidden>'
        signal = pkt.dBm_AntSignal if hasattr(pkt, 'dBm_AntSignal') else None
        cap = pkt.sprintf('{Dot11Beacon:%Dot11Beacon.cap%}')
        security = 'Encrypted' if 'privacy' in cap.lower() else 'Open'
        prev = networks.get(bssid)
        # Update only when stronger signal seen or new
        if not prev or (signal is not None and prev['Signal'] is not None and signal > prev['Signal']):
            networks[bssid] = {'SSID': ssid, 'Signal': signal, 'Security': security}
    # Data frames: track clients
    elif pkt.haslayer(Dot11) and pkt.type == 2:
        fcf = pkt.FCfield
        to_ds = bool(fcf & 0x1)
        from_ds = bool(fcf & 0x2)
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

# -- Sniffer Thread Starter --

def start_sniff(iface: str):
    sniffer = AsyncSniffer(iface=iface, prn=packet_handler, store=False)
    sniffer.start()
    # Channel hopper in parallel
    ch_thread = threading.Thread(target=channel_hopper, args=(iface,), daemon=True)
    ch_thread.start()
    # Run until stopped
    try:
        while not stop_sniff.is_set():
            time.sleep(0.5)
    finally:
        sniffer.stop()

# -- Flet UI --

def main(page: Page):
    global interface
    page.title = "Wi-Fi Scanner"
    page.vertical_alignment = "start"
    page.padding = 20

    # Interface selection
    iface_list = get_if_list()
    interface = iface_list[0]

    # Start sniffing and channel hopper
    sniff_thread = threading.Thread(target=start_sniff, args=(interface,), daemon=True)
    sniff_thread.start()

    # UI Controls
    networks_list = ListView(expand=True, spacing=5)
    clients_list = ListView(expand=True, spacing=5)

    def refresh(_):
        networks_list.controls.clear()
        for bssid, det in networks.items():
            text = f"{det['SSID']} [{bssid}]  Clients: {len(clients[bssid])}  Signal: {det['Signal']}  Sec: {det['Security']}"
            def on_click(e, bssid=bssid):
                clients_list.controls.clear()
                for client, info in clients[bssid].items():
                    clients_list.controls.append(
                        Text(f"{client} - Packets: {info['pkt_count']} - Last Seen: {info['last_seen']}")
                    )
                page.update()

            btn = ElevatedButton(text, on_click=on_click)
            networks_list.controls.append(btn)
        page.update()

    # Timer for auto-refresh
    timer = Timer(1, refresh, periodic=True)

    page.add(
        Row(
            [
                Column([Text("Discovered Networks:"), networks_list], expand=True),
                Column([Text("Clients:"), clients_list], expand=True),
            ], expand=True
        ),
        timer
    )

if __name__ == "__main__":
    app(target=main)
