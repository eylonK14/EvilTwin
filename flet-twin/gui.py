import os
import flet
from flet import Page, Column, Row, Text, ElevatedButton, Dropdown, DataTable, DataColumn, DataRow, DataCell, ProgressRing
from scapy.all import AsyncSniffer, Dot11, Dot11Beacon, Dot11Elt, get_if_list
from collections import defaultdict
import threading
import time

# Global data
networks = {}  # BSSID -> {SSID, Signal, Security, Channel}
clients = defaultdict(lambda: defaultdict(lambda: {'last_seen': None, 'pkt_count': 0}))
stop_sniff = threading.Event()
interface = None
selected_bssid = None
sniffer_thread = None

# Channel utilities
def get_channel(pkt):
    elt = pkt.getlayer(Dot11Elt)
    while elt:
        if elt.ID == 3:
            return int.from_bytes(elt.info, byteorder='little')
        elt = elt.payload.getlayer(Dot11Elt)
    return None

def channel_hopper():
    global interface
    while not stop_sniff.is_set():
        for ch in range(1, 14):
            os.system(f"iwconfig {interface} channel {ch}")
            time.sleep(0.5)
            if stop_sniff.is_set():
                break

# Packet handler
def packet_handler(pkt):
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    ch = get_channel(pkt)
    if pkt.haslayer(Dot11Beacon):
        bssid = pkt[Dot11].addr2
        ssid = pkt[Dot11Elt].info.decode(errors='ignore') if pkt[Dot11Elt].info else '<Hidden>'
        signal = getattr(pkt, 'dBm_AntSignal', None)
        cap = pkt.sprintf('{Dot11Beacon:%Dot11Beacon.cap%}')
        security = 'Encrypted' if 'privacy' in cap.lower() else 'Open'
        prev = networks.get(bssid)
        if not prev or (signal is not None and (prev['Signal'] is None or signal > prev['Signal'])):
            networks[bssid] = {'SSID': ssid, 'Signal': signal, 'Security': security, 'Channel': ch}
    elif pkt.haslayer(Dot11) and pkt.type == 2:
        fcf = pkt.FCfield
        to_ds = bool(fcf & 0x1)
        from_ds = bool(fcf & 0x2)
        if to_ds and not from_ds and pkt.addr1:
            bssid, client = pkt.addr1, pkt.addr2
        elif from_ds and not to_ds and pkt.addr2:
            bssid, client = pkt.addr2, pkt.addr1
        else:
            return
        if bssid in networks and client:
            info = clients[bssid][client]
            info['last_seen'] = timestamp
            info['pkt_count'] += 1

# Sniffer thread
def start_sniffer(iface):
    sniffer = AsyncSniffer(iface=iface, prn=packet_handler, store=False)
    sniffer.start()
    threading.Thread(target=channel_hopper, daemon=True).start()
    while not stop_sniff.is_set():
        time.sleep(0.5)
    sniffer.stop()

# Flet GUI
def main(page: Page):
    page.title = "Wi-Fi Sniffer"
    page.padding = 10

    # Interface selector
    iface_dropdown = Dropdown(
        label="Select Interface",
        options=[flet.dropdown.Option(i) for i in get_if_list()]
    )
    start_btn = ElevatedButton(text="Start Sniffing")
    refresh_btn = ElevatedButton(text="Refresh Data")
    stop_btn = ElevatedButton(text="Stop Sniffing")
    status_text = Text(value="Status: Idle")
    loading_indicator = ProgressRing(visible=False)

    # Tables with row selection
    networks_table = DataTable(
        show_checkbox_column=True,
        columns=[
            DataColumn(Text("BSSID")),
            DataColumn(Text("SSID")),
            DataColumn(Text("Signal")),
            DataColumn(Text("Security")),
            DataColumn(Text("Channel")),
            DataColumn(Text("Clients")),
        ]
    )
    clients_table = DataTable(
        columns=[
            DataColumn(Text("Client MAC")),
            DataColumn(Text("Packets")),
            DataColumn(Text("Last Seen")),
        ]
    )

    def update_networks():
        networks_table.rows.clear()
        for bssid, det in networks.items():
            count = len(clients[bssid])
            row = DataRow(
                selected=(bssid == selected_bssid),
                on_select_changed=lambda e, b=bssid: select_network(b),
                cells=[
                    DataCell(Text(bssid)),
                    DataCell(Text(det['SSID'])),
                    DataCell(Text(str(det['Signal']))),
                    DataCell(Text(det['Security'])),
                    DataCell(Text(str(det.get('Channel', '')))),
                    DataCell(Text(str(count))),
                ]
            )
            networks_table.rows.append(row)
        page.update()

    def update_clients():
        clients_table.rows.clear()
        if selected_bssid:
            for mac, info in clients[selected_bssid].items():
                clients_table.rows.append(
                    DataRow(cells=[
                        DataCell(Text(mac)),
                        DataCell(Text(str(info['pkt_count']))),
                        DataCell(Text(info['last_seen'] or "")),
                    ])
                )
        page.update()

    def select_network(bssid):
        global selected_bssid
        selected_bssid = bssid
        update_networks()
        update_clients()
        status_text.value = f"Selected BSSID: {bssid}"
        page.update()

    def on_start(e):
        global interface, sniffer_thread
        iface = iface_dropdown.value
        if not iface:
            status_text.value = "Select an interface first"; page.update(); return
        interface = iface
        loading_indicator.visible = True; status_text.value = "Starting sniffer..."; page.update()
        stop_sniff.clear()
        sniffer_thread = threading.Thread(target=start_sniffer, args=(iface,), daemon=True)
        sniffer_thread.start()
        threading.Thread(target=lambda: (time.sleep(5), finish_start()), daemon=True).start()

    def finish_start():
        loading_indicator.visible = False
        status_text.value = f"Sniffing on {interface}"; page.update()
        update_networks()

    def on_refresh(e):
        loading_indicator.visible = True; page.update()
        threading.Thread(target=lambda: (update_networks(), loading_indicator.__setattr__('visible', False), page.update()), daemon=True).start()

    def on_stop(e):
        stop_sniff.set(); status_text.value = "Stopped"; page.update()

    start_btn.on_click = on_start
    refresh_btn.on_click = on_refresh
    stop_btn.on_click = on_stop

    # Make content scrollable
    content = Column(
        [
            Row([iface_dropdown, start_btn, refresh_btn, stop_btn, loading_indicator]),
            status_text,
            Text("Discovered Networks:"), networks_table,
            Text("Clients for Selected Network:"), clients_table,
        ],
        scroll="auto",
        expand=True,
    )
    page.add(content)

if __name__ == "__main__":
    flet.app(target=main)
