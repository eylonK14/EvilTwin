"""
FakeAP Defense Module

This module provides detection and optional mitigation against Evil Twin
attacks. It mirrors the simple integration surface used in the provided
Evil-Twin implementation so it can be imported as:

    from defense import defense

and called as:

    defense(interface, net, user)

Where:
- interface: wireless interface name used for sniffing and mitigation
- net: a pandas-like row or mapping with keys 'SSID' and 'BSSID'
- user: target client MAC address (str) to watch for deauth events

Dependencies: scapy
"""

import os
import time
import threading
from dataclasses import dataclass
from typing import Callable, Optional, Dict, Any

from scapy.all import AsyncSniffer, sendp
from scapy.layers.dot11 import (
    Dot11,
    Dot11Beacon,
    Dot11Elt,
    Dot11Deauth,
    RadioTap,
)


@dataclass
class DefenseConfig:
    time_window_seconds: int = 2
    deauth_threshold: int = 10
    channel_hop_delay_s: float = 0.5
    search_fake_ap_timeout_s: int = 20
    auto_mitigate: bool = True
    mitigation_duration_s: int = 20
    verbose: bool = True


class _State:
    time_now: int = 0
    reset: bool = False
    stop_threads: bool = False
    num_deauth: int = 0
    fake_ap_bssid: str = ""


class _Network:
    ssid: str = ""
    bssid: str = ""
    user_mac: str = ""


def _log(enabled: bool, msg: str) -> None:
    if enabled:
        print(msg)


def _ticker() -> None:
    while True:
        time.sleep(1)
        _State.time_now += 1
        if _State.stop_threads:
            break


def _change_channel(interface: str, cfg: DefenseConfig) -> None:
    ch = 1
    while True:
        os.system(f"iwconfig {interface} channel {ch}")
        ch = ch % 14 + 1
        time.sleep(cfg.channel_hop_delay_s)
        if _State.stop_threads:
            break


def _on_deauth(packet, cfg: DefenseConfig) -> None:
    # Time window management
    if _State.time_now % cfg.time_window_seconds == 0 and not _State.reset:
        if _State.num_deauth > cfg.deauth_threshold:
            _log(cfg.verbose, "[!] Deauthentication attack detected")
            _State.stop_threads = True
        _State.num_deauth = 0
        _State.reset = True
    if _State.time_now % cfg.time_window_seconds != 0:
        _State.reset = False

    if packet.haslayer(Dot11Deauth):
        frame: Dot11 = packet[Dot11]
        src = str(frame.addr2)
        dst = str(frame.addr1)
        if src == _Network.user_mac or dst == _Network.user_mac:
            _State.num_deauth += 1


def _on_beacon(packet, cfg: DefenseConfig) -> None:
    if not packet.haslayer(Dot11Beacon):
        return
    try:
        ssid = packet[Dot11Elt].info.decode(errors="ignore")
    except Exception:
        return
    bssid = str(packet[Dot11].addr2)
    if ssid == _Network.ssid and bssid != _Network.bssid:
        _State.fake_ap_bssid = bssid
        _State.stop_threads = True


def _sniff(
    interface: str,
    callback: Callable,
    timeout: Optional[int],
    cfg: DefenseConfig,
) -> None:
    hopper = threading.Thread(
        target=_change_channel,
        args=(interface, cfg),
        daemon=True,
    )
    hopper.start()

    _State.stop_threads = False

    sniffer = AsyncSniffer(
        prn=lambda p: callback(p, cfg),
        iface=interface,
        store=False,
        timeout=timeout,
    )
    sniffer.start()

    # Wait until stopped by detection or timeout
    while not _State.stop_threads and (timeout is None or sniffer.running):
        time.sleep(0.2)
        if timeout is not None and not sniffer.running:
            break

    # Only stop explicitly if no timeout was used
    if timeout is None and sniffer.running:
        sniffer.stop()


def _mitigate_fake_ap(
    interface: str,
    rogue_bssid: str,
    duration_s: int,
    verbose: bool,
) -> None:
    _log(verbose, f"[*] Starting mitigation against fake AP {rogue_bssid}")
    end = time.time() + duration_s
    # Broadcast deauth frames appearing to come from the rogue AP
    frame = (
        RadioTap()
        / Dot11(
            addr1="ff:ff:ff:ff:ff:ff",  # broadcast
            addr2=rogue_bssid,           # source = rogue AP
            addr3=rogue_bssid,           # BSSID = rogue AP
        )
        / Dot11Deauth()
    )
    while time.time() < end:
        sendp(frame, iface=interface, count=16, inter=0.02, verbose=0)
        time.sleep(0.1)
    _log(verbose, "[*] Mitigation complete")


defense_doc = (
    "Run Evil Twin defense on the specified interface.\n\n"
    "Args:\n"
    "  interface: Wireless interface for sniffing/mitigation\n"
    "  net: Mapping with keys 'SSID' and 'BSSID' of the legit AP\n"
    "  user: Client MAC to monitor for deauth frames\n"
    "  kwargs: Optional overrides for DefenseConfig fields\n"
)


def defense(interface: str, net: Dict[str, Any], user: str, **kwargs) -> None:
    """%s""" % defense_doc
    cfg_vals = {
        k: kwargs.get(k, getattr(DefenseConfig, k))
        for k in DefenseConfig.__annotations__.keys()
    }
    cfg = DefenseConfig(**cfg_vals)

    # Set network context
    _Network.ssid = (
        str(net["SSID"]) if isinstance(net, dict) else str(net["SSID"])
    )
    _Network.bssid = (
        str(net["BSSID"]) if isinstance(net, dict) else str(net["BSSID"])
    )
    _Network.user_mac = user

    # Reset state
    _State.time_now = 0
    _State.reset = False
    _State.stop_threads = False
    _State.num_deauth = 0
    _State.fake_ap_bssid = ""

    # Start ticker
    ticker = threading.Thread(target=_ticker, daemon=True)
    ticker.start()

    while True:
        # 1) Detect deauth flood against the user
        _log(cfg.verbose, "\n[+] Scanning for deauthentication attacks...")
        _sniff(interface, _on_deauth, timeout=None, cfg=cfg)

        # 2) Search for fake AP advertising the same SSID
        _log(cfg.verbose, "\n[+] Searching for potential fake APs...")
        _sniff(
            interface,
            _on_beacon,
            timeout=cfg.search_fake_ap_timeout_s,
            cfg=cfg,
        )  # noqa: E501

        if _State.fake_ap_bssid:
            _log(
                cfg.verbose,
                (
                    f"[!] Potential Evil Twin detected: "
                    f"{_State.fake_ap_bssid} "
                    f"(SSID={_Network.ssid})"
                ),
            )
            if cfg.auto_mitigate:
                _mitigate_fake_ap(
                    interface,
                    _State.fake_ap_bssid,
                    cfg.mitigation_duration_s,
                    cfg.verbose,
                )
        else:
            _log(
                cfg.verbose,
                "[*] No fake AP found in the given timeout window",
            )

        # Prepare next iteration
        _State.stop_threads = False
        _State.num_deauth = 0
        _State.fake_ap_bssid = ""


__all__ = ["defense", "DefenseConfig"]
