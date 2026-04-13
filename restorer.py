# After ARP poisoning, target and gateway can retain forged MAC mappings in cache.
# Restoration sends truthful ARP replies so both hosts relearn real IP-to-MAC pairs
# before normal cache expiration. Without this cleanup, target connectivity may be
# degraded for minutes after attack traffic stops.

import time

from scapy.all import ARP, Ether, sendp


def restore_arp(
    interface: str,
    gateway_ip: str,
    gateway_mac: str,
    target_ip: str,
    target_mac: str,
    count: int = 5,
) -> None:
    packet_to_target = Ether(dst=target_mac) / ARP(
        op=2,
        pdst=target_ip,
        hwdst=target_mac,
        psrc=gateway_ip,
        hwsrc=gateway_mac,
    )
    packet_to_gateway = Ether(dst=gateway_mac) / ARP(
        op=2,
        pdst=gateway_ip,
        hwdst=gateway_mac,
        psrc=target_ip,
        hwsrc=target_mac,
    )

    print("Restoring ARP tables...")
    for _ in range(count):
        sendp(packet_to_target, iface=interface, verbose=0)
        sendp(packet_to_gateway, iface=interface, verbose=0)
        time.sleep(0.5)
    print("ARP tables restored.")