# ARGUS-veil

ARGUS-veil is the ARP MITM execution module for the ARGUS network intelligence framework.
It loads configuration, allows operator target selection from the ARGUS database, starts a
session record, poisons ARP tables for target and gateway, and performs cleanup on exit.

## Components

- `config.py`: loads and validates `config.json`
- `db.py`: reads `devices` and writes `sessions`
- `poisoner.py`: enables forwarding and runs ARP poisoning loop
- `restorer.py`: restores truthful ARP mappings on exit
- `main.py`: orchestrates full lifecycle and cleanup

## Prerequisites

- Linux environment
- Python 3.10+
- Root privileges (raw sockets and `/proc` forwarding writes)
- Database schema already created by argus-recon

## Configuration

Create a local `config.json` (gitignored):

```json
{
  "interface": "eth0",
  "gateway_ip": "192.168.1.1",
  "subnet": "192.168.1.0/24",
  "db_path": "../argus.db"
}
```

## Install

```bash
pip install -r requirements.txt
```

## Run

```bash
sudo python main.py
```

## Notes

- ARP restoration is attempted during shutdown paths to reduce post-run connectivity impact.
- Use only in environments where you have explicit authorization to perform active network testing.
