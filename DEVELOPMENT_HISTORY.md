# Development History

## Bugs And Fixes

### Cleanup skipped when target selection was interrupted

- **Root cause:** The target-selection loop originally ran before the `try`/`finally` block. Pressing Ctrl+C at the selection prompt therefore bypassed all cleanup logic.
- **Fix:** Target selection was moved inside the `try` block. `target`, `gateway_mac`, and `session_id` are initialized to `None` before it, and the `finally` block now guards restoration and session-ending calls using those values.
- **Result:** The same interrupt handler covers both target selection and the poison loop, while forwarding shutdown still runs through `finally`.

### Database path validation needed to distinguish allowed and unsafe traversal

- **Root cause:** The database path needed to accept a sibling-level path such as `../argus.db` while rejecting deeper traversal such as `../../anything`.
- **Fix:** Resolution uses the module directory as the base and checks the normalized path against `os.path.dirname(base)` using a prefix check, rather than `os.path.commonpath()`. The database must also end in `.db` and already exist.

### Ambiguous invalid database input

- **Root cause:** Non-string or empty database paths could otherwise fail inside path-joining code with a low-level `TypeError`.
- **Fix:** An explicit validation guard raises `RuntimeError` with a clear message before path joining.

## Design Decisions

### Cleanup is centralized in `main.py`

ARP restoration, forwarding disablement, and session closure were deliberately placed in `finally` so they run after normal interruption and handled exceptions. Restoration is attempted only when both a selected target and gateway MAC are available; session closure is attempted only after a session was successfully started.

### The existing argus-recon database owns schema

The veil module reads the `devices` table and writes `sessions`, but never creates or migrates tables. This keeps schema ownership in argus-recon and avoids silently creating an incompatible database.

### Database connections are short-lived

Each database operation opens and closes its own SQLite connection. No persistent connection or ORM was introduced, keeping lifecycle and failure behavior local to each operation.

### Configuration is external and local

`config.json` is loaded relative to the module location and is gitignored because it contains environment-specific values. The loader validates the four required keys rather than embedding interface, gateway, subnet, or database values in code.

### Scapy is used directly for packet operations

The networking modules use Scapy's ARP, Ether, `sendp`, `srp`, and interface-MAC helpers directly. No additional networking abstraction or dependency was introduced because the requested behavior is raw Ethernet/ARP packet work.

### Forwarding failures are warnings, not immediate exceptions

The forwarding helpers catch `IOError` and print warnings so the orchestrator can retain control of overall exit handling. Other restoration failures are allowed to propagate from `restorer.py`, with `main.py` deciding how to report them during cleanup.

### Root execution is checked at startup

The program requires root for Scapy raw sockets and `/proc/sys/net/ipv4/ip_forward`. It exits before presenting the target menu when not running as root.

### Target selection remains synchronous and CLI-only

The module deliberately uses a numbered prompt with retry-on-invalid-input. No argparse flags, web UI, threads, or asynchronous workflow were added.

### Poison verification is one-time

ARP-cache verification was added after the first poison cycle, not on every loop iteration. A boolean records that the check has been performed and stores its result, avoiding repeated network probes and repeated status output during a long-running attack.

### Documentation and local artifacts

A README was added for setup and operational context. Local configuration, database files, packet captures, logs, virtual environments, Python caches, and common editor/runtime artifacts were added or retained in `.gitignore`. Requirements were kept to Scapy only, with a minimum version of `2.5.0`.

## College Network Test Results

No college-network test results are recorded in the available ARGUS-veil conversation history.

The indexed history contains separate ARGUS-recon and ARGUS-oracle summary sessions, but they are different repositories and do not provide verified ARGUS-veil outcomes. No claims about connectivity, DAI behavior, interface selection, or gateway behavior are therefore carried over into this document.

## ARP Cache Verification

### Why it was added

The verification step was added to determine whether the first forged ARP reply actually changed the target's view of the gateway. This provides an immediate signal that poisoning succeeded or that a control such as Dynamic ARP Inspection may be preventing it.

### What it confirms

The check sends an ARP request for the gateway on the selected interface, reads the target's reported gateway MAC, and compares it with the local attacker-interface MAC.

- A match means the target is reporting the attacker's MAC for the gateway, so poisoning is confirmed.
- A different MAC means the target's ARP cache was not changed to the attacker mapping; the output identifies DAI as a possible cause.
- No usable response means the target may be offline or not responding to ARP.

### Testing evidence

No actual verification output or college-network test result is present in the available ARGUS-veil history. The three output cases above are the intended interpretation of the feature, not a report of observed field results.

## Known Limitations And Important Context

- The available conversation does not document an end-to-end college-network run, so real-world reliability is unverified here.
- ARP poisoning depends on the target and gateway accepting unsolicited ARP replies; network protections such as DAI may prevent the mapping change.
- Restoration depends on having a valid gateway MAC. If gateway resolution fails before cleanup, the restoration step cannot be performed.
- The program assumes the database schema and records were prepared by argus-recon.
- `config.json` and database files are intentionally local and ignored by Git; another environment must provide its own valid configuration and database.
- The process is synchronous and interactive, and requires root privileges.
- The retained history records no rejected feature proposals or alternative implementations beyond the decisions described above.
