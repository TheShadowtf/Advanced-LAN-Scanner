<<<<<<< HEAD
# Advanced LAN Scanner — README

**Short description**
I built this because Advanced IP Scanner (AIS) stopped opening on my laptop, so I wrote my own LAN scanner with a focus on discoverability and extensibility. It’s a lightweight, open-source scanner that combines ping/ARP, UPnP/SSDP, mDNS, SNMP, banner probing and optional nmap for richer device/service fingerprinting. This repo is intended to be extended — see the long TODO/roadmap below.

---

# Table of contents

* [What this does today](#what-this-does-today)
* [What it does NOT (yet) / Roadmap (everything to reach AIS parity)](#what-it-does-not-yet--roadmap-everything-to-reach-ais-parity)
* [Quickstart / Dependencies](#quickstart--dependencies)
* [Files & where to implement new features](#files--where-to-implement-new-features)
* [Usage examples](#usage-examples)
* [Embedded browser (pywebview) helper note](#embedded-browser-pywebview-helper-note)
* [Router Wi-Fi / nearby network scanning note](#router-wi-fi--nearby-network-scanning-note)
* [Security, privacy & legal note](#security-privacy--legal-note)
* [Tests & QA checklist](#tests--qa-checklist)
* [How you can contribute / next steps](#how-you-can-contribute--next-steps)
* [License](#license)

---

# What this does today

(Features already implemented in the repository you shared)

* Concurrent ping sweep + ARP table read to find live hosts on targets.
* Flexible target input: CIDR, ranges, wildcards, file lists (`utils.expand_targets`).
* MAC address extraction from ARP and local/online OUI vendor lookup with caching (`utils.get_mac_vendor`).
* Reverse DNS and NetBIOS fallbacks for hostnames.
* SSDP/UPnP discovery (`ssdp_search`) and fetching/parsing UPnP device-description XML (basic implementation).
* mDNS/zeroconf scanning (optional, if `zeroconf` installed).
* Optional SNMP sysName/sysDescr probing (if `pysnmp` is installed and enabled).
* Banner probing on common TCP ports (HTTP title parsing, SSH banner, simple server header parsing).
* UDP probes for NBNS, SNMP, SSDP/mDNS supplemental information.
* Simple heuristics to guess device type (Router, Printer, IP Camera, Server/Host, etc.).
* Optional on-demand nmap scan per-host (`nmap_scan_target`) — requires `nmap` in PATH.
* Tkinter GUI with:

  * Targets entry, Workers spinner, checkboxes for options.
  * Filter field, progress bar and status.
  * Treeview with columns (ip, hostname, mac, vendor) — grouping support and live updates.
  * Right-click context menu: Copy IP, Open HTTP, Embedded browser helper, Open SSH, Nmap scan, Export CSV.
  * SSH launcher that attempts to open platform terminals and keep the session open.
* Wi-Fi nearby scan helper that probes local wireless (OS-dependent commands) and injects results into the UI as “Wi-Fi Network” items (optional / experimental).
* Basic CSV export and JSON-like details popup.

---

# What it does NOT yet (complete list of everything to add to reach AIS parity)

Below is a comprehensive, exhaustive blueprint of everything you could add to reach parity with or exceed Advanced IP Scanner (AIS). Items are grouped and annotated with short notes so you can triage.

## MUST / High-ROI (do these first)

1. **Stable Tree/grouping fixes** — clear `_group_items` on new scan; use stable `group:<slug>` ids and guard `tree.exists()` before moves. (`gui.py`)
2. **UPnP: robust XML fetch & parser** — extract `manufacturer`, `modelName`, `friendlyName`. (`scanner_core.py`)
3. **mDNS improvements** — decode properties, handle updates and remove events. (`scanner_core.py`)
4. **SNMP improvements** — allow multiple community strings (GUI input), collect `sysName`, `sysDescr`, `sysObjectID`. (`scanner_core.py`)
5. **HTTP targeted endpoints** — probe common admin endpoints `/status`, `/info`, `/deviceinfo`, etc., parse JSON/XML for product strings. (`scanner_core.py`)
6. **UPnP precedence** — prefer UPnP > SNMP > mDNS > HTTP > NetBIOS > banner > OUI for product/manufacturer fields. (`scanner_core.py`)
7. **Local OUI database + caching** — support `oui.csv` file and periodic update instructions. (`utils.py`)
8. **Signature DB (banner → product mapping)** — JSON `signatures.json` and matching code. (`scanner_core.py`, `signatures.json`)
9. **SMB/NetBIOS probing + SMB handshake (optional use of impacket)** — better Windows/NAS detection. (`scanner_core.py`)
10. **Nmap integration & parse results** — optional auto-nmap for “Unknown” hosts or on-demand; parse `-oX` or text for OS/service strings. (`scanner_core.py`, `gui.py`)

## Additional high/medium features to approach AIS behavior

* UDP discovery tuning and additional ports (RTSP, WS-Discovery).
* ONVIF discovery for IP cameras.
* TLS cert parsing (subject could include vendor).
* Signature harvesting UI to add discovered patterns to signature DB.
* SMB/RPC `srvsvc` queries for Windows details (requires `impacket`).
* Auto-updating signature and OUI databases (opt-in).
* Heuristics & confidence scoring (combine evidence from many probes with scoring).
* Better Windows-native integration & packaging (EXE installer) — optional.

## UI and UX polish

* Product column, device icons, grouping collapse/expand by type.
* Column persistence, reorder & width persistence.
* Multi-select actions (WOL, SQL export, SSH batch).
* Embedded browser via helper process (see section below).
* Logging, debug mode, and persistent settings (JSON file).

## Security, privacy & ethical

* Clear warnings about SNMP, UPnP and scanning others’ networks.
* Rate-limiting and polite defaults.
* Avoid running privileged raw sockets unless user opts in.

---

# Quickstart / Dependencies

## Recommended: use a Python venv

```bash
python -m venv venv
venv\Scripts\activate      # Windows
source venv/bin/activate   # macOS / Linux
pip install -r requirements.txt   # if you add this file
```

## Core Python deps (optional ones listed)

* Python 3.8+
* Required (for basic features): `tkinter` (system package on some Linux), nothing else strictly required.
* Optional but strongly recommended:

  * `pywebview` — for embedded browser (helper process recommended)
  * `zeroconf` — mDNS/Bonjour
  * `pysnmp` — SNMP queries
  * `nmap` installed separately (native binary) — used by `nmap_scan_target`
  * `impacket` — stronger SMB/RPC probing (optional, heavy)
* On Windows: provided command-line tools (`netsh`, `arp`, `nbtstat`) are used. On Linux/macOS: `nmcli`, `iwlist`, `nmblookup`, `arp`, `ip` etc may be used.

## How to run

From project root:

```bash
python main.py
```

If you want embedded browser functionality, ensure `webview_helper.py` exists and `pywebview` is installed in the environment the helper will run in (we spawn a helper with `sys.executable` to avoid main-thread problems).

---

# Files & where to implement changes (mapping)

* `main.py` — app bootstrap; avoid calling `webview.start()` in same process as Tkinter; spawn helper process instead.
* `gui.py` — all GUI logic: widgets, tree, right-click menu, embedded browser helper invocation, ssh launcher, CSV export, settings persistence.
* `scanner_core.py` — core scanning logic: ping/arp, ssdp/mdns/snmp, banner probes, UDP probes, heuristics, signature matching, nmap wrapper.
* `utils.py` — MAC/OUI lookup, `expand_targets`, caching, config helpers.
* `webview_helper.py` — small helper script that runs `webview.start()` and opens windows (spawned by GUI).
* `signatures.json` — signature DB for banner → product mapping (new).
* `oui.csv` — optional local OUI CSV for offline MAC vendor lookup (new).
* `ssh_prefs.json`, `config.json` — saved GUI prefs (new).
* `tests/` — unit tests (new).

---

# Embedded browser (pywebview) helper note

Do **not** call `webview.start()` from a background thread in your main Tkinter process — on many platforms pywebview must run on the main thread. The stable approach:

1. Provide `webview_helper.py` that calls `webview.start()` and accepts a URL argument.
2. From `gui.py` spawn a new process: `subprocess.Popen([sys.executable, helper_path, url])`.
3. If `pywebview` isn't installed, fall back to `webbrowser.open(url)`.

This is already implemented in your current `gui.py` code; keep using the helper process approach.

---

# Router Wi-Fi / nearby networks scanning note

* Your laptop can scan *what it sees* (nearby APs and their BSSIDs) using OS tools (`netsh` on Windows, `nmcli` / `iwlist` on Linux, `airport` on macOS). That will enumerate nearby SSIDs & BSSIDs, but **it cannot query other APs' client lists** unless you authenticate to the router APIs (vendor-specific) or the router exposes SNMP/Wi-Fi monitoring endpoints.
* Querying the router for its client list would require:

  * Router-specific API or credentials AND code to authenticate and parse (per-router adapters), or
  * SNMP access to query associated stations (not always enabled).
* Add a GUI checkbox “Scan nearby Wi-Fi networks” to run OS-level scan and show SSIDs; to get router-assigned clients you need router integration (extra work).

---

# Security, privacy & legal note

* Only scan networks you own or have explicit permission to scan.
* SNMP and certain probes can reveal sensitive data. SNMP probing requires opt-in from the user.
* No built-in exploit code should be added — this is a discovery/fingerprinting tool only.

---

# Tests & QA checklist

* Unit tests for: `utils.expand_targets`, `utils.mac_normalize`, `parse_http_title`, UPnP XML parsing.
* Manual tests:

  * Local `/24` scan: check MACs & hostnames populated.
  * mDNS: verify discovery of Apple devices and printers.
  * UPnP: verify friendlyName/model on a Smart TV or DLNA server.
  * SNMP: test against a device with `public` community.
  * Nmap: run on a known host and confirm parsed output is reflected in UI.
  * SSH opening/wake-on-lan/export actions.
  * Cancel scan mid-run; UI should stay responsive.

---

# How you can contribute / next steps

If you plan to open-source and accept contributions, consider adding:

* `CONTRIBUTING.md` with coding style, test instructions, and signature format.
* `signatures.json` starter DB (I can generate a starter set for common devices).
* `requirements.txt` listing optional extras (zeroconf, pysnmp, pywebview).
* CI pipeline for tests & linting.

If you want, I can:

* produce a starter `signatures.json` (~20 patterns),
* provide `webview_helper.py` example,
* produce code to load `signatures.json` and integrate matching into `scanner_core.py`,
* or produce a `TODO.md` with the precise prioritized sprint list mapped to code changes.

Tell me which one you want me to generate next and I’ll paste it here.

---

# License

Choose a license before releasing publicly. Suggested: **MIT** (permissive) or **Apache 2.0** (patent grant). I can generate a `LICENSE` file for you.

---

# Final notes (short)

This README is intended to be both a user quickstart and a dev blueprint. It lists the immediate useful improvements (UPnP, mDNS, SNMP, signature DB, SMB/NetBIOS parsing, UI polish) plus an exhaustive feature bank to approach full AIS parity. If you want, I’ll now generate the starter `signatures.json` and the code snippet to load and use it in your `scanner_core.py`. Which should I produce next?
=======
# Advanced-LAN-Scanner
>>>>>>> f671c0bec211e728466ceb6f3538f28f520d817d
