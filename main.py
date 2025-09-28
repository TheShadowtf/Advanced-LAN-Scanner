#!/usr/bin/env python3
"""
Advanced LAN Scanner
Features:
- Flexible target input: CIDR, IP ranges (a-b), comma lists, file load
- Live ping-sweep (concurrent), ARP -> MAC addresses
- Hostname resolution (reverse DNS), NetBIOS fallback (Windows: nbtstat, Unix: nmblookup)
- Optional online MAC vendor lookup (api.macvendors.com) with local caching
- Optional nmap advanced scans (service/version + OS detection) if nmap in PATH
- Sortable columns, filter, progress bar, CSV export

Run: python scanner_advanced.py
Dependencies: Python 3.8+, tkinter (python3-tk on some Linux), nmap optional
"""
from gui import App

def main():
    app = App()
    app.mainloop()

if __name__ == "__main__":
    main()