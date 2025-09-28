#!/usr/bin/env python3
"""
Advanced LAN Scanner (Tkinter UI)
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

import os
import sys
import re
import json
import time
import socket
import ipaddress
import platform
import subprocess
import threading
import queue
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

IS_WIN = platform.system().lower().startswith("win")
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# -------------------- Config / files --------------------
MAC_CACHE_FILE = os.path.join(SCRIPT_DIR, "mac_cache.json")
# Optional: user can place 'oui.csv' in same folder with rows: OUI_PREFIX,Vendor Name
LOCAL_OUI_CSV = os.path.join(SCRIPT_DIR, "oui.csv")

# -------------------- Utilities --------------------

def load_mac_cache():
    if os.path.exists(MAC_CACHE_FILE):
        try:
            with open(MAC_CACHE_FILE, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except Exception:
            return {}
    return {}

def save_mac_cache(cache):
    try:
        with open(MAC_CACHE_FILE, "w", encoding="utf-8") as fh:
            json.dump(cache, fh, indent=2, ensure_ascii=False)
    except Exception:
        pass

MAC_CACHE = load_mac_cache()

def mac_normalize(mac):
    mac = mac.strip().lower()
    mac = mac.replace('-', ':')
    return mac

def mac_prefix(mac, length=3):
    # return first 3 bytes uppercase e.g. '00:1a:2b'
    mac = mac_normalize(mac)
    parts = mac.split(':')
    return ':'.join(parts[:length])

def lookup_local_oui(mac):
    # optional small local CSV mapping - user can provide if desired
    if not os.path.exists(LOCAL_OUI_CSV):
        return None
    try:
        pref = mac_prefix(mac)
        with open(LOCAL_OUI_CSV, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                parts = [p.strip() for p in line.strip().split(',', 1)]
                if not parts:
                    continue
                if parts[0].lower() == pref.lower() or parts[0].lower().replace('-',':') == pref.lower():
                    return parts[1] if len(parts) > 1 else None
    except Exception:
        pass
    return None

def lookup_mac_online(mac):
    # Simple API call - note: may be rate-limited. Use only if user enables online lookup.
    try:
        api_url = f"https://api.macvendors.com/{urllib.request.quote(mac)}"
        with urllib.request.urlopen(api_url, timeout=6) as resp:
            text = resp.read().decode('utf-8', errors='ignore').strip()
            if text:
                return text
    except Exception:
        return None
    return None

def get_mac_vendor(mac, allow_online=False):
    mac = mac_normalize(mac)
    if not mac:
        return ""
    if mac in MAC_CACHE:
        return MAC_CACHE[mac]
    # check local OUI CSV
    vendor = lookup_local_oui(mac)
    if vendor:
        MAC_CACHE[mac] = vendor
        save_mac_cache(MAC_CACHE)
        return vendor
    # try cache by prefix
    pref = mac_prefix(mac)
    for k,v in MAC_CACHE.items():
        if mac_prefix(k) == pref:
            MAC_CACHE[mac] = v
            save_mac_cache(MAC_CACHE)
            return v
    # online
    if allow_online:
        vendor = lookup_mac_online(mac)
        if vendor:
            MAC_CACHE[mac] = vendor
            save_mac_cache(MAC_CACHE)
            return vendor
    return ""

def detect_local_subnet_default():
    # Best-effort pick of active IPv4 -> /24 default
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
    except Exception:
        ip = "192.168.1.100"
    try:
        net = ipaddress.ip_network(ip + "/24", strict=False)
        return str(net.network_address) + "/24"
    except Exception:
        return "192.168.1.0/24"

# -------------------- Target parsing --------------------

def expand_targets(input_text):
    """
    Accepts:
    - CIDR: 192.168.1.0/24
    - Range: 192.168.1.10-192.168.1.50
    - Single IP: 192.168.1.5
    - Comma separated: 192.168.1.5,192.168.1.10-15
    - Mixed whitespace allowed
    Returns list of IP strings (may be long)
    """
    toks = re.split(r'[,\s]+', input_text.strip())
    ips = []
    for t in toks:
        if not t:
            continue
        # CIDR?
        if '/' in t:
            try:
                net = ipaddress.ip_network(t.strip(), strict=False)
                ips.extend(str(ip) for ip in net.hosts())
                continue
            except Exception:
                pass
        # a-b range with full IPs: 192.168.1.10-192.168.1.50
        m = re.match(r'^(\d+\.\d+\.\d+\.\d+)\s*-\s*(\d+\.\d+\.\d+\.\d+)$', t)
        if m:
            a = ipaddress.IPv4Address(m.group(1))
            b = ipaddress.IPv4Address(m.group(2))
            if int(b) < int(a):
                a, b = b, a
            cur = int(a)
            while cur <= int(b):
                ips.append(str(ipaddress.IPv4Address(cur)))
                cur += 1
            continue
        # shorthand range: 192.168.1.10-50 (only last octet abbreviated)
        m2 = re.match(r'^(\d+\.\d+\.\d+)\.(\d+)\s*-\s*(\d+)$', t)
        if m2:
            base = m2.group(1)
            start = int(m2.group(2))
            end = int(m2.group(3))
            if end < start:
                start, end = end, start
            for o in range(start, end+1):
                ips.append(f"{base}.{o}")
            continue
        # single IP?
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', t):
            ips.append(t)
            continue
        # file://path to load
        if t.lower().startswith("file://"):
            path = t[7:]
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8", errors='ignore') as fh:
                    for line in fh:
                        line = line.strip()
                        if line:
                            ips.extend(expand_targets(line))
            continue
        # otherwise ignore invalid token
    # dedupe and sort
    ips = sorted(set(ips), key=lambda x: tuple(int(p) for p in x.split('.')))
    return ips

# -------------------- Network discovery --------------------

def ping_host(ip):
    # cross-platform ping; return True if success
    if IS_WIN:
        cmd = ["ping", "-n", "1", "-w", "1000", ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]
    try:
        res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return res.returncode == 0
    except Exception:
        return False

def read_arp_table():
    # return dict ip->mac
    try:
        if IS_WIN:
            p = subprocess.run(["arp", "-a"], capture_output=True, text=True)
            out = p.stdout
        else:
            p = subprocess.run(["ip", "neigh"], capture_output=True, text=True)
            out = p.stdout
            if not out.strip():
                p = subprocess.run(["arp", "-n"], capture_output=True, text=True)
                out = p.stdout
        return parse_arp_output(out)
    except Exception:
        return {}

def parse_arp_output(output):
    ip_mac = {}
    mac_re = re.compile(r'([0-9a-fA-F]{2}([:-][0-9a-fA-F]{2}){5})')
    ip_re = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3})')
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        m_mac = mac_re.search(line)
        m_ip = ip_re.search(line)
        if m_ip and m_mac:
            ip = m_ip.group(1)
            mac = m_mac.group(1).lower().replace('-', ':')
            ip_mac[ip] = mac
    return ip_mac

def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        # try NetBIOS / nmblookup fallback
        try:
            if IS_WIN:
                # nbtstat -A <ip>
                p = subprocess.run(["nbtstat", "-A", ip], capture_output=True, text=True, timeout=3)
                out = p.stdout
                # parse name line like: "<00>  UNIQUE  Workstation Service"
                m = re.search(r'^\s*([^<\r\n]+)\s+<..>\s+.+$', out, re.MULTILINE)
                if m:
                    name = m.group(1).strip()
                    if name:
                        return name
            else:
                # nmblookup -A <ip> (from samba package)
                p = subprocess.run(["nmblookup", "-A", ip], capture_output=True, text=True, timeout=3)
                out = p.stdout + p.stderr
                m = re.search(r'^\s*([^<\r\n]+)\s+<..>\s+.+$', out, re.MULTILINE)
                if m:
                    name = m.group(1).strip()
                    if name:
                        return name
        except Exception:
            pass
    return ""

# -------------------- Nmap helper --------------------

def nmap_installed():
    try:
        p = subprocess.run(["nmap", "--version"], capture_output=True, text=True)
        return p.returncode == 0
    except Exception:
        return False

def nmap_scan_target(ip, aggressive=False, ports=None, timeout=120):
    """
    aggressive -> sV -O (service/version + OS)
    ports -> "22,80,443" or None for default
    returns raw nmap output (text)
    """
    if not nmap_installed():
        return "nmap not found in PATH."
    cmd = ["nmap", "-Pn"]
    if aggressive:
        cmd += ["-sV", "-O", "--osscan-guess"]
    else:
        cmd += ["-sV"]
    if ports:
        cmd += ["-p", ports]
    cmd += [ip]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.stdout + ("\n\n" + p.stderr if p.stderr else "")
    except subprocess.TimeoutExpired:
        return "nmap timed out."
    except Exception as e:
        return f"nmap error: {e}"

# -------------------- Scanner class --------------------

class AdvancedScanner:
    def __init__(self, targets, max_workers=200, allow_online_vendor=False):
        self.targets = targets  # list of IP strings
        self.max_workers = max_workers
        self.allow_online_vendor = allow_online_vendor
        self.results = []  # dicts: ip, alive(bool), hostname, mac, vendor
        self._cancel = threading.Event()

    def cancel(self):
        self._cancel.set()

    def run(self, progress_callback=None, live_callback=None):
        self.results = []
        total = len(self.targets)
        alive = []
        # ping sweep concurrently
        with ThreadPoolExecutor(max_workers=min(self.max_workers, total or 1)) as ex:
            futures = {ex.submit(ping_host, ip): ip for ip in self.targets}
            done = 0
            for fut in as_completed(futures):
                ip = futures[fut]
                if self._cancel.is_set():
                    break
                try:
                    ok = fut.result()
                except Exception:
                    ok = False
                if ok:
                    alive.append(ip)
                done += 1
                if progress_callback:
                    progress_callback(done, total)
        if self._cancel.is_set():
            return []
        # read ARP table once (after ping) to get MACs
        arp = read_arp_table()
        # resolve hostnames concurrently
        hostnames = {}
        with ThreadPoolExecutor(max_workers=50) as ex:
            futs = {ex.submit(resolve_hostname, ip): ip for ip in alive}
            for fut in as_completed(futs):
                ip = futs[fut]
                if self._cancel.is_set():
                    break
                try:
                    name = fut.result()
                except Exception:
                    name = ""
                hostnames[ip] = name or ""
        # assemble results; lookup vendors (cached/online)
        for ip in alive:
            mac = arp.get(ip, "")
            vendor = get_mac_vendor(mac, allow_online=self.allow_online_vendor) if mac else ""
            entry = {"ip": ip, "alive": True, "hostname": hostnames.get(ip, ""), "mac": mac, "vendor": vendor}
            self.results.append(entry)
            if live_callback:
                live_callback(entry)
        # sort
        self.results.sort(key=lambda r: tuple(int(x) for x in r['ip'].split('.')))
        return self.results

# -------------------- GUI --------------------

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("LAN Scanner — Advanced")
        self.geometry("980x600")
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.scanner_thread = None
        self.scanner = None

        # top controls
        frm_top = ttk.Frame(self)
        frm_top.pack(side=tk.TOP, fill=tk.X, padx=8, pady=6)

        ttk.Label(frm_top, text="Targets:").pack(side=tk.LEFT)
        self.targets_var = tk.StringVar(value=detect_local_subnet_default())
        entry_targets = ttk.Entry(frm_top, textvariable=self.targets_var, width=40)
        entry_targets.pack(side=tk.LEFT, padx=6)

        btn_load = ttk.Button(frm_top, text="Load File", command=self._load_file)
        btn_load.pack(side=tk.LEFT, padx=2)

        ttk.Label(frm_top, text="Workers:").pack(side=tk.LEFT, padx=(10,0))
        self.workers_var = tk.IntVar(value=150)
        ttk.Spinbox(frm_top, from_=10, to=500, textvariable=self.workers_var, width=5).pack(side=tk.LEFT, padx=4)

        self.online_oui_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(frm_top, text="Online MAC vendor lookup", variable=self.online_oui_var).pack(side=tk.LEFT, padx=6)

        self.nmap_aggressive_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(frm_top, text="Enable nmap aggressive (service+OS)", variable=self.nmap_aggressive_var).pack(side=tk.LEFT, padx=6)

        btn_scan = ttk.Button(frm_top, text="Start Scan", command=self._start_scan)
        btn_scan.pack(side=tk.LEFT, padx=6)
        btn_stop = ttk.Button(frm_top, text="Stop", command=self._stop_scan)
        btn_stop.pack(side=tk.LEFT, padx=4)

        # filter
        frm_filter = ttk.Frame(self)
        frm_filter.pack(side=tk.TOP, fill=tk.X, padx=8, pady=(0,6))
        ttk.Label(frm_filter, text="Filter:").pack(side=tk.LEFT)
        self.filter_var = tk.StringVar(value="")
        self.filter_var.trace_add("write", lambda *a: self._apply_filter())
        ttk.Entry(frm_filter, textvariable=self.filter_var, width=30).pack(side=tk.LEFT, padx=6)
        ttk.Button(frm_filter, text="Clear", command=lambda: self.filter_var.set("")).pack(side=tk.LEFT)

        # progress
        frm_progress = ttk.Frame(self)
        frm_progress.pack(side=tk.TOP, fill=tk.X, padx=8)
        self.status_var = tk.StringVar(value="Idle")
        ttk.Label(frm_progress, textvariable=self.status_var).pack(side=tk.LEFT)
        self.progress = ttk.Progressbar(frm_progress, orient=tk.HORIZONTAL, length=300, mode="determinate")
        self.progress.pack(side=tk.LEFT, padx=8)

        # treeview
        cols = ("ip","hostname","mac","vendor")
        self.tree = ttk.Treeview(self, columns=cols, show="headings")
        self.tree.heading("ip", text="IP", command=lambda: self._sortby("ip", False))
        self.tree.heading("hostname", text="Hostname", command=lambda: self._sortby("hostname", False))
        self.tree.heading("mac", text="MAC", command=lambda: self._sortby("mac", False))
        self.tree.heading("vendor", text="Vendor", command=lambda: self._sortby("vendor", False))
        self.tree.column("ip", width=120, anchor=tk.W)
        self.tree.column("hostname", width=370, anchor=tk.W)
        self.tree.column("mac", width=160, anchor=tk.W)
        self.tree.column("vendor", width=260, anchor=tk.W)
        self.tree.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=8, pady=6)

        # right-click menu
        self.menu = tk.Menu(self, tearoff=0)
        self.menu.add_command(label="Copy IP", command=self._copy_ip)
        self.menu.add_command(label="Open http://IP", command=self._open_http)
        self.menu.add_command(label="Nmap scan this host", command=self._nmap_scan_selected)
        self.menu.add_separator()
        self.menu.add_command(label="Export shown to CSV", command=self._export_csv)

        self.tree.bind("<Button-3>", self._on_right_click)
        self.tree.bind("<Double-1>", lambda e: self._open_http())

        # status bar bottom
        frm_bottom = ttk.Frame(self)
        frm_bottom.pack(side=tk.BOTTOM, fill=tk.X, padx=8, pady=6)
        self.msg_var = tk.StringVar(value="")
        ttk.Label(frm_bottom, textvariable=self.msg_var).pack(side=tk.LEFT)

        # internal data map ip->treeid and entries
        self._entries = {}  # ip -> entry dict
        self._visible_ips = set()
        self._sort_state = {}  # column->(asc_bool)

    # ---------------- UI helpers ----------------

    def _load_file(self):
        p = filedialog.askopenfilename(title="Load IP list file", filetypes=[("Text","*.txt;*.csv"),("All","*.*")])
        if not p:
            return
        lines = []
        try:
            with open(p, "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    line=line.strip()
                    if line:
                        lines.append(line)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read file: {e}")
            return
        if lines:
            # join lines into target field (they can be file:// or ip lines)
            text = ",".join(lines)
            self.targets_var.set(text)

    def _on_right_click(self, event):
        iid = self.tree.identify_row(event.y)
        if iid:
            self.tree.selection_set(iid)
            self.menu.tk_popup(event.x_root, event.y_root)

    def _copy_ip(self):
        sel = self.tree.selection()
        if not sel:
            return
        ip = self.tree.item(sel[0])['values'][0]
        self.clipboard_clear()
        self.clipboard_append(ip)
        self.msg_var.set(f"Copied {ip}")

    def _open_http(self):
        sel = self.tree.selection()
        if not sel:
            return
        ip = self.tree.item(sel[0])['values'][0]
        import webbrowser
        webbrowser.open(f"http://{ip}")

    def _export_csv(self):
        if not self._entries:
            messagebox.showinfo("No data", "No results to export.")
            return
        p = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV","*.csv"),("All","*.*")])
        if not p:
            return
        try:
            with open(p, "w", encoding="utf-8", newline='') as fh:
                import csv
                w = csv.writer(fh)
                w.writerow(["IP","Hostname","MAC","Vendor"])
                for ip in sorted(self._entries.keys(), key=lambda x: tuple(int(p) for p in x.split('.'))):
                    e = self._entries[ip]
                    w.writerow([e.get("ip",""), e.get("hostname",""), e.get("mac",""), e.get("vendor","")])
            messagebox.showinfo("Saved", f"Saved {len(self._entries)} rows to {p}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save: {e}")

    # ---------------- scanning control ----------------

    def _start_scan(self):
        if self.scanner_thread and self.scanner_thread.is_alive():
            messagebox.showwarning("Running", "Scan already running.")
            return
        targets_raw = self.targets_var.get().strip()
        if not targets_raw:
            messagebox.showerror("No targets", "Enter targets (CIDR, range, list) first.")
            return
        targets = expand_targets(targets_raw)
        if not targets:
            messagebox.showerror("No targets", "No valid IPs expanded from input.")
            return
        # prepare UI
        self._entries.clear()
        for item in self.tree.get_children():
            self.tree.delete(item)
        self._visible_ips.clear()
        self.progress['value'] = 0
        self.progress['maximum'] = len(targets)
        self.status_var.set("Starting scan...")
        self.msg_var.set("")
        self.scanner = AdvancedScanner(targets, max_workers=self.workers_var.get(), allow_online_vendor=self.online_oui_var.get())
        self.scanner_thread = threading.Thread(target=self._run_scanner, daemon=True)
        self.scanner_thread.start()

    def _stop_scan(self):
        if self.scanner:
            self.scanner.cancel()
            self.status_var.set("Stopping...")

    def _run_scanner(self):
        try:
            def progress(done, total):
                self.progress['value'] = done
                self.status_var.set(f"Scanning... {done}/{total}")
            def live_cb(entry):
                # insert into tree as discovered
                ip = entry['ip']
                self._entries[ip] = entry
                self._insert_or_update_row(entry)
                self._apply_filter()
            results = self.scanner.run(progress_callback=progress, live_callback=live_cb)
            self.status_var.set(f"Scan complete: {len(results)} host(s) found.")
            self.msg_var.set("Scan finished.")
        except Exception as e:
            self.status_var.set(f"Error: {e}")
            self.msg_var.set("Scan encountered an error.")

    def _insert_or_update_row(self, entry):
        ip = entry['ip']
        vals = (entry.get("ip",""), entry.get("hostname",""), entry.get("mac",""), entry.get("vendor",""))
        # if exists, update, else insert
        if ip in self._entries and any(self.tree.item(i)['values'][0]==ip for i in self.tree.get_children()):
            # find item and update
            for iid in self.tree.get_children():
                if self.tree.item(iid)['values'][0] == ip:
                    self.tree.item(iid, values=vals)
                    return
        # not found -> insert
        iid = self.tree.insert("", tk.END, values=vals)
        self._visible_ips.add(ip)

    # ---------------- filtering / sorting ----------------

    def _apply_filter(self):
        f = self.filter_var.get().strip().lower()
        # clear tree
        for item in self.tree.get_children():
            self.tree.delete(item)
        for ip in sorted(self._entries.keys(), key=lambda x: tuple(int(p) for p in x.split('.'))):
            e = self._entries[ip]
            combined = " ".join([str(e.get("ip","")), e.get("hostname","") or "", e.get("mac","") or "", e.get("vendor","") or ""]).lower()
            if f and f not in combined:
                continue
            self.tree.insert("", tk.END, values=(e.get("ip",""), e.get("hostname",""), e.get("mac",""), e.get("vendor","")))

    def _sortby(self, col, descending):
        # get data from tree
        data = [(self.tree.set(child, col), child) for child in self.tree.get_children('')]
        try:
            data.sort(key=lambda t: tuple(int(x) for x in t[0].split('.')) if col=="ip" else t[0].lower(), reverse=descending)
        except Exception:
            data.sort(reverse=descending)
        # rearrange items
        for index, (val, iid) in enumerate(data):
            self.tree.move(iid, '', index)
        # reverse sort next time
        self._sort_state[col] = not descending
        # update heading command to toggle
        self.tree.heading(col, command=lambda c=col: self._sortby(c, self._sort_state.get(c, False)))

    # ---------------- Nmap scan from UI ----------------

    def _nmap_scan_selected(self):
        sel = self.tree.selection()
        if not sel:
            return
        ip = self.tree.item(sel[0])['values'][0]
        aggressive = self.nmap_aggressive_var.get()
        self._show_nmap_popup(ip, aggressive)

    def _show_nmap_popup(self, ip, aggressive):
        # perform nmap in thread and show output in popup text
        popup = tk.Toplevel(self)
        popup.title(f"Nmap scan: {ip}")
        popup.geometry("700x500")
        txt = tk.Text(popup, wrap="none")
        txt.pack(fill=tk.BOTH, expand=True)
        txt.insert("end", f"Starting nmap scan for {ip}...\n")
        txt.configure(state="disabled")
        def run():
            out = nmap_scan_target(ip, aggressive=aggressive)
            txt.configure(state="normal")
            txt.delete("1.0","end")
            txt.insert("1.0", out)
            txt.configure(state="disabled")
        th = threading.Thread(target=run, daemon=True)
        th.start()

    # ---------------- close ----------------

    def _on_close(self):
        if self.scanner and getattr(self.scanner, "_cancel", None) and not self.scanner._cancel.is_set():
            if not messagebox.askyesno("Quit", "A scan may be running. Quit anyway?"):
                return
        self.destroy()

def main():
    app = App()
    app.mainloop()

if __name__ == "__main__":
    main()
