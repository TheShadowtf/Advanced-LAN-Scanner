# gui.py

import socket
import subprocess
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import webbrowser
import csv
import os
import sys
import webview  # pywebview
import shutil
import getpass
import json
import shlex
import tkinter.simpledialog as simpledialog


from scanner_core import AdvancedScanner, nmap_scan_target, wifi_scan
from utils import detect_local_subnet_default, expand_targets

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("LAN Scanner — Advanced")
        self.geometry("980x600")
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        
        self.scanner_thread = None
        self.scanner = None
        self._entries = {}
        self._sort_state = {}

        # build UI
        self.create_widgets()
        self.targets_var.set(detect_local_subnet_default())

    def create_widgets(self):
        # --- Top controls Frame ---
        top_frame = ttk.Frame(self, padding=(10, 10, 10, 0))
        top_frame.pack(side=tk.TOP, fill=tk.X)

        # Row 1: Targets entry + Load File (entry expands)
        top_row_1 = ttk.Frame(top_frame)
        top_row_1.pack(fill=tk.X, expand=True)
        ttk.Label(top_row_1, text="Targets:").pack(side=tk.LEFT, padx=(0, 5))
        self.targets_var = tk.StringVar()
        entry_targets = ttk.Entry(top_row_1, textvariable=self.targets_var)
        entry_targets.pack(side=tk.LEFT, fill=tk.X, expand=True)
        btn_load = ttk.Button(top_row_1, text="Load File", command=self._load_file)
        btn_load.pack(side=tk.LEFT, padx=(5, 10))

        # Row 2: Controls (workers + checkboxes) on the left, Start/Stop on the right
        top_row_2 = ttk.Frame(top_frame)
        top_row_2.pack(fill=tk.X, expand=False, pady=(6, 0))

        # Left side controls
        left_controls = ttk.Frame(top_row_2)
        left_controls.pack(side=tk.LEFT, anchor="w", fill=tk.X, expand=True)

        ttk.Label(left_controls, text="Workers:").pack(side=tk.LEFT, padx=(0, 5))
        self.workers_var = tk.IntVar(value=150)
        ttk.Spinbox(left_controls, from_=10, to=500, textvariable=self.workers_var, width=5).pack(side=tk.LEFT, padx=(0, 10))

        self.online_oui_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(left_controls, text="Online MAC vendor lookup", variable=self.online_oui_var).pack(side=tk.LEFT, padx=5)

        self.nmap_aggressive_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(left_controls, text="Enable nmap aggressive (service+OS)", variable=self.nmap_aggressive_var).pack(side=tk.LEFT, padx=5)

        self.scan_wifi_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(left_controls, text="Scan nearby Wi-Fi networks", variable=self.scan_wifi_var).pack(side=tk.LEFT, padx=5)

        # Right side action buttons (anchored to right so they don't get pushed)
        right_controls = ttk.Frame(top_row_2)
        right_controls.pack(side=tk.RIGHT, anchor="e")
        self.btn_scan = ttk.Button(right_controls, text="Start Scan", command=self._start_scan)
        self.btn_scan.pack(side=tk.LEFT, padx=(0, 5))
        self.btn_stop = ttk.Button(right_controls, text="Stop", command=self._stop_scan, state=tk.DISABLED)
        self.btn_stop.pack(side=tk.LEFT)

        # --- Filter and Status Bar Frame ---
        bottom_controls_frame = ttk.Frame(top_frame)
        bottom_controls_frame.pack(fill=tk.X, expand=True, pady=(10, 5))

        # Filter row (top)
        filter_row = ttk.Frame(bottom_controls_frame)
        filter_row.pack(fill=tk.X, expand=True)
        ttk.Label(filter_row, text="Filter:").pack(side=tk.LEFT, padx=(0,5))
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add("write", lambda *a: self._apply_filter())
        # keep entry a bit larger so progress can be slightly longer than it
        ttk.Entry(filter_row, textvariable=self.filter_var, width=40).pack(side=tk.LEFT)
        ttk.Button(filter_row, text="Clear", command=lambda: self.filter_var.set("")).pack(side=tk.LEFT, padx=5)

        # Status row (under the filter) — progress is modest fixed length so it doesn't span whole window
        status_row = ttk.Frame(bottom_controls_frame)
        status_row.pack(fill=tk.X, expand=True, pady=(6, 0))
        self.status_var = tk.StringVar(value="Idle")
        ttk.Label(status_row, textvariable=self.status_var).pack(side=tk.LEFT, padx=(0, 5))
        # progress length chosen to be slightly wider than the filter entry visually (~260 px)
        self.progress = ttk.Progressbar(status_row, orient=tk.HORIZONTAL, length=260, mode="determinate")
        self.progress.pack(side=tk.LEFT, expand=False, padx=5)

        # --- Treeview (Results) Frame ---
        tree_frame = ttk.Frame(self, padding=(10, 0, 10, 10))
        tree_frame.pack(fill=tk.BOTH, expand=True)
        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)

        cols = ("ip", "hostname", "product", "type", "mac", "vendor")
        self.tree = ttk.Treeview(tree_frame, columns=cols, show="headings", selectmode="extended")
        self.tree.grid(row=0, column=0, sticky="nsew")

        # icon images registry and grouping state
        self._icons = {}          # device_type -> PhotoImage
        self._group_items = {}    # device_type -> tree parent id
        self._group_order = []    # ordered list of device_type strings (keeps group ordering)

        # vertical scrollbar
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        vsb.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=vsb.set)

        col_widths = {"ip": 120, "hostname": 200, "product": 220, "type": 140, "mac": 150, "vendor": 200}
        for col, width in col_widths.items():
            self.tree.heading(col, text=col.capitalize(), command=lambda _col=col: self._sortby(_col, False))
            self.tree.column(col, width=width, anchor=tk.W)

        # --- Right-click Menu ---
        self.menu = tk.Menu(self, tearoff=0)
        self.menu.add_command(label="Copy IP", command=self._copy_ip)
        self.menu.add_command(label="Open http://IP", command=self._open_http)
        self.menu.add_command(label="Open in built-in browser", command=self._open_in_browser)
        self.menu.add_command(label="Open SSH", command=self._open_ssh)
        self.menu.add_separator()
        self.menu.add_command(label="Nmap scan this host", command=self._nmap_scan_selected)
        self.menu.add_separator()
        self.menu.add_command(label="Export selected to CSV", command=self._export_csv)

        self.tree.bind("<Button-3>", self._on_right_click)
        self.tree.bind("<Double-1>", lambda e: self._open_http())


    def _make_icon(self, color="#4caf50", size=12):
        """
        Generate a tiny round icon with given color and return a PhotoImage.
        Cached per color.
        """
        key = f"{color}_{size}"
        if key in self._icons:
            return self._icons[key]
        img = tk.PhotoImage(width=size, height=size)
        # draw filled circle by filling rows (simple approximation)
        r = size // 2
        for y in range(size):
            for x in range(size):
                dx = x - r + 0.5
                dy = y - r + 0.5
                if dx*dx + dy*dy <= r*r:
                    img.put(color, (x, y))
                else:
                    img.put("", (x, y))
        self._icons[key] = img
        return img

    def _open_ssh(self):
        """Right-click -> Open SSH. Prompt for username/port/key and launch terminal."""
        if not self.tree.selection():
            return
        ip = self.tree.item(self.tree.selection()[0])['values'][0]

        # Load last prefs
        prefs = self._load_ssh_prefs()
        default_user = prefs.get("username", getpass.getuser())
        default_port = prefs.get("port", 22)

        # Ask for username (simple dialog)
        user = simpledialog.askstring("SSH Username", "Username:", initialvalue=default_user, parent=self)
        if user is None:
            return  # user cancelled

        # Ask for port
        try:
            port = simpledialog.askinteger("SSH Port", "Port:", initialvalue=int(default_port), parent=self)
        except Exception:
            port = default_port
        if port is None:
            return

        # Ask optionally for a private key file (or Cancel/Skip)
        use_key = messagebox.askyesno("Private key?", "Use a private key file for authentication?", parent=self)
        key_path = ""
        if use_key:
            key_path = filedialog.askopenfilename(title="Select private key (optional)", parent=self)
            if not key_path:
                # user canceled selection — treat as no key
                key_path = ""

        # Save prefs for next time
        prefs["username"] = user
        prefs["port"] = port
        self._save_ssh_prefs(prefs)

        # Build SSH command (careful quoting)
        # Use shlex.quote for safe quoting of key path and user@ip
        user_at_host = f"{user}@{ip}"
        # Assemble base command string (we use a single string to pass to shell wrappers)
        parts = ["ssh", "-p", str(port)]
        if key_path:
            parts.extend(["-i", key_path])
        parts.append(user_at_host)
        # Build a safe printable command — for windows cmd/powershell this usually works as plain string
        # Use shlex.join when available (py3.8+ doesn't have shlex.join, so do manual)
        try:
            ssh_cmd = shlex.join(parts)
        except AttributeError:
            # fallback for older versions
            ssh_cmd = " ".join(shlex.quote(p) for p in parts)

        # Launch in terminal emulator
        self._launch_ssh_in_terminal(ssh_cmd)


    def _open_in_browser(self):
        """Launch the external webview_helper.py helper process to open an embedded browser.
        If helper missing or pywebview not installed, fall back to the system browser.
        """
        if not self.tree.selection():
            return
        ip = self.tree.item(self.tree.selection()[0])['values'][0]
        url = f"http://{ip}"

        helper_path = os.path.join(os.path.dirname(__file__), "webview_helper.py")
        # if helper not present -> system browser fallback
        if not os.path.exists(helper_path):
            webbrowser.open(url)
            messagebox.showinfo("Embedded browser unavailable", "webview helper not found; opened system browser instead.")
            return

        # ensure pywebview exists in the environment the helper will use
        try:
            import importlib.util
            spec = importlib.util.find_spec("webview")
            if spec is None:
                raise ImportError("pywebview not installed")
        except Exception:
            webbrowser.open(url)
            messagebox.showinfo(
                "pywebview not installed",
                "pywebview is not installed in this Python environment. Opened system browser instead.\n\n"
                "To enable embedded browser, run: pip install pywebview"
            )
            return

        # Launch helper process using same python executable (so env matches)
        try:
            subprocess.Popen([sys.executable, helper_path, url], close_fds=True)
        except Exception as e:
            webbrowser.open(url)
            messagebox.showwarning("Browser launch failed",
                                f"Failed to launch embedded browser helper.\nOpened system browser instead.\n\n{e}")

    # ---------------- SSH prefs helper ----------------
    SSH_PREFS = os.path.join(os.path.dirname(__file__), "ssh_prefs.json")

    def _load_ssh_prefs(self):
        try:
            with open(self.SSH_PREFS, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except Exception:
            return {"username": getpass.getuser(), "port": 22}

    def _save_ssh_prefs(self, prefs):
        try:
            with open(self.SSH_PREFS, "w", encoding="utf-8") as fh:
                json.dump(prefs, fh)
        except Exception:
            pass

    # ---------------- Launch SSH in terminal ----------------
    def _launch_ssh_in_terminal(self, ssh_cmd):
        """Try various terminal emulators to run ssh_cmd and keep the shell open afterwards."""
        # ssh_cmd is a single string (e.g. 'ssh -i "/path/key" -p 2222 user@1.2.3.4')
        # We prefer to avoid shell=True where possible; many terminals require a single string/expression.
        try:
            if sys.platform.startswith("win"):
                # Try Windows Terminal (wt), then PowerShell, then cmd
                if shutil.which("wt"):
                    # wt supports command arguments; use powershell in new tab to run ssh and stay open
                    subprocess.Popen(["wt", "powershell", "-NoExit", "-Command", ssh_cmd], close_fds=True)
                    return
                if shutil.which("powershell"):
                    subprocess.Popen(["powershell", "-NoExit", "-Command", ssh_cmd], close_fds=True)
                    return
                # fallback to cmd.exe /K
                subprocess.Popen(["cmd", "/K", ssh_cmd], close_fds=True)
                return

            if sys.platform == "darwin":
                # Use AppleScript to tell Terminal.app to do script (keeps window open by default)
                # Need to escape double quotes in the command
                esc_cmd = ssh_cmd.replace('"', '\\"')
                applescript = f'''tell application "Terminal" to do script "{esc_cmd}"'''
                subprocess.Popen(["osascript", "-e", applescript], close_fds=True)
                return

            # For Linux/Unix: try common terminal emulators
            terms = [
                ("gnome-terminal", ["gnome-terminal", "--", "bash", "-lc", f"{ssh_cmd}; exec bash"]),
                ("konsole", ["konsole", "-e", "bash", "-lc", f"{ssh_cmd}; exec bash"]),
                ("xfce4-terminal", ["xfce4-terminal", "--command", f"bash -lc '{ssh_cmd}; exec bash'"]),
                ("tilix", ["tilix", "-e", "bash", "-lc", f"{ssh_cmd}; exec bash"]),
                ("alacritty", ["alacritty", "-e", "bash", "-lc", f"{ssh_cmd}; exec bash"]),
                ("xterm", ["xterm", "-e", f"bash -lc '{ssh_cmd}; exec bash'"]),
                ("mate-terminal", ["mate-terminal", "--", "bash", "-lc", f"{ssh_cmd}; exec bash"]),
                ("lxterminal", ["lxterminal", "-e", "bash", "-lc", f"{ssh_cmd}; exec bash"]),
            ]
            for name, cmd in terms:
                if shutil.which(name):
                    # If command is a list, use it directly
                    subprocess.Popen(cmd, close_fds=True)
                    return
            # if none found, fallback to running in a sh -c (may not open a new window)
            subprocess.Popen(["/bin/sh", "-c", f"{ssh_cmd}; exec /bin/bash"], close_fds=True)
        except Exception as e:
            # final fallback: open system browser to show error (or messagebox)
            messagebox.showerror("SSH launch failed", f"Failed to open terminal for SSH:\n{e}")

    def _on_close(self):
        if self.scanner_thread and self.scanner_thread.is_alive():
            if not messagebox.askyesno("Confirm Exit", "A scan is running. Are you sure you want to quit?"):
                return
            self.scanner.cancel()
        # Try to destroy webview windows (if any)
        try:
            for w in list(webview.windows):
                try:
                    webview.destroy_window(w)
                except Exception:
                    pass
        except Exception:
            pass
        self.destroy()

    def _load_file(self):
        p = filedialog.askopenfilename(title="Load IP list from file", filetypes=[("Text files", "*.txt;*.csv"),("All files", "*.*")])
        if not p: return
        try:
            with open(p, "r", encoding="utf-8", errors="ignore") as fh:
                self.targets_var.set(fh.read().replace('\n', ','))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read file: {e}")

    def _copy_multiple_ips(self):
        sel = self.tree.selection()
        ips = [self.tree.item(i)['values'][0] for i in sel]
        txt = "\n".join(ips)
        self.clipboard_clear()
        self.clipboard_append(txt)
        self.status_var.set(f"Copied {len(ips)} IPs to clipboard.")

    def _open_ssh_multi(self):
        # For simplicity: loop over selected and call _open_ssh for each (prompts for user each time).
        for iid in self.tree.selection():
            ip = self.tree.item(iid)['values'][0]
            # reuse _open_ssh logic but allow passing ip: we can create a variant _open_ssh_for_ip(ip)
            self._open_ssh_for_ip(ip)

    def _export_csv_selected(self):
        # export only selected rows (similar to _export_csv)
        items = self.tree.selection()
        if not items:
            messagebox.showinfo("No data", "No rows selected.")
            return
        p = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV","*.csv"),("All","*.*")])
        if not p:
            return
        try:
            with open(p, "w", encoding="utf-8", newline='') as fh:
                import csv
                w = csv.writer(fh)
                w.writerow([self.tree.heading(col)["text"] for col in self.tree["columns"]])
                for iid in items:
                    w.writerow(self.tree.item(iid)['values'])
            messagebox.showinfo("Saved", f"Exported {len(items)} rows to {os.path.basename(p)}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save: {e}")

    def _send_wol(self, mac):
        mac_clean = mac.replace(':','').replace('-','')
        if len(mac_clean) != 12:
            raise ValueError("Invalid MAC")
        data = bytes.fromhex('FF'*6 + mac_clean*16)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.sendto(data, ('<broadcast>', 9))
        s.close()

    def _wake_selected(self):
        # Ask confirmation and do WOL for selected rows that have a MAC
        sel = self.tree.selection()
        macs = []
        for iid in sel:
            entry = self._entries.get(iid)
            if entry and entry.get("mac"):
                macs.append(entry["mac"])
        if not macs:
            messagebox.showinfo("No MACs", "No MAC addresses available for selected hosts.")
            return
        if not messagebox.askyesno("Wake selected", f"Send Wake-on-LAN packet to {len(macs)} host(s)?"):
            return
        for mac in macs:
            try:
                self._send_wol(mac)
            except Exception:
                pass
        messagebox.showinfo("WOL", f"Sent magic packets to {len(macs)} hosts.")

    def _show_details(self, ip):
        entry = self._entries.get(ip)
        if not entry:
            messagebox.showinfo("No details", "No details available.")
            return
        popup = tk.Toplevel(self)
        popup.title(f"Details — {ip}")
        txt = tk.Text(popup, wrap='word', width=80, height=25)
        txt.pack(fill=tk.BOTH, expand=True)
        import json
        txt.insert("1.0", json.dumps(entry, indent=2))
        txt.configure(state='disabled')

    def _on_right_click(self, event):
        iid = self.tree.identify_row(event.y)
        # selection may be multi
        sel = self.tree.selection()
        if iid and iid not in sel:
            # if right-clicked row isn't in selection, select only that row
            self.tree.selection_set(iid)
            sel = (iid,)

        selected = self.tree.selection()
        if not selected:
            return

        # build menu dynamically
        self.menu.delete(0, tk.END)
        if len(selected) == 1:
            ip = self.tree.item(selected[0])['values'][0]
            self.menu.add_command(label="Copy IP", command=self._copy_ip)
            self.menu.add_command(label="Open http://IP", command=self._open_http)
            self.menu.add_command(label="Open in built-in browser", command=self._open_in_browser)
            self.menu.add_command(label="Open SSH", command=self._open_ssh)
            self.menu.add_separator()
            self.menu.add_command(label="Nmap scan this host", command=self._nmap_scan_selected)
            self.menu.add_separator()
            self.menu.add_command(label="Export selected to CSV", command=self._export_csv)
            self.menu.add_command(label="Show details", command=lambda: self._show_details(ip))
        else:
            # multi-select options
            self.menu.add_command(label=f"Copy {len(selected)} IPs", command=self._copy_multiple_ips)
            self.menu.add_command(label="Open SSH to all (prompt per-host)", command=self._open_ssh_multi)
            self.menu.add_command(label="Wake selected (WOL)", command=self._wake_selected)
            self.menu.add_separator()
            self.menu.add_command(label="Export selected to CSV", command=self._export_csv_selected)
        try:
            self.menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.menu.grab_release()

    def _copy_ip(self):
        if not self.tree.selection(): return
        ip = self.tree.item(self.tree.selection()[0])['values'][0]
        self.clipboard_clear()
        self.clipboard_append(ip)
        self.status_var.set(f"Copied {ip} to clipboard.")

    def _open_http(self):
        if not self.tree.selection(): return
        ip = self.tree.item(self.tree.selection()[0])['values'][0]
        webbrowser.open(f"http://{ip}")

    def _export_csv(self):
        items = self.tree.get_children('')
        if not items:
            messagebox.showinfo("No data", "No results to export.")
            return
        p = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV","*.csv"),("All","*.*")])
        if not p:
            return
        try:
            with open(p, "w", encoding="utf-8", newline='') as fh:
                writer = csv.writer(fh)
                # use column headings from Treeview columns (will include Type)
                writer.writerow([self.tree.heading(col)["text"] for col in self.tree["columns"]])
                for iid in items:
                    writer.writerow(self.tree.item(iid)['values'])
            messagebox.showinfo("Saved", f"Exported {len(items)} rows to {os.path.basename(p)}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save: {e}")

    def _start_scan(self):
        if self.scanner_thread and self.scanner_thread.is_alive():
            messagebox.showwarning("Running", "A scan is already in progress.")
            return
        
        self._entries.clear()
        # clear cached group parent ids (they no longer exist after clearing the tree)
        self._group_items.clear()
        # remove all items (groups and children will be rebuilt as needed)
        for item in self.tree.get_children():
            self.tree.delete(item)

        targets_raw = self.targets_var.get().strip()
        if not targets_raw:
            messagebox.showerror("No Targets", "Please enter target IP addresses or a range.")
            return

                # optionally run Wi-Fi nearby scan in background and inject those results into the view
        if self.scan_wifi_var.get():
            def run_wifi_thread():
                try:
                    self.after(0, lambda: self.status_var.set("Scanning nearby Wi-Fi networks..."))
                    try:
                        nets = wifi_scan(timeout=6.0)
                    except Exception as e:
                        nets = []
                        # surface the exception message to help debug
                        print("wifi_scan() raised:", repr(e))
                        self.after(0, lambda: self.status_var.set(f"Local Wi-Fi scan error: {e}"))

                    # Debug: print raw parsed results to console for troubleshooting
                    print("wifi_scan() ->", repr(nets))

                    if not nets:
                        # No networks found — inform user and continue
                        self.after(0, lambda: self.status_var.set("No nearby Wi-Fi networks found."))
                        # Show a small non-blocking information box so you notice
                        try:
                            self.after(0, lambda: messagebox.showinfo("Wi-Fi scan", "No nearby Wi-Fi networks found (wifi_scan returned zero)."))
                        except Exception:
                            pass
                        return

                    # Insert as entries into self._entries with unique ids prefixed by 'wifi:'
                    count = 0
                    for net in nets:
                        bssid = (net.get("bssid") or net.get("mac") or "").lower()
                        if not bssid:
                            bssid = f"no-bssid-{count}"
                        entry_id = f"wifi:{bssid}"
                        entry = {
                            "ip": entry_id,
                            "hostname": net.get("ssid", "") or "",
                            "mac": bssid,
                            "vendor": net.get("security", "") or "",
                            "device_type": "Wi-Fi Network",
                            "open_ports": [],
                            "banners": {},
                            "mdns": [],
                            "ssdp": [],
                            "snmp": {},
                            "udp": {},
                            "wifi_info": net
                        }
                        # store and call GUI insert on main thread
                        self._entries[entry_id] = entry
                        self.after(0, self._insert_or_update_row, entry)
                        count += 1

                    self.after(0, lambda: self.status_var.set(f"Nearby Wi-Fi: {len(nets)} networks found."))
                except Exception as e:
                    # capture any unexpected error
                    print("run_wifi_thread exception:", repr(e))
                    self.after(0, lambda: self.status_var.set(f"Wi-Fi scan failed: {e}"))
            threading.Thread(target=run_wifi_thread, daemon=True).start()


        try:
            targets = expand_targets(targets_raw)
            if not targets:
                messagebox.showerror("No Targets", "No valid IP addresses found in the input.")
                return
        except Exception as e:
            messagebox.showerror("Invalid Target", f"Error parsing targets: {e}")
            return
        
        self.progress['value'] = 0
        self.progress['maximum'] = len(targets)
        self.status_var.set("Starting scan...")
        self.btn_scan.config(state=tk.DISABLED)
        self.btn_stop.config(state=tk.NORMAL)
        
        self.scanner = AdvancedScanner(targets,
                              max_workers=self.workers_var.get(),
                              allow_online_vendor=self.online_oui_var.get(),
                              allow_mdns=True,
                              allow_ssdp=True,
                              allow_snmp=False,
                              do_fingerprints=True)
        self.scanner_thread = threading.Thread(target=self._run_scanner_thread, daemon=True)
        self.scanner_thread.start()

    def _run_scanner_thread(self):
        def progress(done, total):
            self.after(0, self.progress.config, {'value': done})
            self.after(0, self.status_var.set, f"Pinging... {done}/{total}")
        
        def live_cb(entry):
            self._entries[entry['ip']] = entry
            self.after(0, self._insert_or_update_row, entry)

        results_list = self.scanner.run(progress_callback=progress, live_callback=live_cb)
        
        if self.scanner._cancel.is_set():
            self.after(0, lambda: self.status_var.set("Scan stopped by user."))
        else:
            final_count = len(self._entries)
            self.after(0, lambda: self.status_var.set(f"Scan complete: {final_count} host(s) found."))

        self.after(0, lambda: self.btn_scan.config(state=tk.NORMAL))
        self.after(0, lambda: self.btn_stop.config(state=tk.DISABLED))
        self.after(0, self._apply_filter)

    def _stop_scan(self):
        if self.scanner:
            self.scanner.cancel()
        self.btn_stop.config(state=tk.DISABLED)
        
    def _ensure_group(self, dtype):
        """
        Ensure a parent node exists for the given device_type.
        Re-create the parent if the cached id was removed earlier.
        Returns the tree item id of the parent and ensures it's expanded (open).
        """
        if not dtype:
            dtype = "Unknown"

        # return cached parent id if it still exists
        pid = self._group_items.get(dtype)
        if pid and self.tree.exists(pid):
            try:
                self.tree.item(pid, open=True)
            except Exception:
                pass
            return pid

        # create a stable safe id for the group
        base_id = f"group:{dtype.replace(' ', '_')}"
        safe_id = base_id
        idx = 0
        while self.tree.exists(safe_id):
            idx += 1
            safe_id = f"{base_id}_{idx}"

        # Insert parent item (value is the group label).
        try:
            pid = self.tree.insert("", tk.END, iid=safe_id, values=(dtype,))
        except Exception:
            pid = self.tree.insert("", tk.END, values=(dtype,))

        # register and record order (only once)
        self._group_items[dtype] = pid
        if dtype not in self._group_order:
            self._group_order.append(dtype)

        # ensure open so children are visible
        try:
            self.tree.item(pid, open=True)
        except Exception:
            pass
        return pid


    def _insert_or_update_row(self, entry):
        # Build filter check (include device_type now)
        filter_term = self.filter_var.get().lower()
        # combine values including type
        combined = " ".join(str(v) for v in (
            entry.get("ip",""),
            entry.get("hostname",""),
            entry.get("device_type",""),
            entry.get("mac",""),
            entry.get("vendor","")
        )).lower()
        if filter_term and filter_term not in combined:
            # If exists already, detach it
            if self.tree.exists(entry['ip']):
                try:
                    self.tree.detach(entry['ip'])
                except Exception:
                    pass
            return  # Don't insert if it doesn't match the current filter

        # ensure group parent exists (this also repairs stale parent ids)
        dtype = entry.get("device_type") or "Unknown"
        parent = self._ensure_group(dtype)

        values = (
            entry.get("ip", ""),
            entry.get("hostname", ""),
            entry.get("product", "") or entry.get("manufacturer",""),
            entry.get("device_type",""),
            entry.get("mac", ""),
            entry.get("vendor", "")
        )

        item_id = entry['ip']

        # If item exists, update and move under parent
        if self.tree.exists(item_id):
            try:
                self.tree.item(item_id, values=values)
                try:
                    self.tree.move(item_id, parent, 'end')
                except Exception:
                    try:
                        self.tree.reattach(item_id, parent, 'end')
                    except Exception:
                        pass
            except Exception:
                pass
            return

        # Insert new item under parent; if that fails, fall back to root insertion
        try:
            self.tree.insert(parent, tk.END, iid=item_id, values=values)
        except Exception:
            try:
                # last-resort: insert at root so it won't crash
                self.tree.insert("", tk.END, iid=item_id, values=values)
            except Exception:
                pass

    def _apply_filter(self, *args):
        filter_term = self.filter_var.get().lower()

        # Reattach or detach items beneath their correct groups
        for ip, entry in list(self._entries.items()):
            item_id = ip
            combined = " ".join(str(v) for v in entry.values()).lower()
            visible = (filter_term in combined) if filter_term else True

            dtype = entry.get("device_type") or "Unknown"
            parent = self._ensure_group(dtype)

            if visible:
                # if item exists, move it under the correct parent and make sure it's attached
                if self.tree.exists(item_id):
                    try:
                        self.tree.move(item_id, parent, 'end')
                        self.tree.reattach(item_id, parent, 'end')
                    except Exception:
                        try:
                            self.tree.reattach(item_id, parent, 'end')
                        except Exception:
                            pass
                else:
                    # create it under parent if it wasn't present
                    values = (entry.get("ip",""), entry.get("hostname",""), entry.get("mac",""), entry.get("vendor",""))
                    try:
                        self.tree.insert(parent, tk.END, iid=item_id, values=values)
                    except Exception:
                        try:
                            self.tree.insert("", tk.END, iid=item_id, values=values)
                        except Exception:
                            pass
            else:
                # hide the item if it exists
                if self.tree.exists(item_id):
                    try:
                        self.tree.detach(item_id)
                    except Exception:
                        pass

        # Remove empty groups so you don't get floating category rows
        for dtype in list(self._group_order):
            pid = self._group_items.get(dtype)
            if not pid:
                # stale entry, remove from order
                if dtype in self._group_order:
                    try: self._group_order.remove(dtype)
                    except Exception: pass
                continue
            children = self.tree.get_children(pid)
            if not children:
                # delete the parent node and remove from maps
                try:
                    self.tree.delete(pid)
                except Exception:
                    pass
                self._group_items.pop(dtype, None)
                try:
                    self._group_order.remove(dtype)
                except Exception:
                    pass


    def _sortby(self, col, descending):
        """
        Sort items by column. If groups exist, sort children inside each group
        so groups remain intact and children reorder within their group.
        """
        def ip_key_for_sort(val):
            # val may be "wifi:xx..." or real IP; try to parse last dot-sep part as IPv4
            try:
                # if it's a wifi id, use the portion after the last colon for stable order
                if isinstance(val, str) and val.startswith("wifi:"):
                    key = val.split(":")[-1]
                    return key.lower()
                parts = val.split('.')
                if len(parts) == 4:
                    return [int(p) for p in parts]
                return val.lower()
            except Exception:
                return val.lower()

        # If we have groups, sort children within each group
        if hasattr(self, "_group_order") and self._group_order:
            for dtype in list(self._group_order):
                parent = self._group_items.get(dtype)
                if not parent or not self.tree.exists(parent):
                    continue
                children = list(self.tree.get_children(parent))
                data = []
                for child in children:
                    key = self.tree.set(child, col)
                    data.append((key, child))
                try:
                    if col == "ip":
                        data.sort(key=lambda t: ip_key_for_sort(t[0]), reverse=descending)
                    else:
                        data.sort(key=lambda t: (t[0] or "").lower(), reverse=descending)
                except Exception:
                    data.sort(reverse=descending)
                for index, (_, iid) in enumerate(data):
                    try:
                        self.tree.move(iid, parent, index)
                    except Exception:
                        pass
        else:
            # no groups: sort top-level children (root)
            data = [(self.tree.set(child, col), child) for child in self.tree.get_children('')]
            try:
                if col == "ip":
                    data.sort(key=lambda t: ip_key_for_sort(t[0]), reverse=descending)
                else:
                    data.sort(key=lambda t: (t[0] or "").lower(), reverse=descending)
            except Exception:
                data.sort(reverse=descending)
            for index, (val, iid) in enumerate(data):
                self.tree.move(iid, '', index)

        # toggle for next click
        self.tree.heading(col, command=lambda c=col: self._sortby(c, not descending))


    def _nmap_scan_selected(self):
        sel = self.tree.selection()
        if not sel: return
        ip = self.tree.item(sel[0])['values'][0]
        aggressive = self.nmap_aggressive_var.get()
        self._show_nmap_popup(ip, aggressive)

    def _show_nmap_popup(self, ip, aggressive):
        popup = tk.Toplevel(self)
        popup.title(f"Nmap Scan: {ip}")
        popup.geometry("700x500")
        
        txt_frame = ttk.Frame(popup, padding=5)
        txt_frame.pack(fill=tk.BOTH, expand=True)
        txt = tk.Text(txt_frame, wrap="word", state="disabled", bg="#fdfdfd")
        
        ysb = ttk.Scrollbar(txt_frame, orient='vertical', command=txt.yview)
        txt['yscrollcommand'] = ysb.set
        ysb.pack(side=tk.RIGHT, fill=tk.Y)
        txt.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        txt.configure(state="normal")
        txt.insert("end", f"Scanning {ip} with Nmap...\nThis may take several minutes.")
        txt.configure(state="disabled")

        def run_nmap_thread():
            out = nmap_scan_target(ip, aggressive=aggressive)
            def update_ui():
                txt.configure(state="normal")
                txt.delete("1.0", "end")
                txt.insert("1.0", out)
                txt.configure(state="disabled")
            self.after(0, update_ui)

        threading.Thread(target=run_nmap_thread, daemon=True).start()