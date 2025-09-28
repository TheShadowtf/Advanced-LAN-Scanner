#!/usr/bin/env python3
"""
Core network scanning logic for the Advanced LAN Scanner.

Added features:
- SSDP/UPnP discovery (ssdp_search)
- mDNS/Bonjour via zeroconf (mdns_scan) if zeroconf installed
- SNMP sysName/sysDescr (snmp_query_sys) if pysnmp installed
- Banner grabbing / HTTP title probing and simple heuristics for device_type
- Maintains compatibility with GUI: returns entries with ip, hostname, mac, vendor
"""

import platform
import re
import shutil
import socket
import subprocess
import threading
import time
import sys
import os
import urllib.request
import xml.etree.ElementTree as ET

from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils import get_mac_vendor

IS_WIN = platform.system().lower().startswith("win")

# Optional libs
try:
    from zeroconf import Zeroconf, ServiceBrowser, ServiceInfo
    _ZEROCONF_AVAILABLE = True
except Exception:
    _ZEROCONF_AVAILABLE = False

try:
    from pysnmp.hlapi import (
        SnmpEngine, CommunityData, UdpTransportTarget, ContextData, ObjectType, ObjectIdentity, getCmd
    )
    _PYSNMP_AVAILABLE = True
except Exception:
    _PYSNMP_AVAILABLE = False

# -------------------- Basic discovery helpers --------------------

def ping_host(ip):
    if IS_WIN:
        cmd = ["ping", "-n", "1", "-w", "1000", ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]
    try:
        res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return res.returncode == 0
    except Exception:
        return False

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

def read_arp_table():
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

def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        try:
            if IS_WIN:
                p = subprocess.run(["nbtstat", "-A", ip], capture_output=True, text=True, timeout=3)
                out = p.stdout
                m = re.search(r'^\s*([^<\r\n]+)\s+<..>\s+.+$', out, re.MULTILINE)
                if m:
                    name = m.group(1).strip()
                    if name:
                        return name
            else:
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

# -------------------- SSDP / UPnP discovery --------------------

def ssdp_search(timeout=2.0, mx=1):
    """
    Send SSDP M-SEARCH and return mapping ip -> list of response dicts
    """
    results = {}
    MCAST_ADDR = ("239.255.255.250", 1900)
    payload = "\r\n".join([
        'M-SEARCH * HTTP/1.1',
        'HOST: 239.255.255.250:1900',
        'MAN: "ssdp:discover"',
        f'MX: {mx}',
        'ST: ssdp:all',
        '', ''
    ]).encode('utf-8')

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.settimeout(timeout)
        sock.sendto(payload, MCAST_ADDR)
        start = time.time()
        while True:
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                break
            except Exception:
                break
            ip = addr[0]
            text = data.decode('utf-8', errors='ignore')
            headers = {}
            for line in text.splitlines()[1:]:
                line = line.strip()
                if not line:
                    continue
                parts = line.split(":", 1)
                if len(parts) == 2:
                    headers[parts[0].strip().upper()] = parts[1].strip()
            info = {
                "st": headers.get("ST", ""),
                "location": headers.get("LOCATION", ""),
                "server": headers.get("SERVER", ""),
                "usn": headers.get("USN", ""),
                "raw": text,
            }
            results.setdefault(ip, []).append(info)
            if time.time() - start > timeout:
                break
    finally:
        try:
            sock.close()
        except Exception:
            pass
    return results

def fetch_upnp_device_description(location_url, timeout=3.0):
    """
    Fetch the UPnP device description XML at location_url and parse manufacturer, modelName, friendlyName.
    Returns dict with keys: manufacturer, modelName, modelDescription, friendlyName, raw_xml (may be empty).
    Safe: uses urllib with timeout and fails silently on errors.
    """
    out = {"manufacturer": "", "modelName": "", "modelDescription": "", "friendlyName": "", "raw_xml": ""}
    if not location_url:
        return out
    try:
        # Enforce http/https only
        parsed = urlparse(location_url)
        if parsed.scheme not in ("http", "https"):
            return out
        req = urllib.request.Request(location_url, headers={"User-Agent": "scanner/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read()
            out["raw_xml"] = data.decode('utf-8', errors='ignore')
            try:
                root = ET.fromstring(data)
                # common tags can be nested; search by tag suffix
                def find_text(tag_names):
                    for t in tag_names:
                        # try any namespace variant by searching suffix
                        for node in root.iter():
                            if node.tag.lower().endswith(t.lower()):
                                if node.text:
                                    return node.text.strip()
                    return ""
                out["manufacturer"] = find_text(("manufacturer",))
                out["modelName"] = find_text(("modelName", "modelname"))
                out["modelDescription"] = find_text(("modelDescription", "modeldescription"))
                out["friendlyName"] = find_text(("friendlyName", "friendlyname"))
            except Exception:
                # parsing failed; keep raw_xml
                pass
    except Exception:
        # network/timeout or other error -> return empty fields
        pass
    return out


# -------------------- Wi-Fi nearby networks scan --------------------

def wifi_scan(timeout=5.0):
    """
    Cross-platform scan for nearby Wi-Fi networks.
    Returns a list of dicts:
    {
        "ssid": <str>,
        "bssid": <mac str>,
        "channel": <int or None>,
        "freq": <int MHz or None>,
        "signal": <int percent or RSSI int or None>,
        "security": <str>,
        "radio": <"2.4GHz"|"5GHz"|None>,
        # raw: raw parser output line (optional)
    }
    Notes:
    - Uses: Windows netsh, macOS airport, Linux nmcli or iwlist as available.
    - May require system tools to be installed / permissions on some platforms.
    """
    results = []

    try:
        plat = platform.system().lower()
        if plat.startswith("win"):
            # Windows: netsh wlan show networks mode=bssid
            try:
                p = subprocess.run(["netsh", "wlan", "show", "networks", "mode=bssid"],
                                   capture_output=True, text=True, timeout=timeout)
                out = p.stdout
                # netsh groups by SSID; multiple BSSID entries per SSID
                current_ssid = None
                ssid_re = re.compile(r"^SSID\s+\d+\s*:\s*(.+)$", re.IGNORECASE)
                bssid_re = re.compile(r"^\s*BSSID\s+\d+\s*:\s*([0-9A-Fa-f:-]{17})")
                signal_re = re.compile(r"^\s*Signal\s*:\s*(\d+)%")
                channel_re = re.compile(r"^\s*Channel\s*:\s*(\d+)")
                auth_re = re.compile(r"^\s*Authentication\s*:\s*(.+)$", re.IGNORECASE)
                enc_re = re.compile(r"^\s*Encryption\s*:\s*(.+)$", re.IGNORECASE)
                for line in out.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    m = ssid_re.match(line)
                    if m:
                        current_ssid = m.group(1).strip()
                        continue
                    m = bssid_re.match(line)
                    if m:
                        bssid = m.group(1).lower()
                        # defaults
                        entry = {"ssid": current_ssid or "", "bssid": bssid,
                                 "channel": None, "freq": None, "signal": None,
                                 "security": "", "radio": None, "raw": line}
                        results.append(entry)
                        continue
                    m = signal_re.match(line)
                    if m and results:
                        try:
                            results[-1]["signal"] = int(m.group(1))
                        except Exception:
                            pass
                        continue
                    m = channel_re.match(line)
                    if m and results:
                        try:
                            ch = int(m.group(1))
                            results[-1]["channel"] = ch
                            # crude band assignment: channels 1-14 -> 2.4GHz else 5GHz
                            results[-1]["radio"] = "2.4GHz" if ch <= 14 else "5GHz"
                        except Exception:
                            pass
                        continue
                    m = auth_re.match(line)
                    if m and results:
                        results[-1]["security"] = m.group(1).strip()
                        continue
                    m = enc_re.match(line)
                    if m and results and not results[-1].get("security"):
                        results[-1]["security"] = m.group(1).strip()
                return results
            except Exception:
                return []

        if plat == "darwin":
            # macOS: use airport utility
            airport_path = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
            if os.path.exists(airport_path):
                try:
                    p = subprocess.run([airport_path, "-s"], capture_output=True, text=True, timeout=timeout)
                    out = p.stdout
                    # columns: SSID BSSID RSSI CHANNEL HT CC SECURITY
                    # parse by splitting (SSID may contain spaces) — use regex:
                    # Each line: SSID<spaces>BSSID<spaces>RSSI<spaces>CHANNEL...
                    for line in out.splitlines()[1:]:
                        if not line.strip():
                            continue
                        # split by two or more spaces to separate SSID (which may contain single spaces)
                        cols = re.split(r"\s{2,}", line.strip())
                        if not cols:
                            continue
                        ssid = cols[0].strip()
                        bssid = ""
                        rssi = None
                        channel = None
                        security = ""
                        if len(cols) >= 2:
                            # second column often contains BSSID
                            parts = cols[1].split()
                            if parts:
                                bssid = parts[0]
                        # try to find RSSI and channel inside the rest
                        for c in cols[1:]:
                            m = re.search(r"(-?\d+)", c)
                            if m and rssi is None:
                                try:
                                    rssi = int(m.group(1))
                                except Exception:
                                    pass
                            mch = re.search(r"(\d+)(?:,|\b)", c)
                            if mch and channel is None:
                                try:
                                    channel = int(mch.group(1))
                                except Exception:
                                    pass
                        radio = None
                        if channel:
                            radio = "2.4GHz" if channel <= 14 else "5GHz"
                        results.append({"ssid": ssid, "bssid": bssid.lower(), "channel": channel,
                                        "freq": None, "signal": rssi, "security": security,
                                        "radio": radio, "raw": line})
                    return results
                except Exception:
                    return []
            return []

        # Assume Linux or other Unix-like
        # First try nmcli (NetworkManager)
        try:
            if shutil.which("nmcli"):
                # columns: SSID,BSSID,FREQ,SIGNAL,CHAN,SECURITY
                p = subprocess.run(["nmcli", "-f", "SSID,BSSID,FREQ,SIGNAL,CHAN,SECURITY", "device", "wifi", "list"],
                                   capture_output=True, text=True, timeout=timeout)
                out = p.stdout
                # nmcli outputs a header line; parse splitting by multiple spaces
                for line in out.splitlines()[1:]:
                    if not line.strip():
                        continue
                    cols = re.split(r"\s{2,}", line.strip())
                    # attempt mapping columns
                    ssid = cols[0].strip() if len(cols) > 0 else ""
                    bssid = cols[1].strip().lower() if len(cols) > 1 else ""
                    freq = None
                    signal = None
                    channel = None
                    security = ""
                    if len(cols) > 2:
                        try:
                            freq = int(cols[2])
                        except Exception:
                            pass
                    if len(cols) > 3:
                        try:
                            signal = int(cols[3])
                        except Exception:
                            pass
                    if len(cols) > 4:
                        try:
                            channel = int(cols[4])
                        except Exception:
                            pass
                    if len(cols) > 5:
                        security = cols[5].strip()
                    radio = None
                    if channel:
                        radio = "2.4GHz" if channel <= 14 else "5GHz"
                    elif freq:
                        radio = "2.4GHz" if freq < 5000 else "5GHz"
                    results.append({"ssid": ssid, "bssid": bssid, "channel": channel,
                                    "freq": freq, "signal": signal, "security": security,
                                    "radio": radio, "raw": line})
                if results:
                    return results
        except Exception:
            pass

        # Fallback: try iwlist (may require root)
        if shutil.which("iwlist"):
            # pick common interface names (user may need to adapt)
            ifaces = []
            try:
                # try `iw dev` to list interfaces
                p = subprocess.run(["iw", "dev"], capture_output=True, text=True, timeout=1)
                for l in p.stdout.splitlines():
                    l = l.strip()
                    m = re.match(r"Interface\s+(\w+)", l)
                    if m:
                        ifaces.append(m.group(1))
            except Exception:
                pass
            if not ifaces:
                # fallback guess
                ifaces = ["wlan0", "wlp2s0", "wlan1"]
            for iface in ifaces:
                try:
                    p = subprocess.run(["iwlist", iface, "scanning"], capture_output=True, text=True, timeout=timeout)
                    out = p.stdout
                    # parse blocks per Cell
                    cells = re.split(r"Cell \d+ - ", out)[1:]
                    for cell in cells:
                        ssid = ""
                        bssid = ""
                        channel = None
                        freq = None
                        signal = None
                        security = ""
                        m = re.search(r"ESSID:\"([^\"]*)\"", cell)
                        if m:
                            ssid = m.group(1)
                        m = re.search(r"Address:\s*([0-9A-Fa-f:]{17})", cell)
                        if m:
                            bssid = m.group(1).lower()
                        m = re.search(r"Channel:(\d+)", cell)
                        if m:
                            try:
                                channel = int(m.group(1))
                            except Exception:
                                pass
                        m = re.search(r"Frequency:(\d+\.\d+)\s*GHz", cell)
                        if m:
                            try:
                                freq = int(float(m.group(1)) * 1000)
                            except Exception:
                                pass
                        m = re.search(r"Signal level[=:]\s*(-?\d+)", cell)
                        if m:
                            try:
                                signal = int(m.group(1))
                            except Exception:
                                pass
                        # security detection (basic)
                        if "Encryption key:off" in cell or "Key:off" in cell:
                            security = "Open"
                        else:
                            if "IE: IEEE 802.11i/WPA2" in cell or "WPA2" in cell:
                                security = "WPA2"
                            elif "WPA" in cell:
                                security = "WPA"
                            elif "WEP" in cell:
                                security = "WEP"
                        radio = None
                        if channel:
                            radio = "2.4GHz" if channel <= 14 else "5GHz"
                        elif freq:
                            radio = "2.4GHz" if freq < 5000 else "5GHz"
                        results.append({"ssid": ssid, "bssid": bssid, "channel": channel,
                                        "freq": freq, "signal": signal, "security": security,
                                        "radio": radio, "raw": cell.strip()})
                    if results:
                        return results
                except Exception:
                    continue

    except Exception:
        pass

    # final: return whatever parsed or empty
    return results

# -------------------- mDNS / Zeroconf discovery --------------------

class _MDNSListener:
    def __init__(self):
        self.lock = threading.Lock()
        self.services = {}

    def remove_service(self, zeroconf, type, name):
        # optional: remove service from dictionary if desired
        try:
            with self.lock:
                if name in self.services:
                    del self.services[name]
        except Exception:
            pass

    def add_service(self, zeroconf, type, name):
        try:
            info = zeroconf.get_service_info(type, name, timeout=2000)
            if info:
                with self.lock:
                    self.services[name] = info
        except Exception:
            pass

    def update_service(self, zeroconf, type, name):
        # Called when a service is updated; we'll re-fetch and overwrite.
        try:
            info = zeroconf.get_service_info(type, name, timeout=2000)
            if info:
                with self.lock:
                    self.services[name] = info
        except Exception:
            pass


def mdns_scan(timeout=2.0, service_types=None):
    """
    Browse common mDNS service types for timeout seconds.
    Returns mapping ip -> list of discovered service dicts.
    """
    if not _ZEROCONF_AVAILABLE:
        return {}

    if service_types is None:
        service_types = [
            "_http._tcp.local.",
            "_workstation._tcp.local.",
            "_ipp._tcp.local.",
            "_printer._tcp.local.",
            "_ssh._tcp.local.",
            "_smb._tcp.local.",
            "_airplay._tcp.local.",
            "_raop._tcp.local."
        ]
    zer = Zeroconf()
    listener = _MDNSListener()
    browsers = []
    try:
        for st in service_types:
            browsers.append(ServiceBrowser(zer, st, listener))
        time.sleep(timeout)
        mapping = {}
        with listener.lock:
            for name, info in listener.services.items():
                addrs = []
                for raw in info.addresses:
                    try:
                        if len(raw) == 4:
                            addrs.append(socket.inet_ntop(socket.AF_INET, raw))
                        elif len(raw) == 16:
                            addrs.append(socket.inet_ntop(socket.AF_INET6, raw))
                    except Exception:
                        pass
                desc = {
                    "name": name,
                    "server": info.server,
                    "addresses": addrs,
                    "port": info.port,
                    "properties": {k.decode('utf-8', errors='ignore') if isinstance(k, bytes) else k:
                                   (v.decode('utf-8', errors='ignore') if isinstance(v, bytes) else v)
                                   for k, v in info.properties.items()}
                }
                for a in addrs:
                    mapping.setdefault(a, []).append(desc)
        return mapping
    finally:
        try:
            zer.close()
        except Exception:
            pass

# -------------------- SNMP sysName/sysDescr --------------------

def snmp_query_sys(ip, community='public', timeout=1, retries=0):
    """
    Return dict with sysName and sysDescr if available. Requires pysnmp.
    """
    if not _PYSNMP_AVAILABLE:
        return {}
    result = {}
    try:
        iterator = getCmd(
            SnmpEngine(),
            CommunityData(community, mpModel=0),
            UdpTransportTarget((ip, 161), timeout=timeout, retries=retries),
            ContextData(),
            ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysName', 0)),
            ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0))
        )
        errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
        if errorIndication:
            return {}
        if errorStatus:
            return {}
        for oid, val in varBinds:
            # use the last piece of OID as key (sysName/sysDescr)
            name = str(oid).split("::")[-1]
            result[name] = str(val)
    except Exception:
        return {}
    return result

# -------------------- UDP probing (new) --------------------

def udp_probe_ports(ip, ports=(137,161,1900,5353), timeout=0.8):
    """
    Send tiny UDP probes to common UDP ports and listen for replies.
    Returns dict port -> decoded response (if any).
    Note: UDP is connectionless; many devices won't reply unless they expect the probe.
    """
    results = {}
    # create one socket per target to avoid interference on some platforms
    for p in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            # small probe - for some ports an empty packet elicits a response,
            # for SNMP we could send a small GET with no auth but that's more complex.
            # We'll use a single zero byte; if more advanced behavior is desired we can special-case SNMP/NBNS.
            try:
                sock.sendto(b'\x00', (ip, int(p)))
            except Exception:
                # sometimes sending fails (e.g., ICMP unreachable), continue
                sock.close()
                continue
            try:
                data, _ = sock.recvfrom(4096)
                if data:
                    try:
                        txt = data.decode('utf-8', errors='ignore')
                    except Exception:
                        txt = repr(data[:200])
                    results[int(p)] = txt
            except Exception:
                # no reply or timeout
                pass
            try:
                sock.close()
            except Exception:
                pass
        except Exception:
            pass
    return results


# -------------------- Banner probing / HTTP title --------------------

def parse_http_title(data):
    try:
        m = re.search(r'<title[^>]*>(.*?)</title>', data, re.I | re.S)
        if m:
            return m.group(1).strip()
    except Exception:
        pass
    return None

def probe_port_banner(ip, port, timeout=1.0):
    banners = ""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, int(port)))
        if port in (80, 8080, 8000):
            try:
                sock.sendall(b"GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: scanner/1.0\r\nConnection: close\r\n\r\n" % ip.encode())
            except Exception:
                pass
            data = b""
            try:
                data = sock.recv(4096)
            except Exception:
                pass
            text = data.decode('utf-8', errors='ignore')
            title = parse_http_title(text)
            if title:
                banners = f"HTTP title: {title}"
            else:
                m = re.search(r'(?m)^Server:\s*(.+)$', text)
                if m:
                    banners = f"Server: {m.group(1).strip()}"
                else:
                    banners = text[:200].strip()
        elif port in (443, 8443):
            try:
                import ssl
                ss = ssl.create_default_context()
                ss.check_hostname = False
                ss.verify_mode = ssl.CERT_NONE
                ssock = ss.wrap_socket(sock, server_hostname=ip)
                try:
                    ssock.sendall(b"GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: scanner/1.0\r\nConnection: close\r\n\r\n" % ip.encode())
                    data = ssock.recv(4096)
                    text = data.decode('utf-8', errors='ignore')
                    title = parse_http_title(text)
                    if title:
                        banners = f"HTTPS title: {title}"
                    else:
                        m = re.search(r'(?m)^Server:\s*(.+)$', text)
                        if m:
                            banners = f"Server: {m.group(1).strip()}"
                        else:
                            banners = text[:200].strip()
                except Exception:
                    banners = ""
                try:
                    ssock.close()
                except Exception:
                    pass
            except Exception:
                banners = ""
        elif port == 22:
            try:
                data = sock.recv(256)
                banners = data.decode('utf-8', errors='ignore').strip()
            except Exception:
                banners = ""
        else:
            try:
                data = sock.recv(256)
                banners = data.decode('utf-8', errors='ignore').strip()
            except Exception:
                banners = ""
        try:
            sock.close()
        except Exception:
            pass
    except Exception:
        banners = ""
    return banners

def probe_common_ports(ip, ports=(22,23,80,443,139,445,161,1900,5353), timeout=0.9, max_workers=30):
    results = {}
    with ThreadPoolExecutor(max_workers=min(max_workers, len(ports))) as ex:
        futs = {ex.submit(probe_port_banner, ip, p, timeout): p for p in ports}
        for fut in as_completed(futs):
            p = futs[fut]
            try:
                b = fut.result()
            except Exception:
                b = ""
            if b:
                results[p] = b
    return results

# -------------------- Basic heuristics for device type --------------------

def heuristics_device_type(ip,
                           banners,
                           snmp_info=None,
                           mdns_info=None,
                           ssdp_info=None,
                           hostname=None,
                           udp_info=None,
                           vendor=None):
    """
    Improved device type heuristics.
    Checks (in roughly this priority):
      - SNMP sysDescr/sysName
      - mDNS service types/properties (Zeroconf)
      - SSDP server/ST/LOCATION headers
      - TCP service banners (http titles/server, ssh, smbs)
      - UDP probes (NBNS / SNMP replies)
      - Hostname patterns
      - MAC vendor lookup
    Returns a short label like "Router", "Printer", "Windows host", "Android device",
    "Amazon Fire TV", "Chromecast", "Roku", "Smart TV", "NAS", "IP Camera", etc.
    """
    snmp_info = snmp_info or {}
    mdns_info = mdns_info or []
    ssdp_info = ssdp_info or []
    udp_info = udp_info or {}
    hostname_l = (hostname or "").lower()
    vendor_l = (vendor or "").lower()
    banners = banners or {}
    btext = " ".join(str(v) for v in banners.values()).lower()

    # Helper
    def any_in(s, needles):
        return any(n in s for n in needles)

    # 1) SNMP strong clues
    if snmp_info:
        s = " ".join(snmp_info.values()).lower()
        if any_in(s, ("mikrotik", "cisco", "edgeos", "ubnt", "ubiquiti", "asuswrt", "netgear", "tplink")):
            return "Router"
        if any_in(s, ("printer", "hp", "epson", "canon", "ricoh")):
            return "Printer"
        if any_in(s, ("camera", "ipcamera", "axis", "hikvision", "dahua")):
            return "IP Camera"
        if any_in(s, ("nas", "synology", "qnap", "netapp")):
            return "NAS"

    # 2) mDNS/zeroconf clues (very useful)
    if mdns_info:
        for rec in mdns_info:
            name = (rec.get("name") or "").lower()
            props = " ".join(str(v).lower() for v in rec.get("properties", {}).values())
            # Chromecast / Google Cast
            if "_googlecast" in name or "_googlecast" in props or "_googlezone" in props:
                return "Chromecast / Google Cast"
            # Apple / AirPlay / Apple TV
            if "_airplay" in name or "_raop" in name or "apple-tv" in name or "appletv" in name:
                return "Apple TV / AirPlay"
            # Printers
            if "_ipp" in name or "_printer" in name or "printer" in props:
                return "Printer"
            # Smart TV / Media
            if any_in(name + props, ("roku", "lg", "samsung", "webos", "tizen", "sony", "vizio")):
                return "Smart TV"
            # NAS / file sharing services
            if any_in(name + props, ("smb", "samba", "afp", "nfs", "synology", "qnap")):
                return "NAS"
            # IP camera
            if any_in(name + props, ("rtsp", "camera", "ipcamera", "onvif")):
                return "IP Camera"
            # SSH / device
            if "_ssh" in name or "_workstation" in name:
                return "Device (ssh)"

    # 3) SSDP/UPnP headers (server/st/location)
    if ssdp_info:
        for infos in ssdp_info:
            for i in infos:
                st = (i.get("st") or "").lower()
                server = (i.get("server") or "").lower()
                loc = (i.get("location") or "").lower()
                # Roku
                if "roku" in server or "roku" in st or "roku" in loc:
                    return "Roku"
                # Amazon / Fire TV
                if "amazon" in server or "firetv" in server or "aft" in server or "amazon" in st:
                    return "Amazon Fire TV"
                # Chromecast / Google
                if "googlecast" in server or "chromecast" in server or "google" in server:
                    return "Chromecast / Google Cast"
                # Tizen / WebOS / Samsung / LG
                if any_in(server + st + loc, ("tizen", "webos", "samsung", "lg", "vizio", "netcast")):
                    return "Smart TV"
                # DLNA media servers (Plex etc)
                if "mediaserver" in st or "dlna" in server:
                    return "Media Server / TV"
                # Printers
                if "printer" in server or "ipp" in st or "printer" in loc:
                    return "Printer"

    # 4) TCP banner clues (HTTP title/Server, SSH, RTSP, SMB)
    if btext:
        # Gaming consoles
        if any_in(btext, ("playstation", "ps4", "ps5", "sony")):
            return "PlayStation"
        if any_in(btext, ("xbox", "xboxone", "xbox360")):
            return "Xbox"
        # Roku/Fire/Chromecast hints in HTTP
        if any_in(btext, ("roku", "roku-device", "roku/v")):
            return "Roku"
        if any_in(btext, ("amazon fire", "firetv", "aft", "amazon")):
            return "Amazon Fire TV"
        if any_in(btext, ("googlecast", "chromecast", "gcast", "cast")):
            return "Chromecast / Google Cast"
        # Plex/Kodi/media servers
        if any_in(btext, ("plex", "kodi", "mediaserver")):
            return "Media Server / TV"
        # Smart TV platforms
        if any_in(btext, ("webos", "tizen", "smarttv", "lgwebos", "samsung")):
            return "Smart TV"
        # IP camera / rtsp
        if any_in(btext, ("rtsp", "ipcamera", "axis", "hikvision", "dahua", "onvif")):
            return "IP Camera"
        # Printers
        if any_in(btext, ("hp jetdirect", "printer", "cups", "ipp", "printerserver")):
            return "Printer"
        # NAS vendors
        if any_in(btext, ("synology", "qnap", "nas", "networkattached")):
            return "NAS"
        # SMB/Windows clues
        if any_in(btext, ("microsoft", "microsoft-iis", "iis/", "microsoft-httpapi", "netbios", "samba")):
            # Samba indicates Linux/embedded device offering SMB; keep as NAS/Server when samba present
            if "samba" in btext:
                return "NAS/Server"
            return "Windows host"
        # SSH banner -> linux / unix host
        if "openssh" in btext or "ssh-" in btext:
            # many routers also expose ssh; but default to Linux host
            return "Linux host"
        # Android / embedded linux
        if any_in(btext, ("android", "android-")):
            return "Android device"
        # Apple devices (HTTP server strings)
        if any_in(btext, ("apple", "airplay", "darwin", "mac os x")):
            return "Apple device"

    # 5) UDP clues (NBNS: Windows; SNMP sysdescr: router)
    try:
        if 137 in udp_info:
            ud = (udp_info[137] or "").lower()
            if any_in(ud, ("microsoft", "workstation", "netbios", "windows")):
                return "Windows host"
        if 161 in udp_info:
            ud = (udp_info[161] or "").lower()
            if any_in(ud, ("router", "mikrotik", "cisco", "edgeos", "ubnt")):
                return "Router"
    except Exception:
        pass

    # 6) Hostname heuristics
    if hostname_l:
        if any_in(hostname_l, ("android", "galaxy", "pixel", "mi-", "oneplus", "redmi", "phone")):
            return "Android device"
        if any_in(hostname_l, ("iphone", "ipad", "macbook", "imac", "macmini")):
            return "Apple device"
        if any_in(hostname_l, ("playstation", "ps4", "ps5", "ps3", "ps")):
            return "PlayStation"
        if any_in(hostname_l, ("xbox", "xboxone", "xbox360")):
            return "Xbox"
        if any_in(hostname_l, ("roku", "firetv", "firestick", "chromecast")):
            # hostname sometimes contains device model
            if "fire" in hostname_l or "amazon" in hostname_l:
                return "Amazon Fire TV"
            if "roku" in hostname_l:
                return "Roku"
            if "chromecast" in hostname_l or "google" in hostname_l:
                return "Chromecast / Google Cast"
        if any_in(hostname_l, ("printer", "hp", "epson", "canon")):
            return "Printer"
        if any_in(hostname_l, ("nas", "synology", "qnap")):
            return "NAS"
        if any_in(hostname_l, ("router", "gateway")):
            return "Router"
        if any_in(hostname_l, ("desktop", "laptop", "pc", "workstation")):
            # Windows hosts often named DESKTOP-XXXX
            if any_in(hostname_l, ("desktop-", "laptop-", "pc-")) or hostname_l.isupper():
                return "Windows host"
            return "PC/Workstation"

    # 7) MAC vendor heuristics (best-effort)
    if vendor_l:
        if any_in(vendor_l, ("amazon", "amazon technologies")):
            return "Amazon Fire TV"
        if any_in(vendor_l, ("roku")):
            return "Roku"
        if any_in(vendor_l, ("samsung", "lg electronics", "lg")):
            return "Smart TV"
        if any_in(vendor_l, ("google", "google inc", "google llc")):
            return "Chromecast / Google Cast"
        if any_in(vendor_l, ("apple")):
            return "Apple device"
        if any_in(vendor_l, ("huawei", "xiaomi", "xiaomi communications", "zte")):
            return "Android device"
        if any_in(vendor_l, ("d-link", "dlink", "netgear", "tp-link", "asus", "cisco")):
            return "Router"
        if any_in(vendor_l, ("synology", "qnap", "netapp", "seagate")):
            return "NAS"
        if any_in(vendor_l, ("axis communications", "hikvision", "dahua")):
            return "IP Camera"

    # 8) Fallback: common open ports -> server/host
    if banners and any(p in banners for p in (22, 80, 443, 8080, 8000, 8008, 8009, 554, 32400)):
        return "Server/Host"

    # final fallback
    return "Unknown"

# -------------------- AdvancedScanner --------------------

class AdvancedScanner:
    def __init__(self, targets, max_workers=200, allow_online_vendor=False,
                 allow_mdns=True, allow_ssdp=True, allow_snmp=False, do_fingerprints=True):
        """
        targets: list of IP strings
        """
        self.targets = targets
        self.max_workers = max_workers
        self.allow_online_vendor = allow_online_vendor
        self.allow_mdns = allow_mdns
        self.allow_ssdp = allow_ssdp
        self.allow_snmp = allow_snmp
        self.do_fingerprints = do_fingerprints
        self.results = []
        self._cancel = threading.Event()

    def cancel(self):
        self._cancel.set()

    def run(self, progress_callback=None, live_callback=None):
        """
        Full scan pipeline:
        1) ping sweep (concurrent) -> gather list of alive IPs
        2) read ARP table for MACs
        3) SSDP (ssdp_search) and mDNS (mdns_scan) discovery
        4) fetch UPnP device-description XMLs for SSDP LOCATIONs (upnp_map)
        5) per-alive worker tasks (hostname, MAC/vendor, optional SNMP, banner probing,
            UDP probing, heuristics). Results are pushed to live_callback as they arrive.
        """
        self.results = []
        total = len(self.targets)
        alive = []

        # 1) Ping sweep
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
                    try:
                        progress_callback(done, total)
                    except Exception:
                        pass

        if self._cancel.is_set():
            return []

        # 2) Read ARP table for MACs
        arp = read_arp_table()

        # 3) Global SSDP & mDNS discovery (to supplement host info)
        ssdp_map = {}
        mdns_map = {}
        if self.allow_ssdp:
            try:
                ssdp_map = ssdp_search(timeout=2.0)
            except Exception:
                ssdp_map = {}
        if self.allow_mdns:
            try:
                mdns_map = mdns_scan(timeout=2.0)
            except Exception:
                mdns_map = {}

        # 3a) UPnP device-description fetch (follow LOCATION URLs returned by SSDP)
        upnp_map = {}
        if ssdp_map:
            try:
                # limit concurrent fetches to avoid network flood
                with ThreadPoolExecutor(max_workers=16) as upnp_ex:
                    fut_to_ip = {}
                    for ip, infos in ssdp_map.items():
                        for info in infos:
                            # support both uppercase and lowercase keys
                            loc = info.get("location") or info.get("LOCATION") or ""
                            if not loc:
                                continue
                            fut = upnp_ex.submit(fetch_upnp_device_description, loc, 3.0)
                            fut_to_ip[fut] = ip
                    for fut in as_completed(fut_to_ip):
                        ip = fut_to_ip[fut]
                        try:
                            desc = fut.result()
                        except Exception:
                            desc = {"manufacturer":"", "modelName":"", "modelDescription":"", "friendlyName":"", "raw_xml":""}
                        if desc:
                            upnp_map.setdefault(ip, []).append(desc)
            except Exception:
                upnp_map = {}
        else:
            upnp_map = {}

        # 4) Per-alive worker builder
        results = []

        def worker(ip):
            """
            Worker that runs per-alive IP to collect hostname, MAC/vendor, banners, UDP probes,
            optional SNMP, UPnP info, and decide device_type via heuristics.
            Returns an entry dict compatible with the GUI.
            """
            if self._cancel.is_set():
                return None

            # 1) Hostname resolution (reverse DNS + NetBIOS fallback inside resolve_hostname)
            try:
                hostname = resolve_hostname(ip) or ""
            except Exception:
                hostname = ""

            # 2) MAC & vendor (arp map and util)
            mac = arp.get(ip, "")
            vendor = ""
            try:
                if mac:
                    vendor = get_mac_vendor(mac, allow_online=self.allow_online_vendor)
            except Exception:
                vendor = ""

            # Base entry structure (keeps compatibility with GUI)
            entry = {
                "ip": ip,
                "alive": True,
                "hostname": hostname,    # may be overridden by SNMP below
                "mac": mac,
                "vendor": vendor,
                # extended fields
                "product": "",           # friendly product/model name (from UPnP / SNMP / HTTP)
                "manufacturer": "",
                "device_type": "",
                "open_ports": [],
                "banners": {},
                "mdns": mdns_map.get(ip, []),
                "ssdp": ssdp_map.get(ip, []),
                "upnp": upnp_map.get(ip, []),
                "snmp": {},
                "udp": {}
            }

            # If fingerprinting disabled, still try to attach UPnP/SNMP basic info then return minimal entry
            if not self.do_fingerprints:
                # prefer UPnP info if available
                try:
                    ups = entry.get("upnp", [])
                    if ups:
                        for d in ups:
                            manu = (d.get("manufacturer") or "").strip()
                            model = (d.get("modelName") or "").strip()
                            friendly = (d.get("friendlyName") or "").strip()
                            if friendly and not entry["product"]:
                                entry["product"] = friendly
                            if model and not entry["product"]:
                                entry["product"] = model
                            if manu and not entry["manufacturer"]:
                                entry["manufacturer"] = manu
                            if entry["product"] and entry["manufacturer"]:
                                break
                except Exception:
                    pass

                # try SNMP if allowed (may provide sysName/sysDescr)
                if self.allow_snmp and _PYSNMP_AVAILABLE:
                    try:
                        s = snmp_query_sys(ip, community='public', timeout=1, retries=0)
                        if s:
                            entry["snmp"] = s
                            sysname = s.get("sysName") or s.get("sysname") or ""
                            sysdescr = s.get("sysDescr") or s.get("sysdescr") or ""
                            if sysname:
                                entry["hostname"] = sysname
                            if sysdescr and not entry["product"]:
                                entry["product"] = sysdescr
                    except Exception:
                        pass

                return entry

            # 3) Banner probing on common TCP ports (concurrent)
            try:
                common_ports = (
                    22, 23, 80, 443, 139, 445, 161, 1900, 5353,
                    554,        # RTSP (IP cameras, media devices)
                    8000, 8008, 8009, 8080,  # common device HTTP ports (Chromecast/Android)
                    32400      # Plex Media Server
                )
                banners = probe_common_ports(ip, ports=common_ports, timeout=0.9, max_workers=40)
                entry["banners"] = banners or {}
                entry["open_ports"] = sorted(list(banners.keys()))
            except Exception:
                entry["banners"] = {}
                entry["open_ports"] = []

            # 4) UDP probes (NBNS, SNMP, SSDP/mDNS extras)
            try:
                udp_info = udp_probe_ports(ip, ports=(137, 161, 1900, 5353), timeout=0.8)
                entry["udp"] = udp_info or {}
            except Exception:
                entry["udp"] = {}

            # 5) SNMP (try community 'public' if allowed and pysnmp present)
            if self.allow_snmp:
                try:
                    if _PYSNMP_AVAILABLE:
                        s = snmp_query_sys(ip, community='public', timeout=1, retries=0)
                        if s:
                            entry["snmp"] = s
                            # prefer SNMP sysName as hostname if available
                            sysname = s.get("sysName") or s.get("sysname") or ""
                            sysdescr = s.get("sysDescr") or s.get("sysdescr") or ""
                            if sysname:
                                entry["hostname"] = sysname
                            if sysdescr and not entry["product"]:
                                entry["product"] = sysdescr
                except Exception:
                    entry["snmp"] = {}

            # 5a) Prefer UPnP friendlyName / modelName as product/manufacturer if present
            try:
                ups = entry.get("upnp", [])
                if ups:
                    for d in ups:
                        manu = (d.get("manufacturer") or "").strip()
                        model = (d.get("modelName") or "").strip()
                        friendly = (d.get("friendlyName") or "").strip()
                        if friendly and not entry["product"]:
                            entry["product"] = friendly
                        if model and not entry["product"]:
                            entry["product"] = model
                        if manu and not entry["manufacturer"]:
                            entry["manufacturer"] = manu
                        if entry["product"] and entry["manufacturer"]:
                            break
            except Exception:
                pass

            # 6) Device heuristics: combine banners, mdns, ssdp, snmp, udp, hostname, vendor
            try:
                entry["device_type"] = heuristics_device_type(
                    ip,
                    entry.get("banners", {}),
                    snmp_info=entry.get("snmp", {}),
                    mdns_info=entry.get("mdns", []),
                    ssdp_info=entry.get("ssdp", []),
                    hostname=entry.get("hostname", ""),
                    udp_info=entry.get("udp", {}),
                    vendor=vendor
                )
            except Exception:
                entry["device_type"] = "Unknown"

            return entry

        # 5) Run worker tasks concurrently for alive hosts
        if self._cancel.is_set():
            return []

        with ThreadPoolExecutor(max_workers=min(self.max_workers, max(4, len(alive)))) as ex:
            futs = {ex.submit(worker, ip): ip for ip in alive}
            for fut in as_completed(futs):
                if self._cancel.is_set():
                    break
                ip = futs[fut]
                try:
                    ent = fut.result()
                except Exception:
                    ent = None
                if ent:
                    results.append(ent)
                    if live_callback:
                        try:
                            live_callback(ent)
                        except Exception:
                            pass

        # sort results (safe for non-IPv4 ids; fall back to string)
        try:
            results.sort(key=lambda r: tuple(int(x) for x in r['ip'].split('.')))
        except Exception:
            results.sort(key=lambda r: r.get('ip', ''))

        self.results = results
        return results


        with ThreadPoolExecutor(max_workers=min(self.max_workers, max(4, len(alive)))) as ex:
            futs = {ex.submit(worker, ip): ip for ip in alive}
            for fut in as_completed(futs):
                if self._cancel.is_set():
                    break
                ip = futs[fut]
                try:
                    ent = fut.result()
                except Exception:
                    ent = None
                if ent:
                    results.append(ent)
                    if live_callback:
                        try:
                            live_callback(ent)
                        except Exception:
                            pass

        results.sort(key=lambda r: tuple(int(x) for x in r['ip'].split('.')))
        self.results = results
        return results
