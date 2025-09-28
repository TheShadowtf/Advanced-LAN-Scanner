#!/usr/bin/env python3
"""
Utility functions for the Advanced LAN Scanner.

Features:
- MAC vendor lookup using:
    * per-MAC runtime cache (mac_cache.json)
    * local oui.csv (user-provided)
    * local IEEE oui.txt cache (downloaded if allowed)
    * online API fallback (api.macvendors.com) when allowed
- Target parsing utilities (CIDR, ranges, wildcard, file://)
- Local subnet detection helper
"""

import os
import json
import re
import socket
import ipaddress
import urllib.request
import urllib.parse
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# -------------------- Config / files --------------------
MAC_CACHE_FILE = os.path.join(SCRIPT_DIR, "mac_cache.json")
# Optional: user can place 'oui.csv' in same folder with rows: OUI_PREFIX,Vendor Name
LOCAL_OUI_CSV = os.path.join(SCRIPT_DIR, "oui.csv")
# Local cached IEEE OUI file (downloaded when allowed)
OUI_TXT_FILE = os.path.join(SCRIPT_DIR, "oui.txt")

# -------------------- In-memory OUI map --------------------
_OUI_MAP = {}      # prefix -> vendor (prefix format: aa:bb:cc)
_OUI_LOADED = False

# -------------------- MAC cache helpers --------------------

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

# -------------------- MAC utilities --------------------

def mac_normalize(mac):
    if not mac:
        return ""
    mac = str(mac).strip().lower()
    mac = mac.replace('-', ':')
    mac = mac.replace('.', '')  # remove dot-style if present
    # If dot-style like aabb.ccdd.eeff -> reformat
    if len(mac) == 12:
        # already cleaned to hex digits
        mac = ':'.join([mac[i:i+2] for i in range(0, 12, 2)])
    # ensure canonical colon-separated if possible
    parts = [p for p in mac.split(':') if p != '']
    if len(parts) == 6:
        parts = [p.zfill(2) for p in parts]
        return ':'.join(parts)
    # fallback: return cleaned string
    return mac

def mac_prefix(mac, length=3):
    """
    Return prefix of MAC in colon-separated form (default first 3 bytes aa:bb:cc)
    """
    mac = mac_normalize(mac)
    parts = mac.split(':')
    if len(parts) >= length:
        return ':'.join(parts[:length])
    # if not colon format, try to slice raw string
    s = re.sub(r'[^0-9a-f]', '', mac).lower()
    if len(s) >= length * 2:
        return ':'.join([s[i:i+2] for i in range(0, length * 2, 2)])
    return mac

# -------------------- Local OUI CSV lookup (user-provided) --------------------

def lookup_local_oui(mac):
    """
    Lookup vendor in LOCAL_OUI_CSV if present.
    CSV format: PREFIX,Vendor Name
    PREFIX may be 'aa:bb:cc' or 'aabbcc' or 'aa-bb-cc'
    """
    if not os.path.exists(LOCAL_OUI_CSV):
        return None
    try:
        pref = mac_prefix(mac)
        with open(LOCAL_OUI_CSV, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                parts = [p.strip() for p in line.split(',', 1)]
                if not parts:
                    continue
                key = parts[0].lower().replace('-', ':')
                if len(key) == 6:
                    key = ':'.join([key[i:i+2] for i in range(0, 6, 2)])
                vendor = parts[1] if len(parts) > 1 else ""
                if key == pref:
                    return vendor
    except Exception:
        pass
    return None

# -------------------- Online API fallback --------------------

def lookup_mac_online(mac):
    """
    Query a public MAC vendor API as a last resort. May be rate-limited.
    """
    try:
        api_url = f"https://api.macvendors.com/{urllib.parse.quote(mac)}"
        with urllib.request.urlopen(api_url, timeout=6) as resp:
            text = resp.read().decode('utf-8', errors='ignore').strip()
            if text:
                return text
    except Exception:
        return None
    return None

# -------------------- OUI parsing & loader --------------------

def _parse_oui_text(text):
    """
    Parse various OUI listing formats into { 'aa:bb:cc': 'Vendor' }.
    Handles IEEE oui.txt lines like:
      00-00-00   (hex)        XEROX CORPORATION
    and other common formats.
    """
    mapping = {}
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        # IEEE style: "00-00-00   (hex)        XEROX CORPORATION"
        m = re.match(r'^([0-9A-Fa-f]{2}(?:[-:][0-9A-Fa-f]{2}){2})\s+\(hex\)\s+(.+)$', line)
        if m:
            prefix = m.group(1).lower().replace('-', ':')
            mapping[prefix] = m.group(2).strip()
            continue
        # Alternative: "000000 (hex) VENDOR"
        m2 = re.match(r'^([0-9A-Fa-f]{6})\s+\(hex\)\s+(.+)$', line)
        if m2:
            p = m2.group(1).lower()
            prefix = ':'.join([p[i:i+2] for i in range(0, 6, 2)])
            mapping[prefix] = m2.group(2).strip()
            continue
        # Simple "00:11:22 Vendor" or "00-11-22 Vendor"
        m3 = re.match(r'^([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})\s+(.+)$', line)
        if m3:
            prefix = m3.group(1).lower().replace('-', ':')
            mapping[prefix] = m3.group(2).strip()
            continue
    return mapping

def load_oui_cache(allow_online=False, refresh=False):
    """
    Load the OUI map into memory. If allow_online=True and local cached file missing or refresh=True,
    try to download the IEEE oui.txt and save it to OUI_TXT_FILE.
    This function is safe to call multiple times; it's cheap after the first load.
    """
    global _OUI_MAP, _OUI_LOADED
    if _OUI_LOADED and not refresh:
        return

    # 1) Try reading the local cached IEEE file first
    if os.path.exists(OUI_TXT_FILE) and not refresh:
        try:
            with open(OUI_TXT_FILE, "r", encoding="utf-8", errors="ignore") as fh:
                txt = fh.read()
            _OUI_MAP = _parse_oui_text(txt)
            _OUI_LOADED = True
            return
        except Exception:
            pass

    # 2) Try local CSV (user-provided)
    if os.path.exists(LOCAL_OUI_CSV) and not refresh:
        try:
            d = {}
            with open(LOCAL_OUI_CSV, "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    parts = [p.strip() for p in line.split(',', 1)]
                    if len(parts) >= 1:
                        p = parts[0].lower().replace('-', ':')
                        if len(p) == 6:
                            p = ':'.join([p[i:i+2] for i in range(0, 6, 2)])
                        vendor = parts[1] if len(parts) > 1 else ""
                        d[p] = vendor
            if d:
                _OUI_MAP = d
                _OUI_LOADED = True
                return
        except Exception:
            pass

    # 3) Optionally fetch the IEEE OUI list (best-effort)
    if allow_online:
        urls = [
            "https://standards-oui.ieee.org/oui/oui.txt",
            "http://standards-oui.ieee.org/oui/oui.txt"
        ]
        for url in urls:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Advanced-LAN-Scanner/1.0"})
                with urllib.request.urlopen(req, timeout=15) as resp:
                    txt = resp.read().decode('utf-8', errors='ignore')
                # Save a local copy for future runs (best-effort)
                try:
                    with open(OUI_TXT_FILE, "w", encoding="utf-8") as fh:
                        fh.write(txt)
                except Exception:
                    pass
                _OUI_MAP = _parse_oui_text(txt)
                _OUI_LOADED = True
                return
            except Exception:
                continue

    # fallback: empty map
    _OUI_MAP = {}
    _OUI_LOADED = True

# -------------------- Main get_mac_vendor (combined) --------------------

def get_mac_vendor(mac, allow_online=False):
    """
    Return vendor string for a MAC address. Uses (in priority):
      1) per-MAC runtime cache file (mac_cache.json)
      2) local oui.csv (lookup_local_oui)
      3) in-memory OUI map (oui.txt or fetched IEEE file)
      4) online macvendors API (if allow_online)
    """
    mac = mac_normalize(mac)
    if not mac:
        return ""
    # 1) exact per-MAC cache hit
    if mac in MAC_CACHE:
        return MAC_CACHE[mac]

    # 2) local CSV lookup
    vendor = lookup_local_oui(mac)
    if vendor:
        MAC_CACHE[mac] = vendor
        save_mac_cache(MAC_CACHE)
        return vendor

    # 3) OUI map lookup (load if needed)
    pref = mac_prefix(mac)
    if not _OUI_LOADED:
        try:
            load_oui_cache(allow_online=allow_online)
        except Exception:
            pass

    vendor = _OUI_MAP.get(pref)
    if vendor:
        MAC_CACHE[mac] = vendor
        save_mac_cache(MAC_CACHE)
        return vendor

    # 4) try to reuse any cached vendor that shares same prefix
    for k, v in list(MAC_CACHE.items()):
        try:
            if mac_prefix(k) == pref:
                MAC_CACHE[mac] = v
                save_mac_cache(MAC_CACHE)
                return v
        except Exception:
            pass

    # 5) last resort: online API
    if allow_online:
        vendor = lookup_mac_online(mac)
        if vendor:
            MAC_CACHE[mac] = vendor
            save_mac_cache(MAC_CACHE)
            return vendor

    return ""

# -------------------- Local subnet detection --------------------

def detect_local_subnet_default():
    """
    Detect a sensible default local subnet for the host (e.g., 192.168.1.0/24).
    Tries to open a UDP socket to 8.8.8.8 to determine the primary IP.
    """
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
    - Wildcard: 192.168.1.*
    - Single IP: 192.168.1.5
    - Comma separated: 192.168.1.5,192.168.1.10-15
    - Mixed whitespace allowed
    - file://path to load ip list (one per line)
    Returns sorted list of IP strings (unique).
    """
    if not input_text:
        return []
    toks = re.split(r'[,\s]+', input_text.strip())
    ips = []
    for t in toks:
        if not t:
            continue
        t = t.strip()
        # Wildcard?
        if '*' in t:
            parts = t.split('.')
            if len(parts) == 4 and all(p.isdigit() or p == '*' for p in parts):
                base_parts = []
                for p in parts:
                    if p == '*':
                        base_parts.append('*')
                    else:
                        base_parts.append(p)
                # support only one '*' in last octet common case
                if base_parts.count('*') == 1 and base_parts[-1] == '*':
                    base = '.'.join(base_parts[:3])
                    for i in range(256):
                        ips.append(f"{base}.{i}")
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
            try:
                a = ipaddress.IPv4Address(m.group(1))
                b = ipaddress.IPv4Address(m.group(2))
                if int(b) < int(a):
                    a, b = b, a
                cur = int(a)
                while cur <= int(b):
                    ips.append(str(ipaddress.IPv4Address(cur)))
                    cur += 1
            except Exception:
                pass
            continue
        # shorthand range: 192.168.1.10-50
        m2 = re.match(r'^(\d+\.\d+\.\d+)\.(\d+)\s*-\s*(\d+)$', t)
        if m2:
            try:
                base = m2.group(1)
                start = int(m2.group(2))
                end = int(m2.group(3))
                if end < start:
                    start, end = end, start
                for o in range(start, end + 1):
                    ips.append(f"{base}.{o}")
            except Exception:
                pass
            continue
        # single IP?
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', t):
            ips.append(t)
            continue
        # file://path to load
        if t.lower().startswith("file://"):
            path = t[7:]
            if os.path.exists(path):
                try:
                    with open(path, "r", encoding="utf-8", errors='ignore') as fh:
                        for line in fh:
                            line = line.strip()
                            if line:
                                ips.extend(expand_targets(line))
                except Exception:
                    pass
            continue
    # deduplicate & sort numerically by octets
    unique = sorted(set(ips), key=lambda x: tuple(int(p) for p in x.split('.')))
    return unique
