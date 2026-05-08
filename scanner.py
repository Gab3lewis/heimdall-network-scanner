#!/usr/bin/env python3
"""
Heimdall v6.0 — Network Asset Discovery and Vulnerability Assessment

A network scanner focused on explainable findings, conservative CVE matching,
and reducing false positives. Designed for home labs and small networks.

Usage:
  python scanner.py --quick
  python scanner.py --full --target 192.168.1.5
  python scanner.py --target 192.168.1.0/24 --profile home
  python scanner.py --baseline previous_report.json
  python scanner.py --redact
  python scanner.py --cve-since 2018 --nvd-key YOUR_KEY

CVE policy:
  CVEs are assigned only when both product name and version are confirmed from
  the service banner. If the version is unknown, CVE matching is skipped and
  the report says so. This produces fewer results but avoids the noise that
  comes from keyword-only searches against NVD.
"""

import argparse
import html as html_lib
import ipaddress
import json
import re
import select
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Optional

# ──────────────────────────────────────────────────────────────────────────────
# CONSTANTS / COLOUR
# ──────────────────────────────────────────────────────────────────────────────
VERSION = "6.0"

# Only include CVEs published this year or later by default.
# Rationale: vulnerabilities from before this threshold are almost certainly
# patched on any maintained system. Keeping them adds noise without signal.
# Override with --cve-since if you need a broader sweep.
DEFAULT_CVE_SINCE = 2017

class C:
    RED    = "\033[91m"; GREEN  = "\033[92m"; YELLOW = "\033[93m"
    CYAN   = "\033[96m"; WHITE  = "\033[97m"
    BOLD   = "\033[1m";  DIM    = "\033[2m";  RESET  = "\033[0m"

def clr(text, *codes) -> str:
    return "".join(codes) + str(text) + C.RESET

# ANSI escape sequence regex — used to strip codes before measuring display width
_ANSI_RE = re.compile(r"\033\[[0-9;]*m")

def ansi_ljust(s: str, width: int) -> str:
    """
    Left-justify a string that may contain ANSI escape codes to a given
    *visible* width. Standard str.ljust counts ANSI bytes as visible characters,
    which breaks column alignment. This strips ANSI codes to measure the true
    display width then pads accordingly.
    """
    visible_len = len(_ANSI_RE.sub("", s))
    pad = max(0, width - visible_len)
    return s + " " * pad

SEV_CLR = {"CRITICAL":C.RED,"HIGH":C.YELLOW,"MEDIUM":C.CYAN,"LOW":C.GREEN,"INFO":C.DIM}
CONF_CLR = {"high":C.GREEN, "medium":C.YELLOW, "low":C.DIM}

# Global print lock — prevents interleaved output when multiple hosts scan concurrently
_print_lock = threading.Lock()

def tprint(*args, **kwargs):
    """Thread-safe print wrapper."""
    with _print_lock:
        print(*args, **kwargs)

BANNER_ART = f"""
{C.CYAN}{C.BOLD}
  ██╗  ██╗███████╗██╗███╗   ███╗██████╗  █████╗ ██╗     ██╗
  ██║  ██║██╔════╝██║████╗ ████║██╔══██╗██╔══██╗██║     ██║
  ███████║█████╗  ██║██╔████╔██║██║  ██║███████║██║     ██║
  ██╔══██║██╔══╝  ██║██║╚██╔╝██║██║  ██║██╔══██║██║     ██║
  ██║  ██║███████╗██║██║ ╚═╝ ██║██████╔╝██║  ██║███████╗███████╗
  ╚═╝  ╚═╝╚══════╝╚═╝╚═╝     ╚═╝╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝
{C.RESET}{C.DIM}  v{VERSION}  ·  Explainable Findings  ·  Remediation Priorities  ·  Baseline Comparison{C.RESET}
  {C.YELLOW}[!] Authorized use only. Only scan networks you own or have permission for.{C.RESET}
"""

# ──────────────────────────────────────────────────────────────────────────────
# PORT / SERVICE TABLES
# ──────────────────────────────────────────────────────────────────────────────
QUICK_PORTS = [
    21,22,23,25,53,80,110,111,135,139,143,161,389,443,445,
    465,512,513,514,587,631,636,993,995,1433,1521,1723,2049,
    3306,3389,5432,5900,5901,6379,8080,8443,9200,10000,27017
]
COMMON_PORTS = [
    21,22,23,25,53,69,80,110,111,119,123,135,137,138,139,
    143,161,162,179,389,443,445,465,500,512,513,514,515,
    587,631,636,993,995,1080,1194,1433,1434,1521,1723,1883,
    2049,2121,2222,3000,3306,3389,3690,4444,4500,4848,5000,
    5432,5555,5900,5901,6379,6443,6667,7070,7443,8000,8008,
    8080,8081,8443,8888,9000,9090,9200,9300,9418,10000,27017,
    27018,28017,50000,50070,61616
]
SERVICE_MAP = {
    21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",69:"TFTP",
    80:"HTTP",110:"POP3",111:"RPC",119:"NNTP",123:"NTP",135:"MSRPC",
    137:"NetBIOS-NS",138:"NetBIOS-DGM",139:"NetBIOS-SSN",143:"IMAP",
    161:"SNMP",162:"SNMP-Trap",179:"BGP",389:"LDAP",443:"HTTPS",
    445:"SMB",465:"SMTPS",500:"IKE",512:"rexec",513:"rlogin",
    514:"syslog",515:"LPD",587:"SMTP",631:"IPP",636:"LDAPS",
    993:"IMAPS",995:"POP3S",1080:"SOCKS",1194:"OpenVPN",1433:"MSSQL",
    1521:"Oracle",1723:"PPTP",1883:"MQTT",2049:"NFS",2222:"SSH",
    3000:"HTTP",3306:"MySQL",3389:"RDP",3690:"SVN",4444:"Backdoor",
    5000:"UPnP",5432:"PostgreSQL",5555:"ADB",5900:"VNC",5901:"VNC",
    6379:"Redis",6443:"Kubernetes",7070:"RTSP",7443:"HTTPS",
    8000:"HTTP",8008:"HTTP",8080:"HTTP",8081:"HTTP",8443:"HTTPS",
    8888:"HTTP",9000:"PHP-FPM",9090:"Prometheus",9200:"Elasticsearch",
    9300:"Elasticsearch",9418:"Git",10000:"Webmin",27017:"MongoDB",
    50000:"IBM-DB2",61616:"ActiveMQ"
}

_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]
def is_internal(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return any(a in n for n in _PRIVATE_NETS)
    except Exception:
        return False

# ──────────────────────────────────────────────────────────────────────────────
# CONFIDENCE LEVELS
# ──────────────────────────────────────────────────────────────────────────────
CONF_HIGH   = "high"
CONF_MEDIUM = "medium"
CONF_LOW    = "low"

@dataclass
class ServiceVersion:
    product:    str = ""
    version:    str = ""
    raw:        str = ""
    confidence: str = CONF_LOW

# ──────────────────────────────────────────────────────────────────────────────
# VERSION PATTERNS — service-specific regex (group 1 = version)
# ──────────────────────────────────────────────────────────────────────────────
VERSION_PATTERNS: dict = {
    "SSH": [
        (r"SSH-[\d.]+-OpenSSH[_\s]([\d.p]+)",         "OpenSSH"),
        (r"SSH-[\d.]+-dropbear[_\-]?([\d.]+)",         "Dropbear SSH"),
        (r"SSH-[\d.]+-libssh[_\-]?([\d.]+)",           "libssh"),
    ],
    "FTP": [
        (r"vsftpd\s+([\d.]+)",                         "vsftpd"),
        (r"ProFTPD\s+([\d.]+)",                        "ProFTPD"),
        (r"FileZilla Server\s+([\d.]+)",               "FileZilla Server"),
        (r"Microsoft FTP Service.*?Version\s+([\d.]+)","Microsoft FTP"),
        (r"Pure-FTPd\s+([\d.]+)",                      "Pure-FTPd"),
    ],
    "HTTP": [
        (r"Apache/([\d.]+)",                           "Apache httpd"),
        (r"Apache/(\d+\.\d+)",                         "Apache httpd"),       # short form
        (r"nginx/([\d.]+)",                            "nginx"),
        (r"Microsoft-IIS/([\d.]+)",                    "Microsoft IIS"),
        (r"lighttpd/([\d.]+)",                         "lighttpd"),
        (r"Jetty\(([\d.]+)\)",                         "Jetty"),
        (r"Tomcat/([\d.]+)",                           "Apache Tomcat"),
        (r"mini_httpd/([\d.]+)",                       "mini_httpd"),
        (r"OpenResty/([\d.]+)",                        "OpenResty"),
        (r"Werkzeug/([\d.]+)",                         "Werkzeug"),
        (r"Gunicorn/([\d.]+)",                         "Gunicorn"),
        (r"Caddy/([\d.]+)",                            "Caddy"),
        (r"Python/([\d.]+)",                           "Python HTTP"),
        (r"Ruby/([\d.]+)",                             "Ruby HTTP"),
    ],
    "HTTPS": [
        (r"Apache/([\d.]+)",                           "Apache httpd"),
        (r"nginx/([\d.]+)",                            "nginx"),
        (r"Microsoft-IIS/([\d.]+)",                    "Microsoft IIS"),
        (r"OpenSSL/([\d.]+)",                          "OpenSSL"),
        (r"lighttpd/([\d.]+)",                         "lighttpd"),
    ],
    "SMTP": [
        (r"Postfix\s+ESMTP.*?ready.*?([\d.]+)",        "Postfix"),
        (r"Sendmail\s+([\d.]+)",                       "Sendmail"),
        (r"Exim\s+([\d.]+)",                           "Exim"),
        (r"Microsoft ESMTP.*?Version:\s*([\d.]+)",     "Microsoft Exchange"),
    ],
    "MySQL": [
        (r"([\d]+\.[\d]+\.[\d]+)-MariaDB",             "MariaDB"),
        (r"([\d]+\.[\d]+\.[\d]+)",                     "MySQL"),
    ],
    "Redis":         [(r"redis_version:([\d.]+)",      "Redis")],
    "Elasticsearch": [(r'"number"\s*:\s*"([\d.]+)"',   "Elasticsearch")],
    "MongoDB":       [(r'"version"\s*:\s*"([\d.]+)"',  "MongoDB")],
    "VNC":           [(r"RFB\s+([\d.]+)",              "VNC")],
}

# ── EXPANDED BANNER → PRODUCT NORMALISATION ──────────────────────────────────
# Maps substrings found in Server/banner headers to canonical product names.
# Applied BEFORE the generic regex so partial names get a clean product string.
_BANNER_PRODUCT_MAP = [
    # (substring_pattern, canonical_product_name)
    (r"\bhttpd\b",          "Apache httpd"),
    (r"\bapache\b",         "Apache httpd"),
    (r"\bnginx\b",          "nginx"),
    (r"\biis\b",            "Microsoft IIS"),
    (r"\blighttpd\b",       "lighttpd"),
    (r"\btomcat\b",         "Apache Tomcat"),
    (r"\bjetty\b",          "Jetty"),
    (r"\bopenssh\b",        "OpenSSH"),
    (r"\bvsftpd\b",         "vsftpd"),
    (r"\bproftpd\b",        "ProFTPD"),
    (r"\bpostfix\b",        "Postfix"),
    (r"\bexim\b",           "Exim"),
    (r"\bsendmail\b",       "Sendmail"),
    (r"\bmariadb\b",        "MariaDB"),
    (r"\bmysql\b",          "MySQL"),
    (r"\bpostgresql\b",     "PostgreSQL"),
    (r"\bredis\b",          "Redis"),
    (r"\belasticsearch\b",  "Elasticsearch"),
    (r"\bmongodb\b",        "MongoDB"),
    (r"\bvnc\b",            "VNC"),
    (r"\bwebmin\b",         "Webmin"),
    (r"\bglassfish\b",      "GlassFish"),
    (r"\bjboss\b",          "JBoss"),
    (r"\btomcat\b",         "Apache Tomcat"),
    (r"\bwordpress\b",      "WordPress"),
    (r"\bdrupal\b",         "Drupal"),
    (r"\bopenssl\b",        "OpenSSL"),
]
_COMPILED_PROD_MAP = [(re.compile(p, re.IGNORECASE), name) for p, name in _BANNER_PRODUCT_MAP]

_GENERIC_VER_RE = re.compile(
    r"([\w][\w\-]*)[/ ]([\d]+\.[\d]+(?:\.[\d]+)?(?:[_\-p][\d]+)?)"
)
_NOISE_WORDS = {
    "http","html","text","charset","utf","keep","alive","close",
    "application","max","age","no","cache","must","revalidate",
    "public","private","content","type","length","transfer","encoding",
    "gzip","chunked","bytes","server","date","last","modified","etag",
}

def parse_version(service: str, banner: str) -> ServiceVersion:
    """
    Three-pass version extraction:
      1. Service-specific regex (most precise)
      2. Product normalisation map + version capture (handles "httpd/2.0" etc.)
      3. Generic "word/X.Y.Z" fallback

    Confidence:
      HIGH   = product + version confirmed
      MEDIUM = service inferred from port, no version
      LOW    = no useful data
    """
    if not banner or banner in ("No banner","Skipped"):
        if service not in ("Unknown",):
            return ServiceVersion(product=service, confidence=CONF_MEDIUM)
        return ServiceVersion(confidence=CONF_LOW)

    # ── Pass 1: service-specific patterns ────────────────────────────────────
    for pat, product in VERSION_PATTERNS.get(service, []):
        m = re.search(pat, banner, re.IGNORECASE)
        if m:
            return ServiceVersion(product=product, version=m.group(1),
                                  raw=banner[:120], confidence=CONF_HIGH)

    # ── Pass 2: product normalisation + adjacent version ─────────────────────
    # Try to find a known product name in the banner, then grab a version nearby.
    for compiled_re, canon_name in _COMPILED_PROD_MAP:
        m = compiled_re.search(banner)
        if m:
            # Look for a version number close to the match (within ±60 chars)
            start = max(0, m.start()-10)
            end   = min(len(banner), m.end()+60)
            context = banner[start:end]
            vm = re.search(r"[/ v]([\d]+\.[\d]+(?:\.[\d]+)?)", context)
            if vm:
                return ServiceVersion(product=canon_name, version=vm.group(1),
                                      raw=banner[:120], confidence=CONF_HIGH)
            else:
                # Product identified but version not found — still better than nothing
                return ServiceVersion(product=canon_name, raw=banner[:60],
                                      confidence=CONF_MEDIUM)

    # ── Pass 3: generic "Token/X.Y.Z" ─────────────────────────────────────────
    m = _GENERIC_VER_RE.search(banner)
    if m:
        prod = m.group(1)
        if prod.lower() not in _NOISE_WORDS and len(prod) > 1:
            return ServiceVersion(product=prod, version=m.group(2),
                                  raw=banner[:120], confidence=CONF_HIGH)

    # Banner present but nothing matched
    if service not in ("Unknown",):
        return ServiceVersion(product=service, raw=banner[:60], confidence=CONF_MEDIUM)

    return ServiceVersion(confidence=CONF_LOW)

# ──────────────────────────────────────────────────────────────────────────────
# OS FINGERPRINTING  (refined multi-signal)
# ──────────────────────────────────────────────────────────────────────────────
@dataclass
class OSGuess:
    os_type:    str = "Unknown"
    confidence: str = "low"
    method:     str = ""

def fingerprint_os(open_ports: list, banners: dict, ttl: Optional[int]) -> OSGuess:
    signals = []
    ps = set(open_ports)
    priority = {"high":3, "medium":2, "low":1}

    # ── TTL ──────────────────────────────────────────────────────────────────
    if ttl is not None:
        if   ttl <= 64:  signals.append(("Linux/Unix",           "low",    f"TTL={ttl}"))
        elif ttl <= 128: signals.append(("Windows",              "low",    f"TTL={ttl}"))
        else:            signals.append(("Network Device",        "low",    f"TTL={ttl}"))

    # ── SSH banner (most specific OS signal) ─────────────────────────────────
    ssh_b = banners.get(22,"") or banners.get(2222,"")
    if ssh_b:
        bl = ssh_b.lower()
        for kw, os_name in [
            ("ubuntu",   "Linux (Ubuntu)"),
            ("debian",   "Linux (Debian)"),
            ("centos",   "Linux (CentOS/RHEL)"),
            ("rhel",     "Linux (CentOS/RHEL)"),
            ("red hat",  "Linux (RHEL)"),
            ("fedora",   "Linux (Fedora)"),
            ("alpine",   "Linux (Alpine)"),
            ("arch",     "Linux (Arch)"),
            ("freebsd",  "FreeBSD"),
            ("openbsd",  "OpenBSD"),
            ("netbsd",   "NetBSD"),
        ]:
            if kw in bl:
                signals.append((os_name, "high", f"SSH banner: {ssh_b[:70]}"))
                break
        else:
            if "openssh" in bl:
                signals.append(("Linux/Unix", "medium", f"OpenSSH banner"))
            elif "dropbear" in bl:
                signals.append(("Embedded Linux", "medium", "Dropbear SSH (router/IoT)"))

    # ── Windows port combinations ─────────────────────────────────────────────
    # Strong: MSRPC + NetBIOS + SMB (all three = very Windows)
    if {135,139,445}.issubset(ps):
        ver = "Windows (with RDP)" if 3389 in ps else "Windows"
        signals.append((ver, "high", "Ports 135+139+445 (MSRPC+NetBIOS+SMB)"))
    elif 445 in ps and 135 in ps:
        signals.append(("Windows", "medium", "Ports 135+445 (MSRPC+SMB)"))
    elif 3389 in ps and 445 in ps:
        signals.append(("Windows", "high", "Ports 445+3389 (SMB+RDP)"))
    elif 3389 in ps and 135 in ps:
        signals.append(("Windows", "medium", "Ports 135+3389 (MSRPC+RDP)"))

    # ── Linux port combinations ───────────────────────────────────────────────
    # 22 + 111 (RPC) is a reliable Linux indicator (NFS, portmapper)
    if 22 in ps and 111 in ps:
        signals.append(("Linux/Unix", "medium", "Ports 22+111 (SSH+RPC/portmapper)"))
    if 2049 in ps and 111 in ps:
        signals.append(("Linux/Unix (NFS server)", "medium", "Ports 111+2049 (RPC+NFS)"))
    # Docker host often exposes 2375/2376
    if 2375 in ps or 2376 in ps:
        signals.append(("Linux (Docker host)", "medium", "Docker daemon port"))

    # ── HTTP Server header ────────────────────────────────────────────────────
    for hp in [80,8080,8000,443,8443,8888]:
        b = banners.get(hp,"")
        if not b:
            continue
        bl = b.lower()
        matched = None
        for kw, os_name, conf in [
            ("microsoft-iis",  "Windows (IIS)",          "high"),
            ("dd-wrt",         "Router (DD-WRT)",         "high"),
            ("openwrt",        "Router (OpenWrt)",        "high"),
            ("lede",           "Router (OpenWrt/LEDE)",   "high"),
            ("mikrotik",       "Router (MikroTik)",       "high"),
            ("cisco",          "Network Device (Cisco)",  "medium"),
            ("synology",       "NAS (Synology)",          "high"),
            ("qnap",           "NAS (QNAP)",              "high"),
            ("asustor",        "NAS (Asustor)",           "high"),
            ("readynas",       "NAS (Netgear ReadyNAS)",  "high"),
            ("hikvision",      "Camera (Hikvision)",      "high"),
            ("dahua",          "Camera (Dahua)",          "high"),
            ("ubiquiti",       "Network Device (Ubiquiti)","medium"),
            ("pfsense",        "Firewall (pfSense)",      "high"),
            ("opnsense",       "Firewall (OPNsense)",     "high"),
        ]:
            if kw in bl:
                matched = (os_name, conf, f"HTTP header match '{kw}'")
                break
        if matched:
            signals.append(matched)
            break

    # ── Printer / embedded ────────────────────────────────────────────────────
    # Use "low" confidence for printer port signals — this ensures a router with
    # port 515 open (print server feature) is not mis-identified as a printer when
    # a higher-confidence router signal (hostname, HTTP header, etc.) is present.
    if {515,631} & ps or 9100 in ps:
        signals.append(("Network Printer", "low", "Printer ports (515/631/9100)"))
    if 1900 in ps and not signals:
        signals.append(("Smart Device / Router (UPnP)", "low", "UPnP port 1900"))

    if not signals:
        return OSGuess()

    signals.sort(key=lambda x: priority.get(x[1],0), reverse=True)
    return OSGuess(os_type=signals[0][0], confidence=signals[0][1], method=signals[0][2])

def get_ttl(ip: str) -> Optional[int]:
    try:
        param = ["-n","1"] if sys.platform=="win32" else ["-c","1","-W","1"]
        r = subprocess.run(["ping"]+param+[ip], capture_output=True, text=True, timeout=3)
        m = re.search(r"[Tt][Tt][Ll]=(\d+)", r.stdout)
        return int(m.group(1)) if m else None
    except Exception:
        return None

# ──────────────────────────────────────────────────────────────────────────────
# HOST DISCOVERY
# ──────────────────────────────────────────────────────────────────────────────
def ping_host(ip: str) -> bool:
    try:
        param = ["-n","1","-w","500"] if sys.platform=="win32" else ["-c","1","-W","1"]
        r = subprocess.run(["ping"]+param+[ip],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
        return r.returncode == 0
    except Exception:
        return False

def tcp_probe(ip: str) -> bool:
    for port in [80,443,22,445,3389,8080]:
        try:
            s = socket.socket(); s.settimeout(0.3)
            if s.connect_ex((ip,port)) == 0:
                s.close(); return True
            s.close()
        except Exception:
            pass
    return False

def discover_hosts(network: str) -> list:
    try:
        net   = ipaddress.ip_network(network, strict=False)
        hosts = [str(h) for h in net.hosts()]
    except ValueError:
        return [network]
    if len(hosts) == 1:
        return hosts

    print(f"\n{clr('[ HOST DISCOVERY ]',C.CYAN,C.BOLD)}  Probing {len(hosts)} addresses ...")
    live, lock = [], threading.Lock()

    def check(ip):
        if ping_host(ip) or tcp_probe(ip):
            with lock:
                live.append(ip)
                print(f"  {clr('+',C.GREEN,C.BOLD)} {ip} {clr('UP',C.GREEN)}")

    with ThreadPoolExecutor(max_workers=150) as ex:
        ex.map(check, hosts)

    return sorted(live, key=lambda x:[int(p) for p in x.split(".")])

# ──────────────────────────────────────────────────────────────────────────────
# PORT SCANNING
# ──────────────────────────────────────────────────────────────────────────────
def scan_ports(ip: str, ports: list, threads: int = 300, timeout: float = 0.5) -> list:
    open_ports, lock = [], threading.Lock()
    def check(p):
        try:
            s = socket.socket(); s.settimeout(timeout)
            if s.connect_ex((ip,p)) == 0:
                with lock: open_ports.append(p)
            s.close()
        except Exception:
            pass
    with ThreadPoolExecutor(max_workers=min(threads, max(1,len(ports)))) as ex:
        ex.map(check, ports)
    return sorted(open_ports)

# ──────────────────────────────────────────────────────────────────────────────
# BANNER GRABBING
# ──────────────────────────────────────────────────────────────────────────────
_PROBES = {
    25:   b"EHLO heimdall\r\n",
    80:   b"HEAD / HTTP/1.0\r\nHost: {IP}\r\nUser-Agent: Heimdall/4.0\r\n\r\n",
    6379: b"INFO server\r\n",
    9200: b"GET / HTTP/1.0\r\nHost: {IP}\r\n\r\n",
}
_SSL_PORTS = {443,8443,465,993,995,636,7443}

def grab_banner(ip: str, port: int, timeout: float = 2.5) -> str:
    banner = ""
    try:
        if port in _SSL_PORTS:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            raw = socket.socket(); raw.settimeout(timeout)
            with ctx.wrap_socket(raw, server_hostname=ip) as s:
                s.connect((ip,port))
                s.send(b"HEAD / HTTP/1.0\r\nHost: "+ip.encode()+b"\r\n\r\n")
                data = b""
                try:
                    while len(data) < 2048:
                        chunk = s.recv(512)
                        if not chunk: break
                        data += chunk
                        if b"\r\n\r\n" in data: break
                except Exception:
                    pass
                banner = data.decode("utf-8",errors="replace").strip()
                cert = s.getpeercert()
                if cert:
                    subj = dict(x[0] for x in cert.get("subject",[]))
                    cn   = subj.get("commonName","")
                    exp  = cert.get("notAfter","")
                    if cn: banner = f"[TLS CN={cn} Expires={exp}] " + banner
        else:
            s = socket.socket(); s.settimeout(timeout)
            s.connect((ip,port))
            probe = _PROBES.get(port, b"")
            if b"{IP}" in probe: probe = probe.replace(b"{IP}",ip.encode())
            if probe: s.send(probe)
            rdy = select.select([s],[],[],timeout)
            if rdy[0]:
                data = b""
                try:
                    while len(data) < 2048:
                        chunk = s.recv(512)
                        if not chunk: break
                        data += chunk
                        if len(data) > 512 or b"\n" in chunk: break
                except Exception:
                    pass
                banner = data.decode("utf-8",errors="replace").strip()
            s.close()
    except Exception:
        pass
    banner = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]","",banner)
    return banner[:400] if banner else "No banner"

# ──────────────────────────────────────────────────────────────────────────────
# NVD CVE LOOKUP  —  with year filtering + strict relevance
# ──────────────────────────────────────────────────────────────────────────────
_nvd_cache: dict = {}
_nvd_lock  = threading.Lock()
NVD_RATE_DELAY = 0.65

def _query_nvd_raw(keyword: str, max_results: int, api_key: str) -> list:
    """Raw NVD query, returns list of CVE dicts. Cached per keyword."""
    cache_key = f"{keyword}:{max_results}"
    with _nvd_lock:
        if cache_key in _nvd_cache:
            return _nvd_cache[cache_key]

    time.sleep(NVD_RATE_DELAY)
    try:
        params = urllib.parse.urlencode({"keywordSearch":keyword,"resultsPerPage":max_results})
        url    = f"https://services.nvd.nist.gov/rest/json/cves/2.0?{params}"
        hdrs   = {"User-Agent":f"Heimdall/{VERSION}"}
        if api_key: hdrs["apiKey"] = api_key

        ctx = ssl.create_default_context()
        req = urllib.request.Request(url, headers=hdrs)
        with urllib.request.urlopen(req, context=ctx, timeout=12) as resp:
            data = json.loads(resp.read().decode())

        cves = []
        for item in data.get("vulnerabilities",[]):
            cve    = item.get("cve",{})
            cve_id = cve.get("id","")
            descs  = cve.get("descriptions",[])
            desc   = next((d["value"] for d in descs if d["lang"]=="en"),"")[:300]
            pub    = cve.get("published","")[:10]
            score, severity, vector = None, "UNKNOWN", ""
            for mk in ["cvssMetricV31","cvssMetricV30","cvssMetricV2"]:
                ms = cve.get("metrics",{}).get(mk)
                if ms:
                    cd = ms[0].get("cvssData",{})
                    score    = cd.get("baseScore")
                    severity = cd.get("baseSeverity", ms[0].get("baseSeverity","UNKNOWN")).upper()
                    vector   = cd.get("vectorString","")
                    break
            cves.append({"id":cve_id,"description":desc,"score":score,
                         "severity":severity,"vector":vector,"published":pub,
                         "url":f"https://nvd.nist.gov/vuln/detail/{cve_id}"})

        with _nvd_lock:
            _nvd_cache[cache_key] = cves
        return cves
    except Exception:
        return []


def _is_relevant_cve(cve: dict, product: str, cve_since: int) -> bool:
    """
    Strict relevance filter — both conditions must pass:

    1. Year filter: CVE published year >= cve_since
       Rationale: Old CVEs are almost certainly patched on maintained systems.
       We keep the threshold at cve_since (default 2017) so:
         - EternalBlue (2017), Heartbleed (2014 — excluded by default) etc.
         - Configurable via --cve-since for thorough audits

    2. Product name relevance: the first meaningful word of the canonical product
       name must appear in the CVE description.
       Example: product="OpenSSH" → "openssh" must be in description.
       This eliminates NVD results that match a keyword but describe unrelated software.
       Exception: CRITICAL severity CVEs pass even without product match (may be
       zero-day/generic infrastructure vulnerabilities worth flagging).
    """
    # ── Year filter ────────────────────────────────────────────────────────
    pub = cve.get("published","")
    try:
        pub_year = int(pub[:4])
    except (ValueError, TypeError):
        pub_year = 0
    if pub_year < cve_since:
        return False

    # ── Product relevance ──────────────────────────────────────────────────
    if not product:
        return True  # no product info — can't filter, keep it

    # Extract the most distinctive word from the product name for matching.
    # "Apache httpd" → "apache", "Microsoft IIS" → "iis", "OpenSSH" → "openssh"
    prod_words = re.findall(r"[a-z]+", product.lower())
    # Skip generic words that appear in almost any CVE description
    _skip = {"microsoft","server","service","http","the","and","for","of","in"}
    key_words = [w for w in prod_words if w not in _skip and len(w) > 2]
    if not key_words:
        return True

    desc_lower = cve.get("description","").lower()
    # At least one key word must appear in the description
    if any(kw in desc_lower for kw in key_words):
        return True

    # CRITICAL CVEs pass even without product match — too risky to suppress
    if cve.get("severity") == "CRITICAL":
        return True

    return False


def fetch_cves(svc_ver: ServiceVersion, port: int,
               api_key: str = "", cve_since: int = DEFAULT_CVE_SINCE) -> dict:
    """
    Confidence-gated CVE lookup with year + relevance filtering.

    Returns:
      {"cves": [...], "confidence": str, "advisory": str, "filtered_count": int}

    Rules:
      HIGH confidence   → query NVD with product+version, apply strict filters
      MEDIUM confidence → no CVE match, return advisory message
      LOW confidence    → no CVE match, no advisory
    """
    if svc_ver.confidence == CONF_LOW:
        return {"cves":[], "confidence":CONF_LOW, "advisory":"", "filtered_count":0}

    if svc_ver.confidence == CONF_MEDIUM:
        return {
            "cves": [],
            "confidence": CONF_MEDIUM,
            "advisory": (
                f"Service identified as {svc_ver.product} on port {port} but "
                "version could not be confirmed from the banner. CVE matching "
                "skipped to avoid false positives — verify version manually."
            ),
            "filtered_count": 0
        }

    # HIGH confidence path
    product = svc_ver.product
    version = svc_ver.version
    queries = [
        (f"{product} {version}", 8),   # most precise — version-specific
        (product, 4),                   # product sweep for context
    ]

    raw_all, seen, filtered_out = [], set(), 0
    for kw, n in queries:
        for cve in _query_nvd_raw(kw, n, api_key):
            if cve["id"] not in seen:
                seen.add(cve["id"])
                raw_all.append(cve)

    # Apply year + relevance filter
    passed = []
    for cve in raw_all:
        if _is_relevant_cve(cve, product, cve_since):
            passed.append(cve)
        else:
            filtered_out += 1

    passed.sort(key=lambda x:(x["score"] or 0), reverse=True)
    return {
        "cves":          passed[:8],
        "confidence":    CONF_HIGH,
        "advisory":      "",
        "filtered_count": filtered_out
    }

# ──────────────────────────────────────────────────────────────────────────────
# ACTIVE SECURITY CHECKS
# ──────────────────────────────────────────────────────────────────────────────
@dataclass
class SecurityFinding:
    severity:    str
    category:    str   # Auth / Config / Protocol / Header
    check:       str
    detail:      str
    remediation: str = ""

def _check_ftp_anon(ip, port=21, to=3.0):
    out = []
    try:
        s = socket.socket(); s.settimeout(to); s.connect((ip,port))
        s.recv(1024)
        s.send(b"USER anonymous\r\n"); r1 = s.recv(512).decode(errors="replace")
        if r1.startswith("331"):
            s.send(b"PASS heimdall@scan\r\n"); r2 = s.recv(512).decode(errors="replace")
            if r2.startswith("230"):
                out.append(SecurityFinding("CRITICAL","Auth","FTP Anonymous Login",
                    "Anonymous FTP login succeeded — unauthenticated file access possible.",
                    "Set anonymous_enable=NO in vsftpd.conf."))
        s.send(b"QUIT\r\n"); s.close()
    except Exception:
        pass
    return out

def _check_smb(ip, port=445, to=3.0):
    out = []
    pkt = (
        b"\x00\x00\x00\x54"
        b"\xff\x53\x4d\x42"
        b"\x72"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00"
        b"\xff\xff\xff\xff"
        b"\x00\x00"
        b"\x00\x31\x00\x02"
        b"NT LM 0.12\x00"
        b"\x02SMB 2.002\x00"
        b"\x02SMB 2.???\x00"
    )
    try:
        s = socket.socket(); s.settimeout(to); s.connect((ip,port))
        s.send(pkt)
        rdy = select.select([s],[],[],to)
        if rdy[0]:
            data = s.recv(1024)
            if len(data) > 4 and b"\xff\x53\x4d\x42" in data:
                out.append(SecurityFinding("HIGH","Protocol","SMBv1 Enabled",
                    "SMBv1 negotiation succeeded. Vulnerable to EternalBlue (MS17-010).",
                    "Set-SmbServerConfiguration -EnableSMB1Protocol $false"))
            if len(data) > 39:
                sec = data[39]
                if not bool(sec & 0x10):
                    state = "enabled but not required" if bool(sec & 0x08) else "disabled"
                    out.append(SecurityFinding("MEDIUM","Config","SMB Signing Not Required",
                        f"SMB signing is {state}. Susceptible to NTLM relay attacks.",
                        "Set-SmbServerConfiguration -RequireSecuritySignature $true"))
        s.close()
    except Exception:
        pass
    if not out:
        out.append(SecurityFinding("INFO","Config","SMB Port Open",
            "SMB is reachable on this host. SMBv1 status and signing configuration "
            "were not confirmed by this scan. Review file sharing configuration, "
            "confirm SMBv1 is disabled, and verify SMB signing requirements.",
            "Run: Get-SmbServerConfiguration | Select EnableSMB1Protocol, "
            "RequireSecuritySignature. Disable SMBv1 if enabled."))
    return out

def _check_redis(ip, port=6379, to=2.0):
    out = []
    try:
        s = socket.socket(); s.settimeout(to); s.connect((ip,port))
        s.send(b"PING\r\n"); resp = s.recv(128).decode(errors="replace")
        if "+PONG" in resp:
            out.append(SecurityFinding("CRITICAL","Auth","Redis No Authentication",
                "Redis answered PING without credentials. Full DB access + RCE via config rewrite.",
                "Set requirepass in redis.conf; bind to 127.0.0.1 only."))
        elif "NOAUTH" in resp or "WRONGPASS" in resp:
            out.append(SecurityFinding("INFO","Auth","Redis Auth Enforced",
                "Redis requires a password.","Ensure password is strong."))
        s.send(b"QUIT\r\n"); s.close()
    except Exception:
        pass
    return out

def _check_mongodb(ip, port=27017, to=2.0):
    out = []
    query = (
        b"\x41\x00\x00\x00"
        b"\x01\x00\x00\x00"
        b"\x00\x00\x00\x00"
        b"\xd4\x07\x00\x00"
        b"\x00\x00\x00\x00"
        b"admin.$cmd\x00"
        b"\x00\x00\x00\x00"
        b"\x01\x00\x00\x00"
        b"\x13\x00\x00\x00"
        b"\x01ismaster\x00"
        b"\x00\x00\x00\x00\x00\x00\xf0\x3f"
        b"\x00"
    )
    try:
        s = socket.socket(); s.settimeout(to); s.connect((ip,port)); s.send(query)
        rdy = select.select([s],[],[],to)
        if rdy[0]:
            data = s.recv(512)
            if len(data) > 16 and b"ismaster" in data.lower():
                if b"unauthorized" in data.lower():
                    out.append(SecurityFinding("INFO","Auth","MongoDB Auth Enforced",
                        "MongoDB requires authentication.","Confirm port is not internet-facing."))
                else:
                    out.append(SecurityFinding("CRITICAL","Auth","MongoDB No Authentication",
                        "MongoDB responded without credentials. Full database exposed.",
                        "Enable auth: security.authorization: enabled in mongod.conf."))
        s.close()
    except Exception:
        pass
    return out

def _check_elasticsearch(ip, port=9200, to=2.0):
    out = []
    try:
        s = socket.socket(); s.settimeout(to); s.connect((ip,port))
        s.send(b"GET / HTTP/1.0\r\nHost: "+ip.encode()+b"\r\n\r\n")
        rdy = select.select([s],[],[],to)
        if rdy[0]:
            data = s.recv(2048).decode(errors="replace")
            if '"cluster_name"' in data or '"version"' in data:
                out.append(SecurityFinding("CRITICAL","Auth","Elasticsearch Open API",
                    "Elasticsearch API responds without auth. All indices exposed.",
                    "xpack.security.enabled: true in elasticsearch.yml."))
            elif "401" in data or "unauthorized" in data.lower():
                out.append(SecurityFinding("INFO","Auth","Elasticsearch Auth Enforced","",""))
        s.close()
    except Exception:
        pass
    return out

def _check_snmp(ip, port=161, to=2.0):
    out = []
    pkt = bytes([
        0x30,0x26,0x02,0x01,0x00,0x04,0x06,
        0x70,0x75,0x62,0x6c,0x69,0x63,
        0xa0,0x19,0x02,0x04,0x00,0x00,0x00,0x01,
        0x02,0x01,0x00,0x02,0x01,0x00,
        0x30,0x0b,0x30,0x09,
        0x06,0x05,0x2b,0x06,0x01,0x02,0x01,
        0x05,0x00,
    ])
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(to); s.sendto(pkt,(ip,port))
        data,_ = s.recvfrom(1024)
        if data and len(data) > 10:
            out.append(SecurityFinding("HIGH","Config","SNMP Default Community 'public'",
                "SNMP accepts 'public'. Exposes system info; may allow write access.",
                "Change community string; restrict SNMP; upgrade to SNMPv3."))
        s.close()
    except Exception:
        pass
    return out

def _check_vnc(ip, port=5900, to=2.0):
    out = []
    try:
        s = socket.socket(); s.settimeout(to); s.connect((ip,port))
        banner = s.recv(256).decode(errors="replace")
        if "RFB" in banner:
            stypes = s.recv(64)
            if stypes and 1 in list(stypes[1:]):
                out.append(SecurityFinding("CRITICAL","Auth","VNC No Authentication",
                    "VNC offers security type 'None' — no password required.",
                    "Enable VNC password auth or restrict to localhost+SSH tunnel."))
            else:
                out.append(SecurityFinding("INFO","Auth","VNC Auth Required",
                    f"VNC requires auth. Banner: {banner.strip()[:60]}",
                    "Use strong password; prefer SSH tunnel over direct VNC."))
        s.close()
    except Exception:
        pass
    return out

def _is_embedded_device_type(device_type: str) -> bool:
    """
    Returns True for device types where missing HTTP security headers are
    lower-priority hardening items rather than urgent findings.
    Routers, Chromecasts, IoT devices, and printers rarely expose their
    web interfaces externally, so missing CSP/HSTS is less significant.
    """
    if not device_type:
        return False
    dl = device_type.lower()
    return any(kw in dl for kw in (
        "router","chromecast","google cast","amazon smart","iot","esp",
        "printer","embedded","tuya","smart home","ring","sonos","philips",
        "roku","camera","nas","ubiquiti","unifi","access point",
    ))


def _check_http_headers(ip, port, to=3.0, device_type=""):
    """
    Fetch HTTP response and audit security headers.
    Results are grouped by category for cleaner reporting.
    """
    findings = []
    try:
        use_ssl = port in _SSL_PORTS
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            raw = socket.socket(); raw.settimeout(to)
            conn = ctx.wrap_socket(raw, server_hostname=ip)
        else:
            conn = socket.socket(); conn.settimeout(to)
        conn.connect((ip,port))
        req = (f"GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: Heimdall/{VERSION}\r\n"
               f"Connection: close\r\n\r\n").encode()
        conn.send(req)
        data = b""
        try:
            while len(data) < 8192:
                chunk = conn.recv(1024)
                if not chunk: break
                data += chunk
                if b"\r\n\r\n" in data: break
        except Exception:
            pass
        conn.close()

        # Determine if this is an embedded/IoT device — affects wording priority
        is_embedded = _is_embedded_device_type(device_type)
        embedded_note = (
            " Lower priority on embedded or local-only devices unless the "
            "web interface is reachable outside the trusted LAN."
            if is_embedded else ""
        )

        # Server version disclosure
        m = re.search(r"[Ss]erver:\s*(.+)", headers_raw)
        if m:
            srv = m.group(1).strip()[:80]
            if re.search(r"\d+\.\d+", srv):
                findings.append(SecurityFinding("LOW","Header","Server Version Disclosed",
                    f"Server header includes version information: {srv}",
                    "Suppress version in server config (e.g. ServerTokens Prod in Apache)."))

        # Security headers
        hdr_checks = [
            ("strict-transport-security",
             use_ssl, "MEDIUM","Header","Missing HSTS",
             f"No Strict-Transport-Security header. Browsers may fall back to HTTP.{embedded_note}",
             "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"),
            ("content-security-policy",
             True,    "LOW" if is_embedded else "MEDIUM","Header","Missing CSP",
             f"No Content-Security-Policy header. Increases XSS exposure on user-facing services.{embedded_note}",
             "Add: Content-Security-Policy: default-src 'self'"),
            ("x-frame-options",
             "frame-ancestors" not in hl,
             "LOW","Header","Missing X-Frame-Options",
             f"Page can be embedded in iframes — clickjacking risk on user-facing interfaces.{embedded_note}",
             "Add: X-Frame-Options: DENY"),
            ("x-content-type-options",
             True,    "LOW","Header","Missing X-Content-Type-Options",
             f"Browser MIME sniffing is enabled.{embedded_note}",
             "Add: X-Content-Type-Options: nosniff"),
            ("referrer-policy",
             True,    "LOW","Header","Missing Referrer-Policy",
             f"No Referrer-Policy header — may expose URL paths to third parties.{embedded_note}",
             "Add: Referrer-Policy: strict-origin-when-cross-origin"),
        ]
        for hdr, condition, sev, cat, check, detail, fix in hdr_checks:
            if condition and hdr not in hl:
                findings.append(SecurityFinding(sev, cat, check, detail, fix))

    except Exception:
        pass
    return findings

def _check_ssh_config(ip, port=22, to=3.0):
    out = []
    try:
        s = socket.socket(); s.settimeout(to); s.connect((ip,port))
        banner = s.recv(256).decode(errors="replace").strip()
        s.send(b"SSH-2.0-Heimdall_scanner\r\n"); s.close()

        if "SSH-1" in banner:
            out.append(SecurityFinding("CRITICAL","Protocol","SSHv1 Active",
                f"SSHv1 is cryptographically broken. Banner: {banner[:80]}",
                "Set Protocol 2 in /etc/ssh/sshd_config; restart sshd."))

        m = re.search(r"OpenSSH[_\s]([\d]+)\.([\d]+)", banner)
        if m:
            maj, min_ = int(m.group(1)), int(m.group(2))
            if (maj, min_) < (8, 0):
                out.append(SecurityFinding("HIGH","Protocol","Outdated OpenSSH",
                    f"OpenSSH {maj}.{min_} detected — multiple known CVEs below 8.0 "
                    "(username enumeration, pre-auth issues in some branches).",
                    "Upgrade OpenSSH to latest stable (9.x+)."))
            elif (maj, min_) < (9, 0):
                out.append(SecurityFinding("MEDIUM","Protocol","OpenSSH Below 9.x",
                    f"OpenSSH {maj}.{min_} — version 9.x includes security improvements.",
                    "Consider upgrading to OpenSSH 9.x."))
    except Exception:
        pass
    return out

def _check_telnet(ip, port=23):
    return [SecurityFinding("HIGH","Protocol","Telnet Enabled",
        "Telnet transmits credentials and data in plaintext.",
        "Disable telnetd; use SSH instead.")]

def run_security_checks(ip: str, open_ports: list, banners: dict,
                        device_type: str = "") -> dict:
    results = {}
    dispatch = {
        21:    lambda: _check_ftp_anon(ip, 21),
        22:    lambda: _check_ssh_config(ip, 22),
        2222:  lambda: _check_ssh_config(ip, 2222),
        23:    lambda: _check_telnet(ip, 23),
        161:   lambda: _check_snmp(ip, 161),
        445:   lambda: _check_smb(ip, 445),
        5900:  lambda: _check_vnc(ip, 5900),
        5901:  lambda: _check_vnc(ip, 5901),
        6379:  lambda: _check_redis(ip, 6379),
        9200:  lambda: _check_elasticsearch(ip, 9200),
        27017: lambda: _check_mongodb(ip, 27017),
    }
    http_ports = {p for p in open_ports if SERVICE_MAP.get(p,"") in ("HTTP","HTTPS")}

    for port in open_ports:
        pf = []
        if port in dispatch: pf.extend(dispatch[port]())
        if port in http_ports: pf.extend(_check_http_headers(ip, port, device_type=device_type))
        if pf: results[port] = pf

    return results

# ──────────────────────────────────────────────────────────────────────────────
# RISK SCORING  (CVSS-weighted, network-aware)
# ──────────────────────────────────────────────────────────────────────────────
_INHERENT_RISK = {
    22:(15,"SSH: remote access service — version exposure risk"),
    23:(30,"Telnet: cleartext credentials"),
    21:(18,"FTP: cleartext credential risk"),
    25:(8, "SMTP: mail relay misconfiguration risk"),
    445:(28,"SMB: EternalBlue/ransomware vector"),
    3389:(28,"RDP: brute-force / BlueKeep vector"),
    1433:(22,"MSSQL: SA brute-force risk"),
    1521:(22,"Oracle: default credentials risk"),
    4444:(40,"Backdoor/Metasploit default port"),
    5900:(22,"VNC: misconfiguration risk"),
    6379:(25,"Redis: no-auth exposure risk"),
    27017:(25,"MongoDB: no-auth exposure risk"),
    9200:(22,"Elasticsearch: unauthenticated data risk"),
    2049:(18,"NFS: filesystem exposure risk"),
    161:(18,"SNMP: community string leakage"),
    69:(14,"TFTP: unauthenticated file transfer"),
    512:(25,"rexec: no encryption"),
    513:(25,"rlogin: plaintext remote login"),
    514:(18,"syslog/rsh: no encryption"),
}
_AUTH_W = {"CRITICAL":35,"HIGH":20,"MEDIUM":10,"LOW":2,"INFO":0}

def calculate_risk(port: int, cve_result: dict, sec_findings: list,
                   external: bool, device_type: str = "") -> dict:
    """
    Composite risk score (0–100).

    Formula: base + cve_contribution + auth_finding + network_adjustment
    Thresholds: CRITICAL ≥75, HIGH ≥50, MEDIUM ≥25, LOW <25

    Context cap for internal services:
      Internal SSH/SMB/HTTP with CVE-only or protocol-advisory-only risk and
      no confirmed authentication failure is capped at MEDIUM (score ≤49).
      The cap is removed if any of the following are true:
        - The host is externally routable
        - A CRITICAL CVE (≥9.0) was matched
        - An active auth failure was confirmed (Redis no-auth, FTP anon, VNC
          no-password, MongoDB open, etc.)
      SSHv1 active is treated as an auth failure because it is a critical
      protocol break, not just a version advisory.
    """
    # Categories that represent confirmed, active authentication or access failures.
    # Version advisories like "Outdated OpenSSH" are intentionally excluded because
    # they are version observations, not confirmed access issues.
    _AUTH_FAILURE_CHECKS = {
        "FTP Anonymous Login",
        "Redis No Authentication",
        "MongoDB No Authentication",
        "Elasticsearch Open API",
        "VNC No Authentication",
        "SNMP Default Community 'public'",
        "SSHv1 Active",           # protocol break, not just advisory
    }

    factors = []

    base = 0
    if port in _INHERENT_RISK:
        base, reason = _INHERENT_RISK[port]; factors.append(reason)

    cve_score = 0
    cves = cve_result.get("cves",[])
    top_cvss_val = 0
    if cves and cve_result.get("confidence") == CONF_HIGH:
        scores    = [c["score"] or 0 for c in cves]
        avg_cvss  = sum(scores)/len(scores)
        n_crit    = sum(1 for c in cves if c["severity"]=="CRITICAL")
        n_high    = sum(1 for c in cves if c["severity"]=="HIGH")
        cve_score = min(40, int(avg_cvss*3) + n_crit*5)
        top_cvss_val = max(scores)
        parts     = [f"avg CVSS {avg_cvss:.1f}"]
        if n_crit: parts.append(f"{n_crit} CRITICAL CVE(s)")
        if n_high: parts.append(f"{n_high} HIGH CVE(s)")
        factors.append(f"CVE ({', '.join(parts)}, top {top_cvss_val})")
    elif cve_result.get("advisory"):
        factors.append("Version unconfirmed — CVE match skipped")

    # Separate active auth failures from version/protocol advisories.
    # Only confirmed access failures override the internal severity cap.
    auth_score        = 0   # total from all security findings
    advisory_score    = 0   # from version/protocol advisories only
    auth_failure_score= 0   # from confirmed access failures only
    has_auth_failure  = False

    for sf in sec_findings:
        w = _AUTH_W.get(sf.severity, 0)
        if w > auth_score:
            auth_score = w
        if sf.check in _AUTH_FAILURE_CHECKS:
            has_auth_failure = True
            if w > auth_failure_score:
                auth_failure_score = w
        else:
            if w > advisory_score:
                advisory_score = w

    if auth_score > 0:
        top = max(sec_findings, key=lambda f: _AUTH_W.get(f.severity, 0))
        factors.append(f"Security: {top.check} ({top.severity})")

    net_adj = 15 if external else 0
    if external: factors.append("External IP (+15 exposure)")

    raw   = base + cve_score + auth_score + net_adj
    final = min(100, raw)

    # ── Context-aware cap for common internal services ────────────────────────
    internal_capped = False
    if (not external
            and not has_auth_failure
            and top_cvss_val < 9.0
            and final >= 50
            and port in (22, 2222, 445, 80, 443, 53)):
        final = 49
        internal_capped = True
        factors.append("Internal service — capped at MEDIUM "
                        "(no auth failure, no critical CVE, no external exposure)")

    level = ("CRITICAL" if final>=75 else "HIGH" if final>=50
             else "MEDIUM" if final>=25 else "LOW")

    return {
        "score":           final,
        "level":           level,
        "factors":         factors,
        "internal_capped": internal_capped,
        "breakdown": {
            "base":               base,
            "cve":                cve_score,
            "security_advisory":  advisory_score,
            "auth_failure":       auth_failure_score,
            "network_exposure":   net_adj,
        }
    }

# ──────────────────────────────────────────────────────────────────────────────
# ATTACK SURFACE SUMMARY
# Groups open services across all hosts — shows what the network is running
# and how many hosts expose each service type.
# ──────────────────────────────────────────────────────────────────────────────
def build_attack_surface(hosts: list) -> dict:
    """
    Attack surface summary with confidence-aware service labels.

    Uses service_evidence data from each port result so the attack surface
    reflects the same confidence level shown in detailed evidence — a heuristic
    IBM-DB2 fingerprint shows as "Possible IBM-DB2-like service (heuristic)"
    rather than "IBM-DB2" as if it were confirmed.

    Returns:
      service_entries:  list of {service, display_service, hosts, ips,
                                  confidence, fingerprint_source, version_confirmed}
      service_map:      {service: [ip,...]}  — for compatibility with existing code
      high_risk_svcs:   [(service, ip, reason)]
      header_by_host:   {ip: count}
    """
    # _HIGH_RISK_SVCS: services that warrant explicit flagging when observed
    # Note: SMB is listed here but wording is careful — "SMB exposure; verify config"
    # rather than implying EternalBlue/SMBv1 without confirmation.
    _HIGH_RISK_SVCS = {
        "Telnet":        "Cleartext protocol",
        "RDP":           "Remote desktop — brute-force target",
        "SMB":           "File sharing service — verify SMBv1 disabled and signing required",
        "Redis":         "Frequently misconfigured with no auth",
        "MongoDB":       "Frequently misconfigured with no auth",
        "Elasticsearch": "Often exposed unauthenticated",
        "VNC":           "Remote desktop — often no auth",
        "MSSQL":         "Database — SA brute-force risk",
        "Backdoor":      "Likely malicious — Metasploit default port",
        "rexec":         "Cleartext remote execution",
        "rlogin":        "Cleartext remote login",
        "TFTP":          "Unauthenticated file transfer",
    }

    # Accumulate per-service data keyed by canonical service name
    svc_data: dict  = {}  # service → {ips:set, display_service, confidence, fingerprint_source, version_confirmed}
    high_risk       = []
    header_by_host: dict = {}
    svc_map: dict   = {}   # legacy compat: service → [ip,...]

    for host in hosts:
        ip = host["ip"]
        h_header_count = 0

        for p in host.get("open_ports", []):
            svc     = p["service"]
            svc_ev  = p.get("service_evidence", {})
            conf    = svc_ev.get("service_confidence", "low")
            fsrc    = svc_ev.get("fingerprint_source", "port_signature")
            vconf   = svc_ev.get("version_confirmed", False)

            # display_service: apply the same "Possible ... -like service" rule used
            # in service_evidence() so the attack surface is always consistent even
            # when service_evidence is absent (e.g. older JSON, quick scan, no banner).
            if svc_ev.get("display_service"):
                disp = svc_ev["display_service"]
            elif not vconf and fsrc in ("port_signature", "heuristic"):
                disp = f"Possible {svc}-like service"
            else:
                disp = svc

            # Aggregate by canonical service name
            if svc not in svc_data:
                svc_data[svc] = {
                    "service":            svc,
                    "display_service":    disp,
                    "confidence":         conf,
                    "fingerprint_source": fsrc,
                    "version_confirmed":  vconf,
                    "ips":                set(),
                }
            svc_data[svc]["ips"].add(ip)
            # Keep best-confidence entry for the display label
            _conf_rank = {"high": 3, "medium": 2, "low": 1}
            if _conf_rank.get(conf, 0) > _conf_rank.get(svc_data[svc]["confidence"], 0):
                svc_data[svc]["confidence"]         = conf
                svc_data[svc]["display_service"]    = disp
                svc_data[svc]["fingerprint_source"] = fsrc
                svc_data[svc]["version_confirmed"]  = vconf

            # Legacy compat
            svc_map.setdefault(svc, [])
            if ip not in svc_map[svc]:
                svc_map[svc].append(ip)

            if svc in _HIGH_RISK_SVCS:
                high_risk.append((svc, ip, _HIGH_RISK_SVCS[svc]))

            for sf in p.get("security", []):
                if sf["category"] == "Header":
                    h_header_count += 1

        if h_header_count:
            header_by_host[ip] = h_header_count

    # Build sorted service_entries list (most hosts first)
    service_entries = []
    for svc, data in sorted(svc_data.items(), key=lambda x: -len(x[1]["ips"])):
        ips_list = sorted(data["ips"])
        service_entries.append({
            "service":            data["service"],
            "display_service":    data["display_service"],
            "hosts":              len(ips_list),
            "ips":                ips_list,
            "confidence":         data["confidence"],
            "fingerprint_source": data["fingerprint_source"],
            "version_confirmed":  data["version_confirmed"],
        })

    svc_map = dict(sorted(svc_map.items(), key=lambda x: -len(x[1])))
    return {
        "service_entries": service_entries,
        "service_map":     svc_map,         # kept for backwards compat
        "high_risk_svcs":  high_risk,
        "header_by_host":  header_by_host,
    }

# ──────────────────────────────────────────────────────────────────────────────
# EXECUTIVE SUMMARY  (with Top Risk Host + grouped header issues)
# ──────────────────────────────────────────────────────────────────────────────
def build_exec_summary(hosts: list, target: str, duration: float,
                       mode: str, cve_since: int) -> dict:
    total_open = sum(len(h["open_ports"]) for h in hosts)
    total_cves = sum(sum(len(p["cve_result"]["cves"]) for p in h["open_ports"]) for h in hosts)
    crit_ports = [(h["ip"],p) for h in hosts for p in h["open_ports"] if p["risk"]["level"]=="CRITICAL"]
    high_ports = [(h["ip"],p) for h in hosts for p in h["open_ports"] if p["risk"]["level"]=="HIGH"]
    auth_crits = [(h["ip"],p,sf) for h in hosts for p in h["open_ports"]
                  for sf in p.get("security",[]) if sf["severity"]=="CRITICAL"]

    all_levels  = [p["risk"]["level"] for h in hosts for p in h["open_ports"]]
    level_order = {"CRITICAL":4,"HIGH":3,"MEDIUM":2,"LOW":1}
    overall     = max(all_levels, key=lambda l:level_order.get(l,0)) if all_levels else "LOW"

    # ── Top Risk Host ────────────────────────────────────────────────────────
    host_scores = {}
    host_reasons = {}
    for host in hosts:
        ip    = host["ip"]
        score = max((p["risk"]["score"] for p in host["open_ports"]), default=0)
        host_scores[ip] = score
        # Find most significant reason for this host's risk
        reasons = []
        for p in host["open_ports"]:
            if p["risk"]["score"] == score:
                reasons.extend(p["risk"]["factors"][:2])
        host_reasons[ip] = reasons

    top_risk_host = max(host_scores, key=host_scores.get) if host_scores else ""
    top_risk_score = host_scores.get(top_risk_host, 0)
    top_risk_reasons = host_reasons.get(top_risk_host, [])

    # ── Key findings ─────────────────────────────────────────────────────────
    key_findings = []
    if crit_ports:
        key_findings.append(f"{len(crit_ports)} CRITICAL port(s) found — immediate attention required")
    if auth_crits:
        svc_list = list({p["service"] for _,p,_ in auth_crits})[:4]
        key_findings.append(f"{len(auth_crits)} unauthenticated service(s): {', '.join(svc_list)}")
    if any(SERVICE_MAP.get(p["port"],"")=="Telnet" for h in hosts for p in h["open_ports"]):
        key_findings.append("Telnet detected — replace with SSH immediately")
    if any(sf["check"]=="SMBv1 Enabled" for h in hosts
           for p in h["open_ports"] for sf in p.get("security",[])):
        key_findings.append("SMBv1 enabled — vulnerable to EternalBlue (MS17-010 / WannaCry)")
    if total_cves > 0:
        key_findings.append(f"{total_cves} CVE(s) matched (version-confirmed, {cve_since}+ only)")

    # ── Remediations ─────────────────────────────────────────────────────────
    rems, seen_rem = [], set()
    for _,p,sf in auth_crits:
        if sf["remediation"] and sf["remediation"] not in seen_rem:
            seen_rem.add(sf["remediation"]); rems.append(sf["remediation"])
    for _,p in crit_ports:
        for sf in p.get("security",[]):
            if sf["remediation"] and sf["remediation"] not in seen_rem:
                seen_rem.add(sf["remediation"]); rems.append(sf["remediation"])

    return {
        "overall_risk":      overall,
        "hosts_scanned":     len(hosts),
        "open_ports":        total_open,
        "cves_matched":      total_cves,
        "critical_ports":    len(crit_ports),
        "high_ports":        len(high_ports),
        "auth_issues":       len(auth_crits),
        "key_findings":      key_findings,
        "top_remediations":  rems[:8],
        "top_risk_host":     top_risk_host,
        "top_risk_score":    top_risk_score,
        "top_risk_reasons":  top_risk_reasons,
        "scan_target":       target,
        "scan_duration":     duration,
        "scan_mode":         mode,
        "cve_since":         cve_since,
    }


# ──────────────────────────────────────────────────────────────────────────────
# EXPLAINABLE FINDINGS · REMEDIATION PRIORITIES · BASELINE COMPARISON · REDACTION
# ──────────────────────────────────────────────────────────────────────────────

FINDINGS_SCHEMA_VERSION = "1.0"

def build_structured_findings(hosts: list) -> list:
    """
    Produce a flat list of analyst-readable findings.

    One finding per service observation, not one per CVE.
    CVEs are attached as evidence within the finding.

    Finding types:
      - cve_match:       confirmed version with matched CVEs
      - security_check:  active probe result (auth failure, protocol issue)
      - service_exposure: high-risk service detected (SMB, RDP, Telnet)
      - http_headers:    aggregated header hardening finding per host
    """
    findings = []
    ts       = datetime.now().isoformat()

    # Priority label mapping from risk + finding type
    def _priority_for(risk_level: str, finding_type: str, top_cvss: float = 0.0,
                      has_auth_failure: bool = False) -> str:
        if has_auth_failure: return "CRITICAL"
        if top_cvss >= 9.0:  return "CRITICAL"
        if risk_level == "CRITICAL": return "CRITICAL"
        if risk_level == "HIGH":     return "HIGH"
        if top_cvss >= 7.0:          return "HIGH"
        if risk_level == "MEDIUM":   return "MEDIUM"
        return "LOW"

    for host in hosts:
        ip       = host["ip"]
        asset    = host.get("asset", {})
        hostname = asset.get("hostname", "Unknown")
        dtype    = asset.get("device_type", "Unknown")

        for port_data in host.get("open_ports", []):
            port    = port_data["port"]
            service = port_data["service"]
            banner  = port_data.get("banner", "")
            ver     = port_data.get("version", {})
            risk    = port_data.get("risk", {})
            cve_res = port_data.get("cve_result", {})
            cves    = cve_res.get("cves", [])

            product     = ver.get("product", "")
            version_str = ver.get("version", "")
            conf        = ver.get("confidence", "low")
            risk_level  = risk.get("level", "LOW")
            risk_score  = risk.get("score", 0)

            # ── CVE match finding (one per service, CVEs as evidence list) ────
            if cves and cve_res.get("confidence") == "high":
                top_cvss  = max((c.get("score") or 0) for c in cves)
                n_crit    = sum(1 for c in cves if c["severity"] == "CRITICAL")
                n_high    = sum(1 for c in cves if c["severity"] == "HIGH")
                ver_label = f"{product} {version_str}".strip()
                priority  = _priority_for(risk_level, "cve_match", top_cvss)

                why = _cve_why_it_matters(service, product, cves[0]["severity"])
                rec = _cve_recommendation(service, product, version_str)

                findings.append({
                    "finding_id":   f"CVE_MATCH_{ip.replace('.','_')}_{port}",
                    "finding_type": "cve_match",
                    "title":        f"Outdated or potentially vulnerable {ver_label} detected",
                    "ip":           ip,
                    "hostname":     hostname,
                    "device_type":  dtype,
                    "port":         port,
                    "service":      service,
                    "risk":         risk_level,
                    "risk_score":   risk_score,
                    "priority":     priority,
                    "confidence":   "high",
                    "sources":      asset.get("sources", []) + ["service_banner"],
                    "evidence": {
                        "banner":        banner[:120] if banner not in ("No banner","Skipped") else "",
                        "product":       product,
                        "version":       version_str,
                        "cves_matched":  len(cves),
                        "highest_cvss":  top_cvss,
                        "critical_cves": n_crit,
                        "high_cves":     n_high,
                        "cve_ids":       [c["id"] for c in cves[:5]],
                    },
                    "why_it_matters":  why,
                    "recommendation":  rec,
                    "verification":    (
                        f"Confirm the installed version of {product} on the host. "
                        f"Verify whether security patches have been applied by the "
                        f"distribution even if the version string appears outdated."
                    ),
                    "false_positive_note": (
                        f"Version confirmed from service banner. "
                        f"Distribution-applied patches may address some CVEs even if "
                        f"the version string has not changed."
                    ),
                    "status":    "detected",
                    "timestamp": ts,
                })

            # ── Security check findings (one per meaningful check) ─────────────
            #
            # Version-advisory checks like "Outdated OpenSSH" and "OpenSSH Below 9.x"
            # describe the same observation as a CVE-match finding on the same port.
            # When a CVE-match finding already exists for this ip:port, we skip the
            # advisory as a standalone finding and instead record it as a contributing
            # factor inside the CVE finding's evidence. This prevents two cards in
            # the report that say the same thing about the same asset.
            #
            # Checks that represent confirmed active failures (Redis no-auth, FTP
            # anonymous login, etc.) are never suppressed — they carry independent
            # meaning that the CVE finding does not cover.

            _VERSION_ADVISORY_CHECKS = {"Outdated OpenSSH", "OpenSSH Below 9.x"}

            for sf in port_data.get("security", []):
                if sf.get("severity") in ("INFO",):
                    continue
                if sf.get("category") == "Header":
                    continue

                check = sf.get("check", "")

                # Suppress version advisories when a CVE finding already exists
                # for the same ip:port — fold the detail into that finding instead.
                if check in _VERSION_ADVISORY_CHECKS and cves and cve_res.get("confidence") == "high":
                    # The CVE finding was already appended above. Find it and
                    # add the advisory as a contributing factor in its evidence.
                    for existing in findings:
                        if (existing.get("finding_type") == "cve_match"
                                and existing.get("ip") == ip
                                and existing.get("port") == port):
                            existing["evidence"].setdefault("contributing_factors", [])
                            existing["evidence"]["contributing_factors"].append(
                                f"{check}: {sf.get('detail','')}"
                            )
                    continue   # do not create a separate finding card

                sev     = sf.get("severity", "")
                is_auth = check in {
                    "FTP Anonymous Login", "Redis No Authentication",
                    "MongoDB No Authentication", "Elasticsearch Open API",
                    "VNC No Authentication", "SNMP Default Community 'public'",
                    "SSHv1 Active",
                }
                priority = _priority_for(risk_level, "security_check",
                                         has_auth_failure=is_auth)

                why     = _seccheck_why(check, service, port)
                fp_note = _seccheck_fp_note(check, sf.get("category", ""))

                findings.append({
                    "finding_id":   f"{check.upper().replace(' ','_')}_{ip.replace('.','_')}_{port}",
                    "finding_type": "security_check",
                    "title":        check,
                    "ip":           ip,
                    "hostname":     hostname,
                    "device_type":  dtype,
                    "port":         port,
                    "service":      service,
                    "risk":         risk_level,
                    "risk_score":   risk_score,
                    "priority":     priority,
                    "confidence":   "high",
                    "sources":      ["active_probe"],
                    "evidence": {
                        "detail":  sf.get("detail", ""),
                        "port":    port,
                        "service": service,
                        "banner":  banner[:80] if banner not in ("No banner", "Skipped") else "",
                    },
                    "why_it_matters":    why,
                    "recommendation":    sf.get("remediation", ""),
                    "verification":      f"Manually verify {check} on {hostname} ({ip}).",
                    "false_positive_note": fp_note,
                    "status":    "detected",
                    "timestamp": ts,
                })

        # ── HTTP header aggregation (one finding per host) ─────────────────────
        all_header_issues = []
        for port_data in host.get("open_ports", []):
            for sf in port_data.get("security", []):
                if sf.get("category") == "Header" and sf.get("severity") not in ("INFO",):
                    all_header_issues.append({
                        "port":    port_data["port"],
                        "service": port_data["service"],
                        "check":   sf.get("check",""),
                        "detail":  sf.get("detail",""),
                        "fix":     sf.get("remediation",""),
                    })

        if all_header_issues:
            missing = list(dict.fromkeys(i["check"] for i in all_header_issues))
            is_embedded = _is_embedded_device_type(
                host.get("asset",{}).get("device_type","")
            )
            findings.append({
                "finding_id":   f"HTTP_HEADERS_{ip.replace('.','_')}",
                "finding_type": "http_headers",
                "title":        f"HTTP security headers — hardening items",
                "ip":           ip,
                "hostname":     hostname,
                "device_type":  dtype,
                "port":         None,
                "service":      "HTTP/HTTPS",
                "risk":         "LOW",
                "risk_score":   0,
                "priority":     "LOW",
                "confidence":   "high",
                "sources":      ["http_response"],
                "evidence": {
                    "missing_headers": missing,
                    "count":           len(missing),
                    "is_embedded_device": is_embedded,
                },
                "why_it_matters": (
                    "Missing security headers reduce browser-level protections. "
                    "Most relevant on user-facing web applications. "
                    + ("On this device type, these are lower-priority hardening items "
                       "unless the interface is reachable outside the local network."
                       if is_embedded else
                       "Verify whether this interface is user-facing before prioritising.")
                ),
                "recommendation": (
                    "Add missing headers to web services you control. "
                    "Focus on HSTS for HTTPS services and CSP for user-facing apps first."
                ),
                "verification": (
                    "Review which web interfaces on this host are user-facing or externally "
                    "accessible. Apply headers selectively where they provide real protection."
                ),
                "false_positive_note": (
                    "Some headers are not applicable in all contexts. "
                    "HSTS only applies to HTTPS. Verify before treating as urgent."
                ),
                "status":    "detected",
                "timestamp": ts,
            })

    # Sort: CRITICAL/HIGH first, then by risk_score, deprioritise http_headers
    _type_order = {"cve_match":0,"security_check":0,"service_exposure":1,"http_headers":2}
    _sev_order  = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"UNKNOWN":4}
    findings.sort(key=lambda f: (
        _type_order.get(f["finding_type"],1),
        _sev_order.get(f["priority"],4),
        -f["risk_score"]
    ))
    return findings


def _cve_why_it_matters(service: str, product: str, severity: str) -> str:
    """Return a plain-English explanation of why this CVE class matters."""
    sl = service.lower()
    pl = product.lower()

    if "openssh" in pl or sl == "ssh":
        return (
            "Older OpenSSH versions may contain security issues. "
            "The actual impact depends on the specific CVE, distribution patches, "
            "and whether SSH is exposed beyond the local network."
        )
    if sl in ("http","https") or "apache" in pl or "nginx" in pl or "iis" in pl:
        return (
            "Web server vulnerabilities may allow attackers to access files, execute "
            "code, or disrupt service depending on the specific flaw. Impact varies "
            "significantly by CVE."
        )
    if "openssl" in pl:
        return (
            "OpenSSL is used by many services to handle TLS encryption. "
            "Vulnerabilities can affect confidentiality of traffic or allow "
            "downgrade attacks in some cases."
        )
    if sl in ("smb","netbios-ssn","msrpc"):
        return (
            "SMB vulnerabilities are historically high-impact. Exploits like "
            "EternalBlue (MS17-010) were used by WannaCry and NotPetya ransomware. "
            "SMB should not be exposed beyond trusted hosts."
        )
    if sl == "rdp":
        return (
            "RDP vulnerabilities can allow remote code execution without authentication "
            "in some versions. RDP should be restricted to VPN or trusted IPs and "
            "kept up to date."
        )
    if severity == "CRITICAL":
        return (
            "This CVE is rated CRITICAL, typically indicating potential for remote code "
            "execution or significant data exposure with minimal attacker requirements. "
            "Review the CVE details and verify patch status."
        )
    return (
        "Review the linked CVE for specific impact details. "
        "The risk depends on whether the service is exposed, whether the version is "
        "confirmed vulnerable, and whether a patch is available."
    )


def _cve_recommendation(service: str, product: str, version: str) -> str:
    """Produce a concrete, not overstated, recommendation."""
    pl = product.lower()

    if "openssh" in pl:
        return (
            f"Upgrade OpenSSH using the host's package manager. "
            f"For Debian/Raspberry Pi OS/Ubuntu, use apt. "
            f"For RHEL/CentOS/Fedora, use dnf or yum. "
            f"Restart SSH after upgrading and verify the installed version."
        )
    if "apache" in pl:
        return (
            f"Upgrade Apache httpd from {version}. Check your distribution's "
            "package manager or apache.org for the current stable release. "
            "Review release notes for security fixes between your version and current."
        )
    if "nginx" in pl:
        return (
            f"Upgrade nginx from {version} to the latest stable branch. "
            "nginx.org/en/download.html lists current stable and mainline releases."
        )
    if "openssl" in pl:
        return (
            f"Upgrade OpenSSL from {version}. This is usually handled via your "
            "OS package manager. Check openssl.org/news for affected versions."
        )
    return (
        f"Review the CVE details and check whether a patch is available for "
        f"{product} {version}. Check the vendor's security advisories and your "
        "package manager for updates."
    )


def _seccheck_why(check: str, service: str, port: int) -> str:
    """Plain-language explanation for security check findings."""
    cl = check.lower()

    if "telnet" in cl:
        return (
            "Telnet sends everything in plaintext, including login credentials. "
            "Anyone on the same network who can intercept traffic will see usernames "
            "and passwords. There is no justification for using Telnet in 2024 — "
            "SSH provides equivalent functionality with encryption."
        )
    if "smb" in cl and "v1" in cl:
        return (
            "SMBv1 is an outdated file-sharing protocol with serious known vulnerabilities. "
            "The EternalBlue exploit (CVE-2017-0144) targets SMBv1 and was used by the "
            "WannaCry and NotPetya ransomware attacks. Disabling it has no practical downside "
            "for modern systems."
        )
    if "smb signing" in cl:
        return (
            "When SMB signing is not required, an attacker on the local network can "
            "intercept authentication and relay it to another system (NTLM relay attack). "
            "This is a well-documented technique used in internal network attacks."
        )
    if "smb" in cl:
        return (
            "SMB is reachable on this host. SMBv1 status and the specific SMB "
            "version were not confirmed by this scan. SMBv1, if enabled, has known "
            "critical vulnerabilities. Verify the configuration directly on the host."
        )
    if "redis" in cl and "no auth" in cl:
        return (
            "Redis is a database and cache service. When running without authentication, "
            "any host on the network can read and write all data it contains. "
            "In some configurations, Redis can also be used to write files or schedule "
            "commands on the host system."
        )
    if "mongodb" in cl and "no auth" in cl:
        return (
            "MongoDB is running without access control. Any host on the network can "
            "read, modify, or delete all databases. Previous MongoDB exposure incidents "
            "have resulted in large-scale data theft."
        )
    if "elasticsearch" in cl:
        return (
            "Elasticsearch is returning data without authentication. "
            "All indexed data is accessible to any host on the network. "
            "If the index contains sensitive data, this is a significant exposure."
        )
    if "snmp" in cl:
        return (
            "SNMP with the default 'public' community string allows read access to "
            "system information including interfaces, routing tables, and device configuration. "
            "Some devices also support write access with the 'private' community string."
        )
    if "vnc" in cl and "no auth" in cl:
        return (
            "VNC without authentication allows anyone on the network to view and "
            "control this device's desktop immediately. This is a complete remote "
            "access exposure."
        )
    if "openssh" in cl or "outdated" in cl:
        return (
            "Older SSH versions may contain known bugs including username enumeration "
            "and in some cases pre-authentication vulnerabilities. Modern OpenSSH also "
            "supports better cipher suites and key exchange algorithms."
        )
    if "ftp anon" in cl:
        return (
            "Anonymous FTP allows unauthenticated users to access and potentially "
            "modify files on this server. This is rarely intentional on home networks."
        )
    return (
        f"{check} was detected on port {port}. "
        "Review the finding details and the recommended action below."
    )


def _seccheck_fp_note(check: str, category: str) -> str:
    """Return a note about false-positive likelihood for this check type."""
    cl = check.lower()
    if "smb" in cl:
        return (
            "SMB findings are based on active protocol negotiation. "
            "The SMBv1 check sends a real negotiate packet and observes the response. "
            "The signing check reads the security mode byte from the response. "
            "Both are reliable when the port responds."
        )
    if "redis" in cl:
        return (
            "The Redis check sends a PING command and looks for a +PONG response. "
            "If the server responds with PONG, it is confirmed that no authentication "
            "is required. This is a reliable test."
        )
    if "mongodb" in cl:
        return (
            "The MongoDB check sends a minimal isMaster query. "
            "If a valid response is returned without an authentication error, "
            "the database is accessible without credentials."
        )
    if "telnet" in cl:
        return (
            "Port 23 is open and confirmed reachable. "
            "Telnet is inherently insecure regardless of what is running on the port."
        )
    if "vnc" in cl:
        return (
            "The VNC check reads the RFB security type list from the server. "
            "Security type 1 means no authentication. This is a direct protocol observation."
        )
    if "openssh" in cl or "outdated" in cl:
        return (
            "The OpenSSH version was read from the SSH banner. "
            "SSH servers typically disclose their version. "
            "Whether a specific CVE applies depends on build configuration and patches "
            "applied by the distribution."
        )
    return "This finding is based on direct observation of service behavior."


# ──────────────────────────────────────────────────────────────────────────────
# REMEDIATION PRIORITY ENGINE
#
# Produces a ranked list of actionable items a real analyst would act on first.
# Not every finding makes it into priorities — the goal is signal, not volume.
#
# Scoring factors:
#   - Confirmed CVEs with CVSS >= 7.0
#   - Active auth failures (Redis/Mongo/ES with no creds)
#   - Unsafe protocols (Telnet, SMBv1)
#   - Remote access exposure (SSH outdated, RDP, VNC)
#   - Affects lateral movement potential
# ──────────────────────────────────────────────────────────────────────────────

def build_remediation_priorities(hosts: list, findings: list) -> list:
    """
    Returns a ranked list of remediation items, max 10.

    Two distinct labels are maintained:
      priority — how urgently this should be addressed (HIGH/MEDIUM/LOW)
                 based on exploitability, exposure, and actionability
      risk     — the risk level calculated for that specific port/service
                 (from calculate_risk, may differ from priority)

    These are intentionally separate. A finding can be HIGH priority to fix
    (e.g. outdated SSH on an active server) while the calculated risk is MEDIUM
    because no auth failure or external exposure was confirmed.
    """
    candidates = []

    for host in hosts:
        ip       = host["ip"]
        asset    = host.get("asset", {})
        hostname = asset.get("hostname", ip)
        dtype    = asset.get("device_type", "")

        for p in host.get("open_ports", []):
            port       = p["port"]
            service    = p["service"]
            risk_dict  = p.get("risk", {})
            risk_level = risk_dict.get("level", "LOW")   # calculated risk for this port
            cve_res    = p.get("cve_result", {})
            cves       = cve_res.get("cves", [])
            ver        = p.get("version", {})
            product    = ver.get("product", service)
            version    = ver.get("version", "")
            banner     = p.get("banner", "")

            priority_score = 0
            priority_level = "LOW"   # separate from risk_level
            reasons        = []
            action         = ""

            # ── Confirmed CVEs (version-matched) ─────────────────────────────
            if cves and cve_res.get("confidence") == "high":
                top_cvss = max(c.get("score") or 0 for c in cves)
                n_crit   = sum(1 for c in cves if c["severity"] == "CRITICAL")
                n_high   = sum(1 for c in cves if c["severity"] == "HIGH")

                if top_cvss >= 9.0:
                    priority_score += 80; priority_level = "CRITICAL"
                elif top_cvss >= 7.0:
                    priority_score += 55; priority_level = "HIGH"
                elif top_cvss >= 5.0:
                    priority_score += 30; priority_level = "MEDIUM"

                ver_str = f"{product} {version}".strip()
                reasons.append(f"Version confirmed ({ver_str}), {len(cves)} CVE(s) matched, top CVSS {top_cvss}")
                action  = _cve_recommendation(service, product, version)

            # ── Active auth failures ─────────────────────────────────────────
            for sf in p.get("security", []):
                check = sf.get("check", "")
                sev   = sf.get("severity", "")

                if sev == "CRITICAL" and "no auth" in check.lower():
                    priority_score += 90; priority_level = "CRITICAL"
                    reasons.append(f"{check} — service accessible without credentials")
                    action  = sf.get("remediation", "")
                elif sev == "CRITICAL":
                    priority_score += 70; priority_level = "CRITICAL"
                    reasons.append(check)
                    action  = sf.get("remediation", "")
                elif sev == "HIGH" and "telnet" in check.lower():
                    priority_score += 60; priority_level = "HIGH"
                    reasons.append("Telnet transmits credentials in plaintext")
                    action  = "Disable Telnet; use SSH for remote access."
                elif sev == "HIGH" and "smb" in check.lower() and "v1" in check.lower():
                    priority_score += 55; priority_level = "HIGH"
                    reasons.append("SMBv1 is enabled — EternalBlue vector")
                    action  = sf.get("remediation", "")
                elif sev == "HIGH" and "openssh" in check.lower():
                    if priority_score < 45:
                        priority_score += 45; priority_level = "HIGH"
                        reasons.append(check)
                        action  = sf.get("remediation", "")
                elif sev == "MEDIUM" and "smb signing" in check.lower():
                    priority_score += 20
                    if not reasons:
                        reasons.append(check)
                        action  = sf.get("remediation", "")
                        priority_level = "MEDIUM"

            # ── Inherent service risk (no CVEs, no auth failure) ─────────────
            if not reasons:
                if service in ("Telnet","rexec","rlogin"):
                    priority_score += 55; priority_level = "HIGH"
                    reasons.append(f"{service} is a cleartext protocol")
                    action  = "Replace with SSH or remove the service."
                elif service == "RDP" and priority_score < 30:
                    priority_score += 30; priority_level = "MEDIUM"
                    reasons.append("RDP is exposed — brute-force target; verify access controls")
                    action  = "Restrict RDP to trusted IPs or tunnel through VPN."
                elif service == "SMB" and priority_score < 25:
                    priority_score += 25; priority_level = "MEDIUM"
                    reasons.append("SMB is exposed — verify sharing config and SMBv1 status")
                    action  = (
                        "Run: Get-SmbServerConfiguration | Select EnableSMB1Protocol, "
                        "RequireSecuritySignature. Disable SMBv1 if enabled."
                    )

            if priority_score > 0 and reasons and action:
                disp_name = hostname if hostname not in ("Unknown","") else ip
                candidates.append({
                    "ip":           ip,
                    "hostname":     disp_name,
                    "device_type":  dtype,
                    "port":         port,
                    "service":      service,
                    "priority":     priority_level,   # how urgently to address
                    "risk":         risk_level,        # calculated risk for the port
                    "severity":     priority_level,    # kept for backwards compat
                    "score":        priority_score,
                    "reasons":      reasons,
                    "action":       action,
                })

    # Aggregate HTTP header issues across all hosts as a single low-priority item
    http_hosts = set()
    for host in hosts:
        for p in host.get("open_ports", []):
            for sf in p.get("security", []):
                if sf.get("category") == "Header" and sf.get("severity") not in ("INFO",):
                    http_hosts.add(host["ip"])
    if len(http_hosts) >= 2:
        candidates.append({
            "ip":          "multiple",
            "hostname":    f"{len(http_hosts)} hosts",
            "device_type": "",
            "port":        80,
            "service":     "HTTP",
            "priority":    "LOW",
            "risk":        "LOW",
            "severity":    "LOW",
            "score":       10,
            "reasons":     [
                f"{len(http_hosts)} web services are missing security headers "
                "(CSP, HSTS, X-Frame-Options, etc.)"
            ],
            "action": (
                "Add missing headers to web services you control. "
                "Priority: HSTS on HTTPS services, CSP on user-facing apps. "
                "Skip headers that don't apply (HSTS on HTTP, for example)."
            ),
        })

    candidates.sort(key=lambda x: -x["score"])
    seen_keys = set()
    ranked = []
    for i, c in enumerate(candidates, 1):
        key = f"{c['ip']}:{c['port']}:{c['service']}"
        if key not in seen_keys:
            seen_keys.add(key)
            c["rank"] = i
            ranked.append(c)
        if len(ranked) >= 10:
            break

    return ranked


def build_verification_notes() -> list:
    """
    Plain-language notes about what this tool does and does not guarantee.
    Included in terminal output, JSON, and HTML reports.
    These are honest descriptions of the methodology, not legal disclaimers.
    """
    return [
        "CVE matching is version-confirmed only. CVEs are assigned when both "
        "product name and version are confirmed from the service banner. If the "
        "version is unavailable, CVE matching is skipped and the report says so.",

        "SMB, RDP, and similar services may appear in findings without CVEs if "
        "the software version could not be confirmed from the banner.",

        "HTTP security header checks are hardening findings, not evidence of "
        "exploitability. On routers, Chromecasts, and embedded devices, missing "
        "headers are typically lower priority unless the interface is reachable "
        "outside the trusted LAN.",

        "Device names and types are inferred from available signals: reverse DNS, "
        "NetBIOS, mDNS, HTTP page title, TLS certificate CN, MAC vendor OUI, "
        "and open port combinations. If no signal is available, the device is "
        "listed as Unknown rather than guessed.",

        "Risk scores are conservative for internal services. An internal service "
        "with CVE matches but no confirmed authentication failure is capped at "
        "MEDIUM unless a critical CVE or external exposure is present.",

        "Results should be manually verified before taking remediation action. "
        "This tool is a starting point for assessment, not a definitive audit.",
    ]


# ──────────────────────────────────────────────────────────────────────────────
# BASELINE COMPARISON
#
# Compares the current scan against a previously saved JSON report.
# Detects: new/removed hosts, new/closed ports, new services, risk changes,
# device type changes, hostname changes.
#
# Usage: python scanner.py --baseline previous_report.json
# ──────────────────────────────────────────────────────────────────────────────

def build_scan_quality(hosts: list) -> dict:
    """
    Counts how much of the scan was confirmed vs inferred.

    This section is included in terminal, JSON, and HTML to make the
    conservative CVE design transparent — readers can see exactly how many
    services had confirmed versions, how many were heuristic, and how many
    CVE checks were skipped because versions were not available.

    Fields:
      version_confirmed       — ports where product+version extracted from banner
      version_unconfirmed     — ports where service was named but version unknown
      heuristic_fingerprints  — ports where service label came from port convention only
      assets_strong_identity  — hosts with high/medium confidence enrichment
      assets_unknown_identity — hosts where device type is "Unknown Device"
      cve_skipped_no_version  — ports where CVE lookup was skipped (medium/low confidence)
      cves_matched            — total CVEs matched across confirmed services
    """
    version_confirmed    = 0
    version_unconfirmed  = 0
    heuristic_fp         = 0
    cve_skipped          = 0
    cves_matched         = 0
    strong_identity      = 0
    unknown_identity     = 0

    for host in hosts:
        asset = host.get("asset", {})
        conf  = asset.get("confidence", "low")
        dtype = asset.get("device_type", "Unknown Device")

        if conf in ("high", "medium") and dtype not in ("Unknown Device", "Unknown"):
            strong_identity += 1
        else:
            unknown_identity += 1

        for p in host.get("open_ports", []):
            svc_ev = p.get("service_evidence", {})
            if svc_ev.get("version_confirmed"):
                version_confirmed += 1
            elif svc_ev.get("fingerprint_source") == "heuristic":
                heuristic_fp += 1
            else:
                version_unconfirmed += 1

            cve_res = p.get("cve_result", {})
            if cve_res.get("advisory"):      # advisory = version not confirmed
                cve_skipped += 1
            elif cve_res.get("confidence") in ("low",) and not cve_res.get("cves"):
                cve_skipped += 1
            cves_matched += len(cve_res.get("cves", []))

    return {
        "version_confirmed":      version_confirmed,
        "version_unconfirmed":    version_unconfirmed,
        "heuristic_fingerprints": heuristic_fp,
        "assets_strong_identity": strong_identity,
        "assets_unknown_identity":unknown_identity,
        "cve_skipped_no_version": cve_skipped,
        "cves_matched":           cves_matched,
    }
    """Load a previously saved Heimdall JSON report as a baseline."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        # Normalise: build ip → host_data index
        baseline = {}
        for host in data.get("hosts", []):
            baseline[host["ip"]] = host
        return baseline
    except FileNotFoundError:
        print(f"\n  {clr('[!]',C.YELLOW)} Baseline file not found: {path}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"\n  {clr('[!]',C.YELLOW)} Could not parse baseline file: {e}")
        sys.exit(1)


def compare_to_baseline(current_hosts: list, baseline: dict) -> dict:
    """
    Diff current scan against baseline.
    Returns a structured change report including finding verification status.
    """
    current_by_ip = {h["ip"]: h for h in current_hosts}
    current_ips   = set(current_by_ip.keys())
    baseline_ips  = set(baseline.keys())

    new_hosts     = []
    removed_hosts = []
    changed_hosts = []

    # ── New and removed hosts ─────────────────────────────────────────────────
    for ip in sorted(current_ips - baseline_ips):
        host  = current_by_ip[ip]
        asset = host.get("asset", {})
        new_hosts.append({
            "ip":          ip,
            "hostname":    asset.get("hostname", "Unknown"),
            "device_type": asset.get("device_type", "Unknown"),
            "open_ports":  [p["port"] for p in host.get("open_ports", [])],
            "risk":        max((p["risk"]["level"] for p in host.get("open_ports",[])), default="LOW",
                              key=lambda l: {"CRITICAL":4,"HIGH":3,"MEDIUM":2,"LOW":1}.get(l,0)),
        })

    for ip in sorted(baseline_ips - current_ips):
        bh = baseline[ip]
        removed_hosts.append({
            "ip":         ip,
            "hostname":   bh.get("asset",{}).get("hostname","Unknown"),
            "last_ports": [p["port"] for p in bh.get("open_ports",[])],
        })

    # ── Changed hosts ─────────────────────────────────────────────────────────
    for ip in sorted(current_ips & baseline_ips):
        curr = current_by_ip[ip]
        prev = baseline[ip]

        curr_ports = {p["port"]: p for p in curr.get("open_ports", [])}
        prev_ports = {p["port"]: p for p in prev.get("open_ports", [])}

        curr_set = set(curr_ports.keys())
        prev_set = set(prev_ports.keys())

        new_ports       = []
        closed_ports    = []
        risk_changes    = []
        service_changes = []
        hostname_change = None

        for port in sorted(curr_set - prev_set):
            new_ports.append({
                "port":    port,
                "service": curr_ports[port].get("service",""),
                "risk":    curr_ports[port].get("risk",{}).get("level",""),
            })

        for port in sorted(prev_set - curr_set):
            closed_ports.append({
                "port":    port,
                "service": prev_ports[port].get("service",""),
            })

        for port in sorted(curr_set & prev_set):
            curr_risk = curr_ports[port].get("risk",{}).get("level","")
            prev_risk = prev_ports[port].get("risk",{}).get("level","")
            if curr_risk != prev_risk:
                risk_changes.append({
                    "port":     port,
                    "service":  curr_ports[port].get("service",""),
                    "previous": prev_risk,
                    "current":  curr_risk,
                })

            curr_ver = curr_ports[port].get("version",{})
            prev_ver = prev_ports[port].get("version",{})
            curr_v = f"{curr_ver.get('product','')} {curr_ver.get('version','')}".strip()
            prev_v = f"{prev_ver.get('product','')} {prev_ver.get('version','')}".strip()
            if curr_v and prev_v and curr_v != prev_v:
                service_changes.append({
                    "port":     port,
                    "service":  curr_ports[port].get("service",""),
                    "previous": prev_v,
                    "current":  curr_v,
                })

        curr_hostname = curr.get("asset",{}).get("hostname","")
        prev_hostname = prev.get("asset",{}).get("hostname","")
        if curr_hostname and prev_hostname and curr_hostname != prev_hostname:
            hostname_change = {"previous": prev_hostname, "current": curr_hostname}

        if any([new_ports, closed_ports, risk_changes, service_changes, hostname_change]):
            changed_hosts.append({
                "ip":               ip,
                "hostname":         curr.get("asset",{}).get("hostname","Unknown"),
                "new_ports":        new_ports,
                "closed_ports":     closed_ports,
                "risk_changes":     risk_changes,
                "service_changes":  service_changes,
                "hostname_change":  hostname_change,
            })

    # ── Finding verification: were previous findings resolved? ────────────────
    # Compare version strings on shared ports to detect upgrades.
    finding_verifications = []
    for ip in sorted(current_ips & baseline_ips):
        curr      = current_by_ip[ip]
        prev      = baseline[ip]
        hostname  = curr.get("asset",{}).get("hostname","Unknown")

        curr_ports_d = {p["port"]: p for p in curr.get("open_ports",[])}
        prev_ports_d = {p["port"]: p for p in prev.get("open_ports",[])}

        for port in sorted(set(curr_ports_d) & set(prev_ports_d)):
            cp = curr_ports_d[port]
            pp = prev_ports_d[port]

            curr_ver = cp.get("version",{})
            prev_ver = pp.get("version",{})
            curr_v   = f"{curr_ver.get('product','')} {curr_ver.get('version','')}".strip()
            prev_v   = f"{prev_ver.get('product','')} {prev_ver.get('version','')}".strip()
            service  = cp.get("service","")

            # Previous scan had CVEs, current scan has none (or fewer)
            prev_cves = pp.get("cve_result",{}).get("cves",[])
            curr_cves = cp.get("cve_result",{}).get("cves",[])

            if prev_v and curr_v and prev_v != curr_v and prev_cves:
                # Version changed and CVEs existed before
                if not curr_cves:
                    status = "remediated"
                    detail = f"Version updated: {prev_v} → {curr_v}. No CVEs matched on current version."
                else:
                    curr_top = max((c.get("score") or 0) for c in curr_cves)
                    prev_top = max((c.get("score") or 0) for c in prev_cves)
                    if curr_top < prev_top:
                        status = "improved"
                        detail = f"Version updated: {prev_v} → {curr_v}. CVE risk reduced (CVSS {prev_top} → {curr_top})."
                    else:
                        status = "changed"
                        detail = f"Version changed: {prev_v} → {curr_v}. CVEs still present."
                finding_verifications.append({
                    "ip":       ip,
                    "hostname": hostname,
                    "port":     port,
                    "service":  service,
                    "previous": prev_v,
                    "current":  curr_v,
                    "status":   status,
                    "detail":   detail,
                })
            elif prev_v and curr_v and prev_v == curr_v and prev_cves and curr_cves:
                finding_verifications.append({
                    "ip":       ip,
                    "hostname": hostname,
                    "port":     port,
                    "service":  service,
                    "previous": prev_v,
                    "current":  curr_v,
                    "status":   "still_present",
                    "detail":   f"{prev_v} on port {port} — {len(curr_cves)} CVE(s) still matched.",
                })

            # Check if a previously flagged open port is now closed (service remediated)
            prev_open_risk = pp.get("risk",{}).get("level","")
            if prev_open_risk in ("HIGH","CRITICAL") and port not in set(curr_ports_d):
                finding_verifications.append({
                    "ip":       ip,
                    "hostname": hostname,
                    "port":     port,
                    "service":  service,
                    "previous": f"Port open ({prev_open_risk})",
                    "current":  "Port closed",
                    "status":   "remediated",
                    "detail":   f"Port {port}/{service} was {prev_open_risk} risk in baseline — no longer open.",
                })

    has_changes = bool(new_hosts or removed_hosts or changed_hosts)
    return {
        "has_changes":            has_changes,
        "new_hosts":              new_hosts,
        "removed_hosts":          removed_hosts,
        "changed_hosts":          changed_hosts,
        "finding_verifications":  finding_verifications,
        "summary": {
            "new_hosts":          len(new_hosts),
            "removed_hosts":      len(removed_hosts),
            "changed_hosts":      len(changed_hosts),
            "new_ports":          sum(len(h["new_ports"]) for h in changed_hosts),
            "closed_ports":       sum(len(h["closed_ports"]) for h in changed_hosts),
            "remediated":         sum(1 for v in finding_verifications if v["status"]=="remediated"),
            "still_present":      sum(1 for v in finding_verifications if v["status"]=="still_present"),
            "risk_increases":     sum(
                1 for h in changed_hosts for rc in h["risk_changes"]
                if {"LOW":1,"MEDIUM":2,"HIGH":3,"CRITICAL":4}.get(rc["current"],0)
                 > {"LOW":1,"MEDIUM":2,"HIGH":3,"CRITICAL":4}.get(rc["previous"],0)
            ),
        },
    }


def print_baseline_diff(diff: dict):
    """Print a clean baseline comparison to terminal."""
    if not diff["has_changes"] and not diff.get("finding_verifications"):
        print(f"\n  {clr('No changes detected',C.GREEN,C.BOLD)} — network matches baseline.\n")
        return

    summ = diff["summary"]
    print(f"\n{clr('[ BASELINE CHANGES ]',C.CYAN,C.BOLD)}")
    print(f"  New: {summ['new_hosts']}  Removed: {summ['removed_hosts']}  "
          f"Changed: {summ['changed_hosts']}  "
          f"Remediated: {summ.get('remediated',0)}  "
          f"Still present: {summ.get('still_present',0)}")

    if diff["new_hosts"]:
        print(f"\n  {clr('New devices:',C.YELLOW,C.BOLD)}")
        for h in diff["new_hosts"]:
            hn    = h["hostname"] if h["hostname"] not in ("Unknown","") else "unknown hostname"
            dtype = h["device_type"] if h["device_type"] not in ("Unknown","Unknown Device") else ""
            ports = ", ".join(str(p) for p in h["open_ports"][:6])
            dtype_str = f" — {dtype}" if dtype else ""
            print(f"    {clr('+',C.GREEN)} {clr(h['ip'],C.BOLD)} ({hn}){dtype_str}")
            if ports:
                print(f"      Ports: {ports}")

    if diff["removed_hosts"]:
        print(f"\n  {clr('Removed devices:',C.DIM)}")
        for h in diff["removed_hosts"]:
            hn = h["hostname"] if h["hostname"] not in ("Unknown","") else "unknown hostname"
            print(f"    {clr('-',C.DIM)} {h['ip']} ({hn}) — no longer responding")

    if diff["changed_hosts"]:
        print(f"\n  {clr('Changes on existing hosts:',C.CYAN)}")
        for h in diff["changed_hosts"]:
            hn = h["hostname"] if h["hostname"] not in ("Unknown","") else h["ip"]
            print(f"\n    {clr(h['ip'],C.BOLD)} ({hn})")

            for np in h["new_ports"]:
                print(f"      {clr('+',C.GREEN)} Port {np['port']}/{np['service']} opened  [{np['risk']}]")
            for cp in h["closed_ports"]:
                print(f"      {clr('-',C.DIM)} Port {cp['port']}/{cp['service']} closed")
            for rc in h["risk_changes"]:
                up = {"LOW":1,"MEDIUM":2,"HIGH":3,"CRITICAL":4}
                arrow = clr("↑",C.RED) if up.get(rc["current"],0) > up.get(rc["previous"],0) else clr("↓",C.GREEN)
                print(f"      {arrow} Port {rc['port']}/{rc['service']}: "
                      f"{rc['previous']} → {clr(rc['current'],SEV_CLR.get(rc['current'],C.DIM))}")
            for sc in h["service_changes"]:
                print(f"      {clr('~',C.YELLOW)} Port {sc['port']}: {sc['previous']} → {sc['current']}")
            if h.get("hostname_change"):
                hc = h["hostname_change"]
                print(f"      {clr('~',C.YELLOW)} Hostname: {hc['previous']} → {hc['current']}")

    verifs = diff.get("finding_verifications", [])
    if verifs:
        print(f"\n  {clr('Finding verification:',C.CYAN)}")
        status_icons = {
            "remediated":   clr("✓  Remediated",  C.GREEN, C.BOLD),
            "still_present":clr("→  Still present",C.YELLOW),
            "improved":     clr("↑  Improved",     C.CYAN),
            "changed":      clr("~  Changed",      C.DIM),
        }
        for v in verifs:
            hn     = v["hostname"] if v["hostname"] not in ("Unknown","") else v["ip"]
            status = status_icons.get(v["status"], v["status"])
            print(f"    {status}  {hn} port {v['port']}/{v['service']}")
            print(f"      {clr(v['detail'], C.DIM)}")
    print()


# ──────────────────────────────────────────────────────────────────────────────
# REPORT PROFILES
#
# Controls what sections appear in the HTML/terminal output.
# home:          Plain-English summary, unknown devices, open services, top risks.
# small-business: Asset inventory, exposed services, remediations, baseline changes.
# technical:     Everything — banners, CVE details, confidence, raw scores, evidence.
# ──────────────────────────────────────────────────────────────────────────────

PROFILE_HOME = {
    "name":             "home",
    "show_banners":     False,
    "show_cvss_vector": False,
    "show_raw_scores":  False,
    "show_all_headers": False,
    "max_cves_shown":   3,
    "min_severity":     "MEDIUM",
    "description":      "Focused on unknown devices, open services, and findings that need attention.",
}
PROFILE_SMALL_BIZ = {
    "name":             "small-business",
    "show_banners":     False,
    "show_cvss_vector": True,
    "show_raw_scores":  False,
    "show_all_headers": True,
    "max_cves_shown":   5,
    "min_severity":     "LOW",
    "description":      "Asset inventory, service exposure, remediations, and baseline changes.",
}
PROFILE_TECHNICAL = {
    "name":             "technical",
    "show_banners":     True,
    "show_cvss_vector": True,
    "show_raw_scores":  True,
    "show_all_headers": True,
    "max_cves_shown":   8,
    "min_severity":     "INFO",
    "description":      "Full output — banners, CVE details, confidence, scoring breakdown, raw evidence.",
}
PROFILES = {
    "home":           PROFILE_HOME,
    "small-business": PROFILE_SMALL_BIZ,
    "technical":      PROFILE_TECHNICAL,
}


# ──────────────────────────────────────────────────────────────────────────────
# REDACTION
#
# Replaces personal hostnames, workstation names, and optionally IPs
# so scan results can be shared publicly (e.g., GitHub, forums).
#
# Usage: python scanner.py --redact
#        Produces a redacted copy of the report file.
#
# What it replaces:
#   - Hostnames that look personal (contain a name, not just a model number)
#   - MAC addresses
#   - Optionally: last octet of internal IPs
# ──────────────────────────────────────────────────────────────────────────────

def redact_results(results: dict) -> dict:
    """
    Return a deep copy of results with personal identifiers replaced.
    Does not modify the original dict.

    Replacement strategy:
      - Each unique personal hostname gets a stable label (WORKSTATION-1, etc.)
      - Device-type labels like "Raspberry Pi" or "Router (ASUS)" are kept as-is
        because they don't identify a person.
      - MAC addresses are replaced with XX:XX:XX:XX:XX:XX
      - IPs are kept by default (they're RFC-1918, not personally identifying)
    """
    import copy
    results = copy.deepcopy(results)

    hostname_map  = {}  # original → redacted label
    counters      = {
        "workstation": 0, "mobile": 0, "server": 0,
        "device": 0, "host": 0,
    }

    def _redact_hostname(hostname: str, device_type: str) -> str:
        if not hostname or hostname in ("Unknown",""):
            return hostname
        # Keep model numbers / device-type names — not personally identifying
        keeper_patterns = [
            r"^RT-",r"^AP-",r"^UAP",r"^USG",r"^ESP_",r"^BRWC",
            r"raspberrypi",r"(?i)router",r"(?i)printer",r"(?i)nas",
            r"(?i)chromecast",r"(?i)amazon",r"(?i)ring",r"(?i)roku",
        ]
        if any(re.search(p, hostname) for p in keeper_patterns):
            return hostname
        if hostname in hostname_map:
            return hostname_map[hostname]
        # Assign a category-based label
        dtl = device_type.lower()
        if any(k in dtl for k in ("iphone","ipad","android","mobile","phone")):
            counters["mobile"] += 1
            label = f"MOBILE-{counters['mobile']}"
        elif any(k in dtl for k in ("windows pc","workstation","laptop")):
            counters["workstation"] += 1
            label = f"WORKSTATION-{counters['workstation']}"
        elif any(k in dtl for k in ("server","linux","freebsd")):
            counters["server"] += 1
            label = f"SERVER-{counters['server']}"
        else:
            counters["host"] += 1
            label = f"HOST-{counters['host']}"
        hostname_map[hostname] = label
        return label

    # Walk the results tree
    for host in results.get("hosts", []):
        asset = host.get("asset", {})
        dtype = asset.get("device_type", "")
        if asset.get("hostname"):
            asset["hostname"] = _redact_hostname(asset["hostname"], dtype)
        if asset.get("mac_addr"):
            asset["mac_addr"] = "XX:XX:XX:XX:XX:XX"

    # Redact inventory
    for item in results.get("asset_inventory", []):
        dtype = item.get("device_type", "")
        if item.get("hostname"):
            item["hostname"] = _redact_hostname(item["hostname"], dtype)
        if item.get("mac_addr"):
            item["mac_addr"] = "XX:XX:XX:XX:XX:XX"

    # Redact findings
    for f in results.get("findings", []):
        if f.get("hostname"):
            f["hostname"] = hostname_map.get(f["hostname"], f["hostname"])

    # Redact exec summary top_risk_host reference (keep IP, redact name)
    summ = results.get("executive_summary", {})
    if summ.get("top_risk_host"):
        # Keep the IP — it's not personally identifying
        pass

    return results

# ══════════════════════════════════════════════════════════════════════════════
# ASSET ENRICHMENT MODULE
# Multi-source device identification: rDNS, NetBIOS, mDNS, HTTP title,
# TLS cert CN/SAN, banner hints, OUI/MAC vendor lookup.
# Runs concurrently, uses short timeouts, caches per IP.
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class AssetInfo:
    hostname:      str  = "Unknown"
    device_type:   str  = "Unknown"
    mac_vendor:    str  = ""
    mac_addr:      str  = ""
    confidence:    str  = "low"   # high / medium / low
    sources:       list = None    # enrichment sources used
    service_hints: list = None    # extra role hints from open ports (not device identity)

    def __post_init__(self):
        if self.sources is None:
            self.sources = []
        if self.service_hints is None:
            self.service_hints = []

    def display_name(self) -> str:
        if self.hostname and self.hostname != "Unknown":
            return self.hostname
        if self.device_type and self.device_type != "Unknown":
            return self.device_type
        return "Unknown"


# ── OUI / MAC Vendor database (top ~150 vendors covering most home networks) ──
# Format: first 6 hex chars (uppercase, no separators) → vendor name
_OUI_DB: dict = {
    # Apple
    "000393":"Apple","000502":"Apple","000A27":"Apple","000A95":"Apple",
    "000D93":"Apple","001124":"Apple","001451":"Apple","0016CB":"Apple",
    "001731":"Apple","001E52":"Apple","001EC2":"Apple","002241":"Apple",
    "002312":"Apple","002500":"Apple","0026B9":"Apple","0026BB":"Apple",
    "003065":"Apple","0050E4":"Apple","006171":"Apple","00617F":"Apple",
    "0C4DE9":"Apple","0C8385":"Apple","1C1AC0":"Apple","1C9E46":"Apple",
    "200DB0":"Apple","24A074":"Apple","283737":"Apple","2CF0EE":"Apple",
    "341298":"Apple","381C1A":"Apple","3C0754":"Apple","3C2EFF":"Apple",
    "3C7D0A":"Apple","400010":"Apple","404D7F":"Apple","40A6D9":"Apple",
    "480F4B":"Apple","48D705":"Apple","4C3275":"Apple","4C8D79":"Apple",
    "500746":"Apple","505354":"Apple","5C8D4E":"Apple","5CF7E6":"Apple",
    "60C547":"Apple","60F445":"Apple","6C709F":"Apple","6CF049":"Apple",
    "70700D":"Apple","70CD60":"Apple","74E2F5":"Apple","7831C1":"Apple",
    "7C6D62":"Apple","80BE05":"Apple","84FC AC":"Apple","880065":"Apple",
    "8C7B9D":"Apple","8C8590":"Apple","90FD61":"Apple","981DFA":"Apple",
    "9C04EB":"Apple","9CF387":"Apple","A45E60":"Apple","A4B197":"Apple",
    "A8969D":"Apple","A8BB50":"Apple","AC3C0B":"Apple","AC7F3E":"Apple",
    "B065BD":"Apple","B419F1":"Apple","B8782E":"Apple","B8C111":"Apple",
    "BC3BAF":"Apple","BC4CC4":"Apple","C82A14":"Apple","CC08E0":"Apple",
    "D0034B":"Apple","D49A20":"Apple","D82D6F":"Apple","DC2B61":"Apple",
    "E0AC CB":"Apple","E44749":"Apple","E8040B":"Apple","EC3586":"Apple",
    "F0181D":"Apple","F0DBE2":"Apple","F40F24":"Apple","F82793":"Apple",
    "FC253F":"Apple","0C51 7E":"Apple",
    # Samsung
    "001377":"Samsung","001632":"Samsung","001D25":"Samsung","0021D1":"Samsung",
    "002339":"Samsung","002399":"Samsung","0024E9":"Samsung","002566":"Samsung",
    "0026E2":"Samsung","00E3B2":"Samsung","041EAF":"Samsung","08D42B":"Samsung",
    "0C7108":"Samsung","143A28":"Samsung","1C62B8":"Samsung","1C66AA":"Samsung",
    "20D390":"Samsung","247703":"Samsung","285371":"Samsung","2C44FD":"Samsung",
    "3C6200":"Samsung","4006FB":"Samsung","40F382":"Samsung","441F29":"Samsung",
    "50A4C8":"Samsung","5492BE":"Samsung","5C3C27":"Samsung","600084":"Samsung",
    "6457FD":"Samsung","68DBCA":"Samsung","6C2F2C":"Samsung","6CF373":"Samsung",
    "706F81":"Samsung","70F927":"Samsung","7425EA":"Samsung","74458A":"Samsung",
    "7C1DD9":"Samsung","800CE7":"Samsung","843838":"Samsung","88329B":"Samsung",
    "8C771F":"Samsung","8C8590":"Samsung","94063D":"Samsung","9851D7":"Samsung",
    "9C0298":"Samsung","A0821F":"Samsung","A42BB0":"Samsung","A8F274":"Samsung",
    "B047BF":"Samsung","B4EF39":"Samsung","B8BC1B":"Samsung","BC7074":"Samsung",
    "C01173":"Samsung","C44233":"Samsung","C4731E":"Samsung","C4AE12":"Samsung",
    "CC07AB":"Samsung","D022BE":"Samsung","D06374":"Samsung","D87195":"Samsung",
    "DC7144":"Samsung","E47CF9":"Samsung","E488B2":"Samsung","E8508B":"Samsung",
    "EC9BF3":"Samsung","F05A09":"Samsung","F08131":"Samsung","F49F54":"Samsung",
    "FC1910":"Samsung",
    # Amazon / Ring / Echo
    "1C4D66":"Amazon","3474A7":"Amazon","40B4CD":"Amazon","44650D":"Amazon",
    "4CEFBD":"Amazon","680AE2":"Amazon","6C5697":"Amazon","74C246":"Amazon",
    "84D6D0":"Amazon","8871E5":"Amazon","A002DC":"Amazon","B47C9C":"Amazon",
    "CC9EE8":"Amazon","D00F50":"Amazon","F0A731":"Amazon","F0272D":"Amazon",
    "34D270":"Amazon","2C3AE8":"Amazon","0C8268":"Amazon","9084EC":"Amazon",
    # Google / Nest / Chromecast
    "1C1B68":"Google","3C5AB4":"Google","48D6D5":"Google","54607E":"Google",
    "6C5ABA":"Google","6CFDB9":"Google","708286":"Google","7C2EBD":"Google",
    "9061AE":"Google","A47733":"Google","A88040":"Google","C0EE40":"Google",
    "D4F57D":"Google","DC13A3":"Google","E43791":"Google","E4F0AB":"Google",
    "F4F5D8":"Google","B8BBD3":"Google","94EB2C":"Google","20DF0B":"Google",
    # Raspberry Pi Foundation
    "B827EB":"Raspberry Pi","DC A6 32":"Raspberry Pi","E4 5F 01":"Raspberry Pi",
    "B8:27:EB":"Raspberry Pi","DCA632":"Raspberry Pi","E45F01":"Raspberry Pi",
    "70B3D5":"Raspberry Pi",
    # Espressif (ESP8266/ESP32 — IoT)
    "24A160":"Espressif","10521C":"Espressif","18FE34":"Espressif","1CAE01":"Espressif",
    "2CF432":"Espressif","3C71BF":"Espressif","48:3F:DA":"Espressif","5CCF7F":"Espressif",
    "60019F":"Espressif","7C9EBD":"Espressif","84:0D:8E":"Espressif","8CAAB5":"Espressif",
    "A4CF12":"Espressif","A8032A":"Espressif","B4E842":"Espressif","C44F33":"Espressif",
    "DC4F22":"Espressif","E89F6D":"Espressif","F0921C":"Espressif","4A:3F:DA":"Espressif",
    "24A160":"Espressif",
    # Tuya (Smart home / IoT)
    "6857D5":"Tuya","D8F15B":"Tuya","105997":"Tuya","7CF666":"Tuya",
    "BC4CBF":"Tuya","D83BDA":"Tuya","685736":"Tuya","2CAF9A":"Tuya",
    # TP-Link / Archer
    "000AEB":"TP-Link","001D0F":"TP-Link","006B8E":"TP-Link","1027F5":"TP-Link",
    "14CC20":"TP-Link","1C3BF3":"TP-Link","28876B":"TP-Link","2C4D54":"TP-Link",
    "3C46D8":"TP-Link","40A5EF":"TP-Link","50C7BF":"TP-Link","54AF97":"TP-Link",
    "60E3AC":"TP-Link","6466B3":"TP-Link","70E231":"TP-Link","84169C":"TP-Link",
    "8CABE3":"TP-Link","90F652":"TP-Link","AC84C6":"TP-Link","B0487A":"TP-Link",
    "B48669":"TP-Link","B0A7B9":"TP-Link","C006C3":"TP-Link","C44BD2":"TP-Link",
    "D46E0E":"TP-Link","D86CE9":"TP-Link","E84D D8":"TP-Link","EC086B":"TP-Link",
    "F48E38":"TP-Link","F8A058":"TP-Link",
    # ASUS
    "001731":"ASUS","002354":"ASUS","08606E":"ASUS","107B44":"ASUS",
    "1CB72C":"ASUS","2C4D54":"ASUS","305A3A":"ASUS","382C4A":"ASUS",
    "3C97AE":"ASUS","40167E":"ASUS","485B39":"ASUS","50465D":"ASUS",
    "54A050":"ASUS","5404A6":"ASUS","6045CB":"ASUS","683AEA":"ASUS",
    "6CCCC2":"ASUS","70853C":"ASUS","74D02B":"ASUS","9C5C8E":"ASUS",
    "A8F3F1":"ASUS","B06EBF":"ASUS","BC9780":"ASUS","D850E6":"ASUS",
    "E4BEED":"ASUS","E894F6":"ASUS","F07967":"ASUS","F46D04":"ASUS",
    "04D4C4":"ASUS","00248C":"ASUS","90E6BA":"ASUS","04921F":"ASUS",
    # Netgear
    "001B2F":"Netgear","00146C":"Netgear","001E2A":"Netgear","00224B":"Netgear",
    "002275":"Netgear","0026F2":"Netgear","20E52A":"Netgear","28C68E":"Netgear",
    "2CB05D":"Netgear","44940F":"Netgear","4C60DE":"Netgear","5C:D9:98":"Netgear",
    "9C3DCF":"Netgear","A021B7":"Netgear","C03F0E":"Netgear","E0469A":"Netgear",
    # Linksys / Belkin
    "000C41":"Linksys","001310":"Linksys","001839":"Linksys","00216B":"Linksys",
    "0025F3":"Linksys","C0C1C0":"Linksys","14DAE9":"Belkin","20F3A3":"Belkin",
    "94103E":"Belkin","B4750E":"Belkin","EC1A59":"Belkin","F45C89":"Belkin",
    # Ubiquiti / UniFi
    "002722":"Ubiquiti","0418D6":"Ubiquiti","04180F":"Ubiquiti","245A4C":"Ubiquiti",
    "44D9E7":"Ubiquiti","687278":"Ubiquiti","788A20":"Ubiquiti","80AACC":"Ubiquiti",
    "9CEFD5":"Ubiquiti","B4FBE4":"Ubiquiti","DC9FDB":"Ubiquiti","E063DA":"Ubiquiti",
    "F09FC2":"Ubiquiti","F4E2C6":"Ubiquiti","FC:EC:DA":"Ubiquiti",
    # Cisco
    "000142":"Cisco","00011A":"Cisco","001036":"Cisco","001B54":"Cisco",
    "001CA4":"Cisco","002490":"Cisco","0025B5":"Cisco","005079":"Cisco",
    "00507F":"Cisco","204CA7":"Cisco","3C0E23":"Cisco","3C1888":"Cisco",
    "487A13":"Cisco","606745":"Cisco","8478AC":"Cisco","94D469":"Cisco",
    "B4A4E3":"Cisco","E48722":"Cisco","F07F06":"Cisco",
    # Roku
    "086986":"Roku","108996":"Roku","B0A737":"Roku","CC6ADA":"Roku",
    "D8316B":"Roku","DC3A5E":"Roku","F082C0":"Roku",
    # Sonos
    "000E58":"Sonos","28349B":"Sonos","5CAAE5":"Sonos","788119":"Sonos",
    "94103E":"Sonos","B8E937":"Sonos",
    # Nintendo
    "001656":"Nintendo","001F32":"Nintendo","002659":"Nintendo","0009BF":"Nintendo",
    "40F407":"Nintendo","58BDA3":"Nintendo","78A2A0":"Nintendo","8CCDE8":"Nintendo",
    # Microsoft / Xbox / Surface
    "00155D":"Microsoft","001DD8":"Microsoft","002248":"Microsoft","0050F2":"Microsoft",
    "280102":"Microsoft","2C54CF":"Microsoft","3085A9":"Microsoft","485073":"Microsoft",
    "4893BC":"Microsoft","50F0D3":"Microsoft","5CF3FC":"Microsoft","7CB04D":"Microsoft",
    "8C19B5":"Microsoft","98703C":"Microsoft","BC8385":"Microsoft","C4337A":"Microsoft",
    "D4BE D9":"Microsoft","DC4A3E":"Microsoft","E42B34":"Microsoft","E83835":"Microsoft",
    # Intel (common in laptops/PCs)
    "001320":"Intel","0019D1":"Intel","001BFC":"Intel","002170":"Intel",
    "002622":"Intel","003048":"Intel","00BE43":"Intel","036EFD":"Intel",
    "04D3B0":"Intel","08D40C":"Intel","0C84DC":"Intel","10027B":"Intel",
    "10F1F2":"Intel","1866DA":"Intel","1C697A":"Intel","20899B":"Intel",
    "24777E":"Intel","287831":"Intel","38DE1C":"Intel","3C970E":"Intel",
    "44850F":"Intel","483D6C":"Intel","4C7972":"Intel","504BD3":"Intel",
    "54E1AD":"Intel","5849EF":"Intel","6045BD":"Intel","64EF3A":"Intel",
    "68EC C5":"Intel","6C8814":"Intel","6CB3EF":"Intel","70F1A1":"Intel",
    "7C7635":"Intel","809B20":"Intel","8C70AA":"Intel","8C8D28":"Intel",
    "9CB6D0":"Intel","A04299":"Intel","A4C9F0":"Intel","A4FAD8":"Intel",
    "A8A1E8":"Intel","AC7BA1":"Intel","B03041":"Intel","C89474":"Intel",
    "CC3D82":"Intel","D0509E":"Intel","D85F20":"Intel","E0D55E":"Intel",
    "E4B318":"Intel","F44D30":"Intel","F805A4":"Intel",
    # Philips Hue
    "0017C7":"Philips","001788":"Philips","0025CA":"Philips","EC4A6C":"Philips",
    "001CDB":"Philips Hue","7CAB8B":"Philips Hue","00178C":"Philips Hue",
    # Ring
    "90E202":"Ring","B47C9C":"Ring","2C3AE8":"Ring",
    # Compal (common in HP / Lenovo / Acer laptops)
    "7C8AE1":"Compal","001558":"Compal","001CF0":"Compal","005056":"Compal",
    # Ralink / MediaTek (many cheap IoT devices)
    "002275":"Ralink","0023A1":"Ralink","28285D":"Ralink","48022A":"Ralink",
    # Honeywell / Resideo
    "005080":"Honeywell","00601D":"Honeywell","B4A8B9":"Resideo",
    # LG
    "001E75":"LG","0025E5":"LG","006FF1":"LG","08C6B3":"LG","1064AD":"LG",
    "1C9981":"LG","34CF00":"LG","3C6200":"LG","40B837":"LG","48590C":"LG",
    "50CC70":"LG","5416EB":"LG","60A10A":"LG","64995D":"LG","68B599":"LG",
    "6C24E3":"LG","706296":"LG","782DB0":"LG","88C9D0":"LG","90806C":"LG",
    "9CD91D":"LG","A841E7":"LG","AC3474":"LG","B42BB2":"LG","B4E62D":"LG",
    "BC4760":"LG","C80090":"LG","CC2D8C":"LG","D0583F":"LG","E869CD":"LG",
    # Sony
    "001024":"Sony","001315":"Sony","0015C1":"Sony","001A80":"Sony",
    "001D0D":"Sony","001EF7":"Sony","002197":"Sony","0024BE":"Sony",
    "0026C6":"Sony","00D0BC":"Sony","2CFD3E":"Sony","30517A":"Sony",
    "402BA1":"Sony","44D4E0":"Sony","54198F":"Sony","5C514F":"Sony",
    "7086CE":"Sony","7811DC":"Sony","8400D2":"Sony","84C7E9":"Sony",
    "9CE635":"Sony","A0E456":"Sony","AC9B0A":"Sony","B4521B":"Sony",
    "C49C3E":"Sony","CC1DA0":"Sony","D027C8":"Sony","E0B557":"Sony",
    # Vizio
    "00049F":"Vizio","000C26":"Vizio","3C9BD6":"Vizio","5C2EB5":"Vizio",
    "609AC1":"Vizio","7FAE05":"Vizio","88289C":"Vizio","C4ADB5":"Vizio",
    # HP / Hewlett-Packard
    "001060":"HP","001321":"HP","00145E":"HP","001635":"HP","001708":"HP",
    "0019BB":"HP","001B78":"HP","001CC4":"HP","001E0B":"HP","002129":"HP",
    "0022A4":"HP","0023AE":"HP","002481":"HP","0025B3":"HP","002756":"HP",
    "00286F":"HP","3440B5":"HP","3C4A92":"HP","40B034":"HP","483073":"HP",
    "58F39C":"HP","5CF5DA":"HP","70105C":"HP","7C6EB3":"HP","806D97":"HP",
    "88540C":"HP","9840BB":"HP","9CB70D":"HP","A0B3CC":"HP","B4B52F":"HP",
    "C87B5B":"HP","D85270":"HP","D0BFC0":"HP","F0921C":"HP","F4CE46":"HP",
    # Dell
    "000874":"Dell","000BDB":"Dell","001372":"Dell","001A4B":"Dell",
    "001E4F":"Dell","0021F6":"Dell","002215":"Dell","002564":"Dell",
    "00274D":"Dell","00B6BD":"Dell","143D67":"Dell","18DB F2":"Dell",
    "1C40AF":"Dell","204747":"Dell","24BE05":"Dell","344B50":"Dell",
    "3417EB":"Dell","488745":"Dell","4C5249":"Dell","5CBA37":"Dell",
    "78D75F":"Dell","8C8D28":"Dell","983B16":"Dell","B083FE":"Dell",
    "B4965D":"Dell","B8CB29":"Dell","C81F66":"Dell","D4BE D9":"Dell",
    "F8DB88":"Dell","FCAA14":"Dell",
    # Broadcom / generic WiFi
    "001018":"Broadcom","001A1E":"Broadcom","0022C7":"Broadcom","00904B":"Broadcom",
    # Huawei
    "001882":"Huawei","00259E":"Huawei","002EC7":"Huawei","003A9A":"Huawei",
    "0050C2":"Huawei","04C06F":"Huawei","0C96BF":"Huawei","10C61F":"Huawei",
    "143004":"Huawei","1C1D67":"Huawei","202BC1":"Huawei","24499C":"Huawei",
    "281BD9":"Huawei","2C9D1E":"Huawei","3440B5":"Huawei","38D82F":"Huawei",
    "3C4371":"Huawei","3CDFBD":"Huawei","40CB C0":"Huawei","485A3F":"Huawei",
    "4CADBF":"Huawei","4CE17A":"Huawei","500E89":"Huawei","5439DF":"Huawei",
    "5C4CCC":"Huawei","6009AA":"Huawei","683B78":"Huawei","6C8D8F":"Huawei",
    "740BC4":"Huawei","7C6093":"Huawei","7CDF A1":"Huawei","80FB06":"Huawei",
    "84DBD6":"Huawei","8C34FD":"Huawei","9C37F4":"Huawei","A08CF8":"Huawei",
    "A4D9CD":"Huawei","AC853D":"Huawei","B4430D":"Huawei","BC4FEB":"Huawei",
    "C4F081":"Huawei","C8D15E":"Huawei","CCCC81":"Huawei","D0D04B":"Huawei",
    "D4128B":"Huawei","D8490B":"Huawei","D8D43C":"Huawei","DC727E":"Huawei",
    "E0247F":"Huawei","E444AF":"Huawei","E8CD2D":"Huawei","F48E92":"Huawei",
    "F44E05":"Huawei","F8BF09":"Huawei","FC4819":"Huawei",
}

def _normalise_oui(mac: str) -> str:
    """Strip separators and uppercase — return first 6 hex chars."""
    clean = re.sub(r"[^0-9A-Fa-f]","", mac).upper()
    return clean[:6]

def lookup_mac_vendor(mac: str) -> str:
    """Return vendor name from local OUI table, or empty string."""
    oui = _normalise_oui(mac)
    if not oui or len(oui) < 6:
        return ""
    return _OUI_DB.get(oui, "")


# ── Device-type heuristics from vendor + open ports + OS guess ───────────────
def infer_device_type(vendor: str, hostname: str, open_ports: list,
                      os_type: str, banners: dict) -> tuple:
    """
    Produce a (device_type_label, source) tuple.

    IDENTITY CONFIDENCE PRECEDENCE
    ──────────────────────────────
    Device type is assigned from the highest-confidence signal available.
    Lower signals are used only when higher ones are absent.
    This order exists because:
      - MAC OUI is authoritative hardware identification
      - Hostnames set by the device itself (NetBIOS, mDNS, rDNS) are reliable
      - Port signatures alone are ambiguous (many services share ports)
      - OS fingerprinting from ports is weaker than banner-derived identity

    Priority (highest to lowest):
      1. MAC vendor OUI       — hardware manufacturer, most reliable
      2. Hostname keywords    — checked BEFORE port signatures so RT-AC5300
                                stays Router (ASUS) even if port 515 is open
      3. Port signatures      — definitive combos (135+139+445 → Windows)
      4. OS fingerprint       — TTL/banner OS type
      5. Banner keywords      — last-resort keyword scan

    Service hints (e.g. "LPD/print service exposed") are never used to
    overwrite device_type — they are recorded separately in AssetInfo.service_hints.
    """
    vl  = vendor.lower()
    hl  = hostname.lower()
    osl = os_type.lower()
    ps  = set(open_ports)

    # ── Vendor OUI ────────────────────────────────────────────────────────────
    if "apple"       in vl: return ("Apple Device",                  "mac_vendor")
    if "raspberry"   in vl: return ("Raspberry Pi",                  "mac_vendor")
    if "espressif"   in vl: return ("IoT Device (ESP-based)",        "mac_vendor")
    if "tuya"        in vl: return ("Smart Home Device (Tuya)",      "mac_vendor")
    if "ring"        in vl: return ("Ring Device",                   "mac_vendor")
    if "roku"        in vl: return ("Roku Streaming Device",         "mac_vendor")
    if "sonos"       in vl: return ("Sonos Speaker",                 "mac_vendor")
    if "nintendo"    in vl: return ("Nintendo Console",              "mac_vendor")
    if "philips"     in vl: return ("Philips Hue Device",            "mac_vendor")
    if "amazon"      in vl: return ("Amazon Smart Device",           "mac_vendor")
    if "google"      in vl: return ("Google Device",                 "mac_vendor")
    if "vizio"       in vl: return ("Vizio Smart TV",                "mac_vendor")
    if "compal"      in vl: return ("Laptop (Compal ODM)",           "mac_vendor")

    # ── Hostname keyword clues ────────────────────────────────────────────────
    # Checked before port signatures: a router with LPD/515 open stays "Router",
    # not "Network Printer".
    for kw, label in [
        ("esp_","IoT Device (ESP-based)"),("esp8266","IoT Device (ESP-based)"),
        ("esp32","IoT Device (ESP-based)"),
        ("amazon-","Amazon Smart Device"),
        ("iphone","iPhone"),("ipad","iPad"),("macbook","MacBook"),("imac","iMac"),
        ("macpro","Mac Pro"),("macmini","Mac Mini"),("airpods","AirPods"),
        ("appletv","Apple TV"),("homepod","HomePod"),
        ("android","Android Device"),("pixel","Google Pixel"),
        ("galaxy","Samsung Galaxy"),("echo","Amazon Echo"),
        ("kindle","Amazon Kindle"),("firetv","Amazon Fire TV"),
        ("nest","Google Nest"),("chromecast","Chromecast"),
        ("roku","Roku"),("ring","Ring"),("raspberrypi","Raspberry Pi"),
        ("printer","Printer"),("hp-print","Printer (HP)"),
        ("scanner","Scanner"),("camera","IP Camera"),
        ("smarttv","Smart TV"),("bravia","Sony TV"),
        ("xbox","Xbox"),("playstation","PlayStation"),
        ("ps5","PlayStation 5"),("ps4","PlayStation 4"),
        ("wii","Nintendo Wii"),("switch","Nintendo Switch"),
        # Router model prefixes come before port-based guesses
        ("rt-","Router (ASUS)"),("rt_","Router (ASUS)"),("asus","Router (ASUS)"),
        ("archer","Router (TP-Link)"),("tplink","Router (TP-Link)"),
        ("netgear","Router (Netgear)"),("nighthawk","Router (Netgear)"),
        ("linksys","Router (Linksys)"),("eero","Router (Amazon eero)"),
        ("orbi","Router (Netgear Orbi)"),("deco","Router (TP-Link Deco)"),
        ("airport","Router (Apple AirPort)"),("timecapsule","Router (Apple Time Capsule)"),
        ("pfsense","Firewall (pfSense)"),("opnsense","Firewall (OPNsense)"),
        ("ubnt","Ubiquiti Device"),("unifi","UniFi AP"),("uap","UniFi AP"),
        ("synology","Synology NAS"),("qnap","QNAP NAS"),("nas","NAS Device"),
        ("ap-","Access Point"),("router","Router"),
    ]:
        if kw in hl:
            return (label, "reverse_dns")

    # ── Port signature clues ──────────────────────────────────────────────────
    if {135,139,445}.issubset(ps):
        return ("Windows PC/Server",                              "port_signature")
    if 3389 in ps and 445 in ps:
        return ("Windows PC (Remote Desktop)",                    "port_signature")
    if 8008 in ps and 8443 in ps:
        # Google Cast signature — ports 8008 (Cast v2) and 8443 (Cast TLS)
        return ("Google Cast Device (Chromecast/Google TV)",      "port_signature")
    if 5900 in ps or 5901 in ps:
        return ("VNC Device",                                     "port_signature")
    # Note: port 515 alone is NOT enough to call something a printer —
    # routers with USB print servers also expose 515. Only use it if no
    # stronger hostname/vendor/os_type evidence points to a router/gateway.
    if (9100 in ps or 515 in ps) and not any(
        kw in hl for kw in ("rt-","router","asus","netgear","linksys","archer")
    ) and not any(
        kw in osl for kw in ("router","gateway","firewall","network device")
    ):
        return ("Network Printer", "port_signature")
    if 1883 in ps or 8883 in ps:
        return ("MQTT IoT Device",                                "port_signature")
    if 5353 in ps:
        return ("mDNS Device",                                    "port_signature")
    if 1900 in ps:
        return ("UPnP Device",                                    "port_signature")
    if 2049 in ps or 111 in ps:
        return ("NAS / Linux Server",                             "port_signature")
    if {22,80,443}.issubset(ps):
        return ("Linux Server",                                   "port_signature")
    if 22 in ps and not {80,443,445}.intersection(ps):
        return ("Linux Host",                                     "port_signature")
    if {80,443}.issubset(ps):
        return ("Web Server",                                     "port_signature")
    if 27017 in ps: return ("MongoDB Server",  "port_signature")
    if 6379  in ps: return ("Redis Server",    "port_signature")
    if 9200  in ps: return ("Elasticsearch Node", "port_signature")
    if 3306  in ps: return ("MySQL Server",    "port_signature")
    if 5432  in ps: return ("PostgreSQL Server","port_signature")
    if 1433  in ps: return ("MSSQL Server",    "port_signature")

    # ── OS fingerprint fallback ───────────────────────────────────────────────
    if "windows"  in osl: return ("Windows Device",        "os_fingerprint")
    if "linux"    in osl: return ("Linux Device",          "os_fingerprint")
    if "router"   in osl: return ("Router",                "os_fingerprint")
    if "nas"      in osl: return ("NAS Device",            "os_fingerprint")
    if "printer"  in osl: return ("Network Printer",       "os_fingerprint")
    if "camera"   in osl: return ("IP Camera",             "os_fingerprint")
    if "freebsd"  in osl: return ("FreeBSD Host",          "os_fingerprint")
    if "embedded" in osl: return ("Embedded / IoT Device", "os_fingerprint")

    # ── Banner keyword scan (last resort) ─────────────────────────────────────
    all_banners = " ".join(str(v) for v in banners.values()).lower()
    for kw, label in [
        ("dd-wrt","Router (DD-WRT)"),("openwrt","Router (OpenWrt)"),
        ("mikrotik","Router (MikroTik)"),("synology","Synology NAS"),
        ("qnap","QNAP NAS"),("hikvision","IP Camera (Hikvision)"),
        ("printer","Network Printer"),("cups","Print Server"),
        ("pfsense","Firewall (pfSense)"),("opnsense","Firewall (OPNsense)"),
        ("ubiquiti","Ubiquiti Device"),("unifi","UniFi AP"),
    ]:
        if kw in all_banners:
            return (label, "banner")

    return ("Unknown Device", "")


# ── Individual enrichment probes ──────────────────────────────────────────────
def _rdns_lookup(ip: str, timeout: float = 1.5) -> tuple:
    """Reverse DNS → (hostname, "reverse_dns") or ("","")"""
    try:
        socket.setdefaulttimeout(timeout)
        name = socket.gethostbyaddr(ip)[0]
        return (name, "reverse_dns") if name else ("","")
    except Exception:
        return ("","")
    finally:
        socket.setdefaulttimeout(None)

def _netbios_lookup(ip: str, timeout: float = 1.5) -> tuple:
    """
    NetBIOS Name Service query (UDP 137) → (name, "netbios")
    Sends a NBNS Name Query for wildcard '*' which elicits the host's names.
    Works on Windows hosts without any firewall blocking UDP 137.
    """
    try:
        # NBNS Name Query Request for <01><02>__MSBROWSE__<02><01> (node status)
        # Simpler: send Node Status Request to get all names
        txid = b"\xAB\xCD"
        pkt = (
            txid +
            b"\x00\x00" +          # flags: query, not recursive
            b"\x00\x01" +          # QDCOUNT = 1
            b"\x00\x00\x00\x00\x00\x00" +  # ANCOUNT, NSCOUNT, ARCOUNT
            b"\x20" +              # length of encoded name (32)
            b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +  # encoded "*"
            b"\x00" +              # null terminator
            b"\x00\x21" +          # QTYPE: NBSTAT
            b"\x00\x01"            # QCLASS: IN
        )
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(pkt, (ip, 137))
        data, _ = s.recvfrom(1024)
        s.close()
        # Parse: response has variable header; names start after 56 bytes
        # Number of names is at offset 56
        if len(data) < 57:
            return ("","")
        num_names = data[56]
        names = []
        for i in range(num_names):
            base = 57 + i * 18
            if base + 15 > len(data):
                break
            raw_name = data[base:base+15].decode("ascii", errors="replace").strip()
            name_type = data[base+15] if base+15 < len(data) else 0xFF
            # type 0x00 = workstation, 0x20 = file server — these are the host name
            if name_type in (0x00, 0x20) and raw_name and raw_name != "*":
                names.append(raw_name)
        if names:
            return (names[0].strip(), "netbios")
    except Exception:
        pass
    return ("","")

def _mdns_lookup(ip: str, timeout: float = 1.5) -> tuple:
    """
    mDNS PTR query to 224.0.0.251:5353 — resolves .local hostnames.
    Used by Apple, Chromecast, printers, IoT devices.
    """
    try:
        # Build DNS PTR query for the in-addr.arpa reverse address
        parts = ip.split(".")
        rev   = ".".join(reversed(parts)) + ".in-addr.arpa"
        # Encode DNS name
        def encode_name(name):
            result = b""
            for label in name.split("."):
                encoded = label.encode("ascii")
                result += bytes([len(encoded)]) + encoded
            return result + b"\x00"

        txid  = b"\xAB\xCD"
        query = txid + b"\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        query += encode_name(rev)
        query += b"\x00\x0C\x00\x01"  # QTYPE=PTR, QCLASS=IN

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Send to the actual host first (unicast mDNS)
        s.sendto(query, (ip, 5353))
        data, _ = s.recvfrom(512)
        s.close()
        # Extract any name from answer — look for .local strings
        text = data.decode("ascii", errors="replace")
        m = re.search(r"([\w\-]+\.local)", text)
        if m:
            return (m.group(1), "mdns")
    except Exception:
        pass
    return ("","")

def _http_title_lookup(ip: str, open_ports: list, timeout: float = 2.0) -> tuple:
    """
    Grab HTTP/HTTPS page title and extract device name from common patterns.
    Checks ports in order of most-likely-useful.
    """
    http_ports = [p for p in [80,8080,8000,8888,3000,443,8443,8081,7443]
                  if p in open_ports]
    for port in http_ports:
        try:
            use_ssl = port in {443,8443,7443}
            if use_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                raw = socket.socket(); raw.settimeout(timeout)
                conn = ctx.wrap_socket(raw, server_hostname=ip)
            else:
                conn = socket.socket(); conn.settimeout(timeout)
            conn.connect((ip, port))
            req = (f"GET / HTTP/1.1\r\nHost: {ip}\r\n"
                   f"User-Agent: Heimdall/{VERSION}\r\nConnection: close\r\n\r\n").encode()
            conn.send(req)
            data = b""
            try:
                while len(data) < 8192:
                    chunk = conn.recv(1024)
                    if not chunk: break
                    data += chunk
                    if b"</title>" in data or b"</head>" in data: break
            except Exception:
                pass
            conn.close()
            text = data.decode("utf-8", errors="replace")
            # Extract <title>
            m = re.search(r"<title[^>]*>([^<]{1,100})</title>", text, re.IGNORECASE)
            if m:
                title = m.group(1).strip()
                if title and len(title) > 2:
                    return (title, "http_title")
        except Exception:
            pass
    return ("","")

def _tls_cert_lookup(ip: str, open_ports: list, timeout: float = 2.0) -> tuple:
    """Extract CN and SAN from TLS certificate — often has device/router hostnames."""
    tls_ports = [p for p in [443,8443,7443,636,993,995,465] if p in open_ports]
    for port in tls_ports:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            raw = socket.socket(); raw.settimeout(timeout)
            with ctx.wrap_socket(raw, server_hostname=ip) as s:
                s.connect((ip, port))
                cert = s.getpeercert()
                if cert:
                    # CN
                    subj = dict(x[0] for x in cert.get("subject",[]))
                    cn   = subj.get("commonName","")
                    # SAN
                    sans = []
                    for stype, sval in cert.get("subjectAltName",[]):
                        if stype == "DNS":
                            sans.append(sval)
                    name = cn or (sans[0] if sans else "")
                    if name and not re.match(r"^\d+\.\d+\.\d+\.\d+$", name):
                        return (name, "tls_cert")
        except Exception:
            pass
    return ("","")

def _banner_hostname_hint(banners: dict) -> tuple:
    """
    Extract hostname hints from already-collected banners.
    Looks for SSH hostname, SMTP HELO/greeting, FTP greeting, HTTP Host header hints.
    """
    for port, banner in banners.items():
        if not banner or banner in ("No banner","Skipped"):
            continue
        # SSH: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6" — no hostname usually
        # SMTP: "220 mail.example.com ESMTP Postfix"
        if port == 25:
            m = re.match(r"220\s+([\w\.\-]+)", banner)
            if m:
                host = m.group(1)
                if "." in host and not re.match(r"^\d+\.\d+", host):
                    return (host, "banner_smtp")
        # FTP: "220 FTP server (vsftpd) HOSTNAME ready"
        if port == 21:
            m = re.search(r"220[^\n]+([\w\-]+\.[\w\-\.]+)\s", banner)
            if m:
                return (m.group(1), "banner_ftp")
        # Generic: look for "hostname: xxx" patterns
        m = re.search(r"(?:hostname|host)[:\s]+([a-zA-Z][a-zA-Z0-9\-\.]+)", banner, re.IGNORECASE)
        if m:
            return (m.group(1), "banner_generic")
    return ("","")


# ── Enrichment cache ──────────────────────────────────────────────────────────
_enrich_cache: dict = {}
_enrich_lock  = threading.Lock()

def enrich_asset(ip: str, open_ports: list, banners: dict,
                 os_type: str, mac: str = "", timeout: float = 1.5) -> AssetInfo:
    """
    Run all enrichment probes concurrently and merge results.
    Returns AssetInfo with best hostname, device_type, confidence, sources.
    Cached per IP so multiple calls are free.
    Never raises — always returns a valid AssetInfo even if all probes fail.
    """
    with _enrich_lock:
        if ip in _enrich_cache:
            return _enrich_cache[ip]

    results: dict = {}   # key → (name, source_label)
    # Give probes their timeout + a small scheduling buffer
    wall_budget = timeout + 1.5

    probes = [
        (lambda t=timeout: _rdns_lookup(ip, t),                    "rdns"),
        (lambda t=timeout: _netbios_lookup(ip, t),                 "netbios"),
        (lambda t=timeout: _mdns_lookup(ip, t),                    "mdns"),
        (lambda t=timeout: _http_title_lookup(ip, open_ports, t),  "http_title"),
        (lambda t=timeout: _tls_cert_lookup(ip, open_ports, t),    "tls_cert"),
        (lambda: _banner_hostname_hint(banners),                    "banner"),
    ]

    try:
        with ThreadPoolExecutor(max_workers=6) as ex:
            future_map = {ex.submit(fn): key for fn, key in probes}
            deadline   = time.monotonic() + wall_budget

            # Poll completed futures until deadline — never call as_completed with timeout
            pending = set(future_map.keys())
            while pending and time.monotonic() < deadline:
                done_now = {f for f in pending if f.done()}
                for fut in done_now:
                    key = future_map[fut]
                    pending.discard(fut)
                    try:
                        result = fut.result(timeout=0.05)
                        if result and result[0]:
                            results[key] = result
                    except Exception:
                        pass
                if pending:
                    time.sleep(0.05)

            # Cancel anything still running — ThreadPoolExecutor ignores cancel()
            # for already-started threads but it prevents new ones starting
            for fut in pending:
                fut.cancel()
                # Still harvest if it finished during cancel
                if fut.done():
                    try:
                        result = fut.result(timeout=0.02)
                        if result and result[0]:
                            key = future_map[fut]
                            results.setdefault(key, result)
                    except Exception:
                        pass

    except Exception:
        pass   # Degrade gracefully — return what we have

    # ── Merge: priority order for hostname selection ────────────────────────
    # More reliable sources ranked first
    priority = ["netbios","mdns","tls_cert","rdns","http_title","banner"]
    hostname = ""
    sources_used = []

    for src in priority:
        if src in results:
            name, label = results[src]
            if name and name != ip:
                hostname = name
                sources_used.append(label)
                break

    # Collect all sources for metadata
    all_sources = list({r[1] for r in results.values()})

    # ── MAC vendor ─────────────────────────────────────────────────────────
    vendor = lookup_mac_vendor(mac) if mac else ""

    # ── Device type ────────────────────────────────────────────────────────
    device_type, dtype_source = infer_device_type(vendor, hostname, open_ports, os_type, banners)

    # If the device type was inferred from ports or banners, add that to sources
    if dtype_source and dtype_source not in all_sources:
        all_sources.append(dtype_source)

    # ── Confidence ─────────────────────────────────────────────────────────
    if hostname and hostname != "Unknown" and len(sources_used) >= 1:
        confidence = "high" if sources_used[0] in ("netbios","mdns","tls_cert") else "medium"
    elif device_type != "Unknown Device":
        confidence = "medium"
        hostname   = hostname or "Unknown"
    else:
        confidence = "low"
        hostname   = "Unknown"

    # ── Service hints ───────────────────────────────────────────────────────
    # Ports that indicate a secondary service role rather than device identity.
    # These are shown alongside device_type, not instead of it, so a router
    # with LPD port open is still "Router (ASUS)" with hint "LPD/print service".
    _SERVICE_HINT_PORTS = {
        515:  "LPD/print service exposed",
        631:  "IPP/print service exposed",
        9100: "RAW print service exposed",
        2049: "NFS file share exposed",
        111:  "RPC portmapper exposed",
        6379: "Redis service exposed",
        9200: "Elasticsearch service exposed",
        27017:"MongoDB service exposed",
        5900: "VNC remote desktop exposed",
        5901: "VNC remote desktop exposed",
        1883: "MQTT broker exposed",
        3306: "MySQL service exposed",
        5432: "PostgreSQL service exposed",
    }
    service_hints = []
    # Only add hints when there is already a confident device identity.
    # For unknown devices, the port signature IS the identity, not a hint.
    if device_type not in ("Unknown Device", "Unknown") and confidence in ("high","medium"):
        for p in open_ports:
            hint = _SERVICE_HINT_PORTS.get(p)
            if hint and hint not in service_hints:
                service_hints.append(hint)

    asset = AssetInfo(
        hostname      = hostname,
        device_type   = device_type,
        mac_vendor    = vendor,
        mac_addr      = mac,
        confidence    = confidence,
        sources       = all_sources or sources_used,
        service_hints = service_hints,
    )

    with _enrich_lock:
        _enrich_cache[ip] = asset

    return asset


# ── Asset Inventory builder (called after all hosts are scanned) ───────────────
def build_asset_inventory(hosts: list) -> list:
    """
    Returns a flat list of dicts — one per host — for the Asset Inventory table.
    Pulls enrichment data from host["asset"] which is set by scan_host().
    """
    inventory = []
    for host in hosts:
        asset = host.get("asset", {})
        ports = host.get("open_ports", [])
        top_risk = max((p["risk"]["score"] for p in ports), default=0)
        top_level= next((p["risk"]["level"] for p in ports
                         if p["risk"]["score"] == top_risk), "LOW") if ports else "LOW"
        inventory.append({
            "ip":          host["ip"],
            "hostname":    asset.get("hostname","Unknown"),
            "device_type": asset.get("device_type","Unknown"),
            "mac_vendor":  asset.get("mac_vendor",""),
            "mac_addr":    asset.get("mac_addr",""),
            "open_ports":  [p["port"] for p in ports],
            "services":    [p["service"] for p in ports],
            "risk_level":  top_level,
            "risk_score":  top_risk,
            "confidence":  asset.get("confidence","low"),
            "sources":     asset.get("sources",[]),
            "os":          host.get("os",{}).get("os_type","Unknown"),
        })
    inventory.sort(key=lambda x: x["risk_score"], reverse=True)
    return inventory


# ── Service fingerprint evidence helper ──────────────────────────────────────
# Ports where the SERVICE_MAP label is well-established by IANA assignment or
# universal protocol convention. These can be shown without qualification.
_HIGH_CONFIDENCE_PORTS = {
    21,22,23,25,53,80,110,111,143,161,389,443,445,465,514,587,
    636,993,995,3306,3389,5432,5900,5901,6379,8080,8443,9200,22222,27017,
}

# Ports where the service name is a heuristic based on common usage rather than
# a confirmed protocol exchange. A banner or protocol probe is needed to confirm.
_HEURISTIC_PORTS = {
    50000: "IBM-DB2",     # IBM-DB2 uses 50000 by convention, but other services also do
    9000:  "PHP-FPM",     # PHP-FPM default, but Prometheus, Portainer, etc. also use 9000
    8000:  "HTTP",        # HTTP is correct but any app can listen here
    8888:  "HTTP",        # Same
    3000:  "HTTP",        # Flask/Node dev servers, Grafana, etc.
    9090:  "Prometheus",  # Prometheus default, but not confirmed without banner
    4848:  "GlassFish",   # GlassFish admin, but not confirmed without banner
    50070: "Hadoop",      # Hadoop HDFS, heuristic
    61616: "ActiveMQ",    # ActiveMQ default, not confirmed without banner
}


def service_evidence(port: int, service: str, svc_ver, banner: str) -> dict:
    """
    Return structured service evidence fields for a scanned port.

    Fields:
      service                 — canonical name from SERVICE_MAP
      normalized_service      — clean name used for display/grouping
      service_confidence      — high / medium / low
      version_confirmed       — bool: product+version extracted from banner
      banner_present          — bool: non-empty banner received
      fingerprint_source      — how service identity was determined
      display_service         — what to show in terminal/HTML
    """
    version_confirmed = bool(svc_ver.product and svc_ver.version
                             and svc_ver.confidence == "high")
    banner_present    = bool(banner and banner not in ("No banner", "Skipped"))

    # parse_version() returns product=service when a banner is present but nothing
    # matched any pattern — it is a fallback, not a genuine extraction. We detect
    # this case by checking whether the product is identical to the service name
    # AND no version was extracted. In that situation the banner contributes nothing
    # useful to identity and we fall through to the port-based confidence path.
    product_genuinely_extracted = bool(
        svc_ver.product
        and (svc_ver.version                             # version present → real match
             or svc_ver.product.lower() != service.lower())  # product differs → real match
    )

    if version_confirmed:
        # Product and version both confirmed from banner — highest confidence.
        confidence         = "high"
        fingerprint_source = "service_banner"
        display_service    = f"{svc_ver.product} {svc_ver.version}"
    elif banner_present and product_genuinely_extracted:
        # Banner produced a real product extraction but version is unknown.
        # "IBM-DB2" appearing here means a banner explicitly identified the product,
        # e.g. an IBM DB2 greeting — not just parse_version returning the service name.
        confidence         = "medium"
        fingerprint_source = "service_banner"
        display_service    = f"{svc_ver.product}-like service, version unknown"
    elif port in _HIGH_CONFIDENCE_PORTS:
        # Well-established IANA port — reasonable to name the service without qualification.
        # The protocol is almost certainly what the port says it is, even without a banner.
        confidence         = "medium"
        fingerprint_source = "port_signature"
        display_service    = service
    elif port in _HEURISTIC_PORTS:
        # Port is associated with this service by common convention but not exclusively.
        confidence         = "low"
        fingerprint_source = "heuristic"
        display_service    = f"Possible {service}-like service"
    else:
        # Port number is in SERVICE_MAP but not well-established — use qualification.
        confidence         = "low"
        fingerprint_source = "port_signature"
        display_service    = f"Possible {service}-like service"

    return {
        "service":             service,
        "normalized_service":  service,
        "service_confidence":  confidence,
        "version_confirmed":   version_confirmed,
        "banner_present":      banner_present,
        "fingerprint_source":  fingerprint_source,
        "display_service":     display_service,
    }


# ──────────────────────────────────────────────────────────────────────────────
# SCAN ORCHESTRATOR
# ──────────────────────────────────────────────────────────────────────────────
def scan_host(ip: str, ports: list, threads: int, timeout: float,
              do_banners: bool, do_cves: bool, do_security: bool,
              api_key: str = "", cve_since: int = DEFAULT_CVE_SINCE) -> dict:
    """
    Scan a single host. All terminal output is buffered and flushed atomically
    via _print_lock so concurrent host scans never interleave lines.
    """
    host_start = time.time()
    lines = []   # all output for this host — flushed atomically when scan completes

    def emit(text=""):
        lines.append(text)

    def flush():
        with _print_lock:
            for ln in lines:
                print(ln)
            lines.clear()

    emit(f"\n  {clr('→',C.CYAN)} Scanning {clr(ip,C.BOLD)}")

    open_ports = scan_ports(ip, ports, threads, timeout)
    if not open_ports:
        asset = enrich_asset(ip, [], {}, "Unknown")
        disp  = asset.display_name()
        name_tag = f" {clr('('+disp+')',C.DIM)}" if disp != "Unknown" else ""
        emit(f"    {clr('No open ports',C.DIM)}{name_tag}")
        flush()
        return {"ip":ip,"is_up":True,"scan_duration":round(time.time()-host_start,1),
                "os":asdict(OSGuess()),"asset":asdict(asset),"open_ports":[]}

    emit(f"    {clr('Open:',C.GREEN)} {open_ports}")

    banners: dict = {}
    if do_banners:
        for port in open_ports:
            banners[port] = grab_banner(ip, port, timeout=2.5)

    ttl      = get_ttl(ip)
    os_guess = fingerprint_os(open_ports, banners, ttl)
    cc       = CONF_CLR.get(os_guess.confidence, C.DIM)

    # ── Asset Enrichment ─────────────────────────────────────────────────────
    asset  = enrich_asset(ip, open_ports, banners, os_guess.os_type, timeout=1.5)
    disp   = asset.display_name()
    conf_c = CONF_CLR.get(asset.confidence, C.DIM)
    name_str  = (f" {clr('('+disp+')',conf_c)}" if disp != "Unknown"
                 else f" {clr('(Unknown)',C.DIM)}")
    dtype_str = (f" — {clr(asset.device_type,C.DIM)}"
                 if asset.device_type not in ("Unknown","Unknown Device") else "")
    vendor_str = f" {clr('['+asset.mac_vendor+']',C.DIM)}" if asset.mac_vendor else ""
    src_str    = (f" {clr('via '+','.join(asset.sources[:2]),C.DIM)}"
                  if asset.sources else "")

    emit(f"    {clr('OS:',C.CYAN)} {clr(os_guess.os_type,cc)} "
         f"{clr('('+os_guess.confidence+')',C.DIM)}")
    hints_str = ""
    if asset.service_hints:
        hints_str = f" {clr('[hints: '+', '.join(asset.service_hints[:2])+']', C.DIM)}"
    emit(f"    {clr('[ASSET]',C.CYAN,C.BOLD)} {ip}{name_str}{dtype_str}{vendor_str}{src_str}{hints_str}")

    # Version-advisory checks that are merged into CVE findings in the report.
    # We suppress their [SEC] line in the live scan output when a CVE result
    # already covers the same port, to avoid printing duplicate information.
    _ADVISORY_ONLY_CHECKS = {"Outdated OpenSSH", "OpenSSH Below 9.x"}

    external = not is_internal(ip)

    sec_results: dict = {}
    if do_security:
        sec_results = run_security_checks(ip, open_ports, banners,
                                          device_type=asset.device_type)
        # We need CVE results to decide which [SEC] lines to suppress.
        # Build a quick set of ports that will have CVE-backed findings.
        # We do this by running a lightweight version parse — no NVD queries yet.
        ports_with_cve_finding: set = set()
        if do_cves:
            for _p in open_ports:
                _svc = SERVICE_MAP.get(_p, "Unknown")
                _ban = banners.get(_p, "Skipped")
                _sv  = parse_version(_svc, _ban)
                # Only HIGH confidence (confirmed version) leads to CVE matching
                if _sv.confidence == CONF_HIGH:
                    ports_with_cve_finding.add(_p)

        for port, sec_findings_list in sec_results.items():
            for f in sec_findings_list:
                if f.severity in ("CRITICAL", "HIGH"):
                    # Suppress version advisories that will be merged into CVE cards
                    if (f.check in _ADVISORY_ONLY_CHECKS
                            and port in ports_with_cve_finding):
                        emit(f"    {clr('[SEC]',C.DIM)} {port}: "
                             f"{f.check} — noted in CVE-backed finding")
                        continue
                    emit(f"    {clr('[SEC]',SEV_CLR[f.severity],C.BOLD)} "
                         f"{port}: {f.check}")

    port_results = []
    for port in open_ports:
        service  = SERVICE_MAP.get(port, "Unknown")
        banner   = banners.get(port, "Skipped")
        svc_ver  = parse_version(service, banner)
        port_sec = sec_results.get(port, [])
        svc_ev   = service_evidence(port, service, svc_ver, banner)

        cve_result = {"cves":[],"confidence":CONF_LOW,"advisory":"","filtered_count":0}
        if do_cves:
            # Use display_service for terminal label — makes confidence visible
            ver_label = (f"{svc_ver.product} {svc_ver.version}".strip()
                         if svc_ver.product else svc_ev["display_service"])
            cve_result = fetch_cves(svc_ver, port, api_key, cve_since)
            cves = cve_result["cves"]
            if cves:
                top   = cves[0]
                top_s = clr(f"CVSS {top['score']} {top['severity']}",
                            SEV_CLR.get(top["severity"], C.DIM))
                filt  = cve_result.get("filtered_count", 0)
                filt_note = clr(f" ({filt} filtered)", C.DIM) if filt else ""
                emit(f"    {clr('[CVE]',C.YELLOW)} {port} ({ver_label}): "
                     f"{len(cves)} CVE(s) — {top_s}{filt_note}")
            elif cve_result["advisory"]:
                emit(f"    {clr('[CVE]',C.DIM)} {port}: version unconfirmed — skipped")
            else:
                conf_note = (f" [{svc_ev['fingerprint_source']}]"
                             if svc_ev["service_confidence"] == "low" else "")
                emit(f"    {clr('[CVE]',C.DIM)} {port}: no match "
                     f"({svc_ver.confidence} conf{conf_note})")

        risk = calculate_risk(port, cve_result, port_sec, external,
                              asset.device_type)
        if risk["level"] in ("CRITICAL", "HIGH"):
            rl, rs = risk["level"], risk["score"]
            emit(f"    {clr('[!]',SEV_CLR[rl],C.BOLD)} "
                 f"{port}/{svc_ev['display_service']}: {rl} (score {rs})")

        port_results.append({
            "port":            port,
            "service":         service,
            "display_service": svc_ev["display_service"],
            "service_evidence": svc_ev,
            "banner":          banner,
            "version":         asdict(svc_ver),
            "cve_result":      cve_result,
            "security":        [asdict(sf) for sf in port_sec],
            "risk":            risk,
        })

    # Flush the complete host block in one locked write — prevents interleaving
    flush()

    host_duration = round(time.time()-host_start, 1)
    return {
        "ip":             ip,
        "is_up":          True,
        "external":       external,
        "ttl":            ttl,
        "scan_duration":  host_duration,
        "scan_timestamp": datetime.now().isoformat(),
        "os":             asdict(os_guess),
        "asset":          asdict(asset),
        "open_ports":     port_results,
    }

# ──────────────────────────────────────────────────────────────────────────────
# HTML REPORT  (v4: exec summary + attack surface + top risk host + grouped headers)
# ──────────────────────────────────────────────────────────────────────────────
def write_html(results: dict, path: str):
    e       = html_lib.escape
    meta    = results.get("scan_metadata", results.get("meta", {}))
    hosts   = results["hosts"]
    summ    = results.get("executive_summary", {})
    atk     = results.get("attack_surface", {})
    inv     = results.get("asset_inventory", [])
    vnotes  = results.get("verification_notes", [])
    sq      = results.get("scan_quality", {})
    all_findings   = results.get("findings", [])
    priorities     = results.get("remediation_priorities", [])
    baseline_diff  = results.get("baseline_changes", results.get("baseline_comparison"))

    def badge(level, small=False):
        bg = {"CRITICAL":"#ff2d55","HIGH":"#ff6b35","MEDIUM":"#ffd60a","LOW":"#30d158"}.get(level,"#555")
        fg = "#fff" if level=="CRITICAL" else "#000"
        fs = "10px" if small else "11px"
        return (f'<span style="background:{bg};color:{fg};padding:2px 8px;border-radius:3px;'
                f'font-size:{fs};font-weight:700;letter-spacing:.5px">{level}</span>')

    def sc(level):
        return {"CRITICAL":"#ff2d55","HIGH":"#ff6b35","MEDIUM":"#ffd60a",
                "LOW":"#30d158","INFO":"#636366"}.get(level,"#888")

    def conf_badge(conf):
        cfg = {
            "high":   ("HIGH CONF","#30d158","#0d2010"),
            "medium": ("MED CONF", "#ffd60a","#201a00"),
            "low":    ("LOW CONF", "#555",   "#1a1a1a"),
        }.get(conf, ("?","#555","#1a1a1a"))
        return (f'<span style="background:{cfg[2]};color:{cfg[1]};border:1px solid {cfg[1]}40;'
                f'padding:1px 5px;border-radius:3px;font-size:9px;font-weight:700;'
                f'letter-spacing:.5px">{cfg[0]}</span>')

    # ── Executive Summary ─────────────────────────────────────────────────────
    ov    = summ.get("overall_risk","LOW")
    trh   = summ.get("top_risk_host","")
    trr   = summ.get("top_risk_reasons",[])
    trs   = summ.get("top_risk_score", 0)
    risk_border = {"CRITICAL":"rgba(255,45,85,.5)","HIGH":"rgba(255,107,53,.4)",
                   "MEDIUM":"rgba(255,214,10,.3)","LOW":"rgba(48,209,88,.3)"}.get(ov,"#222")

    findings_li = "".join(
        f'<li style="margin:4px 0;color:#aeaeb2;font-size:13px">{e(f)}</li>'
        for f in summ.get("key_findings",[])
    )
    remed_li = "".join(
        f'<li style="margin:4px 0;color:#636366;font-size:12px;font-family:monospace">{e(r)}</li>'
        for r in summ.get("top_remediations",[])
    )
    top_risk_html = ""
    if trh:
        top_risk_html = f"""
        <div style="margin-top:16px;padding:12px 16px;background:rgba(255,45,85,.07);
                    border:1px solid rgba(255,45,85,.3);border-radius:8px">
          <div style="font-size:11px;color:#636366;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px">
            Highest Risk Host
          </div>
          <span style="font-family:monospace;font-size:16px;font-weight:700;color:#fff">{e(trh)}</span>
          <span style="color:#ff2d55;font-weight:700;font-size:13px;margin-left:12px">Score {trs}</span>
          {badge(ov, small=True)}
          <div style="color:#636366;font-size:12px;margin-top:6px">
            {' &nbsp;·&nbsp; '.join(e(r) for r in trr[:3]) if trr else 'Multiple risk factors'}
          </div>
        </div>"""

    exec_html = f"""
    <div style="padding:24px;background:rgba(255,255,255,.02);border:1px solid {risk_border};
                border-radius:12px;margin-bottom:24px">
      <div style="display:flex;align-items:center;gap:12px;margin-bottom:16px;flex-wrap:wrap">
        <span style="font-size:15px;font-weight:700">Executive Summary</span>
        {badge(ov)}
        <span style="color:#444;font-size:12px">Overall Network Risk</span>
        <span style="color:#3a3a3c;font-size:11px;margin-left:auto">
          Mode: {e(summ.get('scan_mode',''))} &nbsp;·&nbsp;
          CVEs: {e(str(summ.get('cve_since','')))}+ only
        </span>
      </div>
      <div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:18px">
        {"".join(f'<div style="background:#0a0a0a;border:1px solid #1a1a1a;border-radius:8px;padding:10px 16px;min-width:80px"><div style="font-size:24px;font-weight:700;font-family:monospace;color:{col}">{val}</div><div style="font-size:10px;color:#333;text-transform:uppercase;letter-spacing:1px;margin-top:2px">{lbl}</div></div>'
          for val,lbl,col in [
              (summ.get('hosts_scanned',0),"Hosts","#0a84ff"),
              (summ.get('open_ports',0),"Open Ports","#30d158"),
              (summ.get('cves_matched',0),"CVEs","#ff9f0a"),
              (summ.get('critical_ports',0),"Critical","#ff2d55"),
              (summ.get('auth_issues',0),"Auth Issues","#ff6b35"),
          ])}
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;flex-wrap:wrap">
        <div>
          {"<div style='font-size:11px;color:#333;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px'>Key Findings</div><ul style='list-style:disc;padding-left:16px'>"+findings_li+"</ul>" if findings_li else ""}
        </div>
        <div>
          {"<div style='font-size:11px;color:#333;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px'>Top Remediations</div><ol style='padding-left:16px'>"+remed_li+"</ol>" if remed_li else ""}
        </div>
      </div>
      {top_risk_html}
    </div>"""

    # ── Attack Surface Summary ─────────────────────────────────────────────────
    svc_entries = atk.get("service_entries", [])
    svc_map     = atk.get("service_map",{})    # kept for hr_svcs lookup
    hr_svcs     = atk.get("high_risk_svcs",[])
    hdr_by_host = atk.get("header_by_host",{})

    _conf_color = {"high":"#0a84ff","medium":"#aeaeb2","low":"#636366"}
    svc_rows = "".join(
        f'<tr>'
        f'<td style="padding:6px 12px;font-family:monospace;font-weight:700;'
        f'color:{_conf_color.get(entry["confidence"],"#636366")}">'
        f'{e(entry["display_service"])}</td>'
        f'<td style="padding:6px 12px;color:#aeaeb2">{entry["hosts"]}</td>'
        f'<td style="padding:6px 12px;color:#555;font-size:10px">'
        f'{e(entry["confidence"])} / {e(entry["fingerprint_source"])}</td>'
        f'<td style="padding:6px 12px;font-family:monospace;font-size:11px;color:#636366">'
        f'{", ".join(e(i) for i in entry["ips"][:5])}'
        f'{"..." if len(entry["ips"]) > 5 else ""}</td></tr>'
        for entry in svc_entries
    )

    hr_rows = "".join(
        f'<li style="margin:4px 0;font-size:12px">'
        f'<span style="font-family:monospace;color:#0a84ff">{e(ip)}</span> '
        f'<span style="color:#ff6b35">→ {e(svc)}</span> '
        f'<span style="color:#636366">({e(reason)})</span></li>'
        for svc, ip, reason in hr_svcs[:12]
    )

    hdr_rows = "".join(
        f'<li style="margin:4px 0;font-size:12px">'
        f'<span style="font-family:monospace;color:#0a84ff">{e(ip)}</span> '
        f'<span style="color:#ffd60a">→ {count} issue(s)</span></li>'
        for ip, count in sorted(hdr_by_host.items(), key=lambda x:-x[1])
    )

    atk_html = f"""
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:24px">
      <div style="padding:18px;background:#0a0a0a;border:1px solid #1a1a1a;border-radius:10px">
        <div style="font-size:11px;color:#333;text-transform:uppercase;letter-spacing:1px;margin-bottom:12px">
          Exposed Services ({len(svc_entries)} types)
        </div>
        <table style="width:100%;border-collapse:collapse">
          <tr style="color:#333;font-size:10px;text-transform:uppercase;letter-spacing:1px;border-bottom:1px solid #111">
            <th style="padding:4px 12px;text-align:left">Service</th>
            <th style="padding:4px 12px;text-align:left">Hosts</th>
            <th style="padding:4px 12px;text-align:left">Confidence / Source</th>
            <th style="padding:4px 12px;text-align:left">IPs</th>
          </tr>
          {svc_rows}
        </table>
      </div>
      <div>
        <div style="padding:18px;background:#0a0a0a;border:1px solid #1a1a1a;border-radius:10px;margin-bottom:12px">
          <div style="font-size:11px;color:#333;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">
            High-Risk Services
          </div>
          {"<ul style='list-style:none;padding:0'>"+hr_rows+"</ul>" if hr_rows else '<div style="color:#3a3a3c;font-size:12px">None detected</div>'}
        </div>
        {"<div style='padding:18px;background:#0a0a0a;border:1px solid #1a1a1a;border-radius:10px'><div style='font-size:11px;color:#333;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px'>HTTP Header Issues by Host</div><ul style='list-style:none;padding:0'>"+hdr_rows+"</ul></div>" if hdr_rows else ""}
      </div>
    </div>"""

    # ── Scan Quality ───────────────────────────────────────────────────────────
    sq_html = ""
    if sq:
        sq_html = f"""
    <div style="background:#0a0a0a;border:1px solid #1a1a1a;border-radius:8px;
                padding:16px 20px;margin-bottom:24px">
      <div style="font-size:11px;color:#333;text-transform:uppercase;letter-spacing:1px;
                  margin-bottom:12px">Scan Quality</div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px">
        {"".join(
          f'<div style="font-size:12px"><span style="color:#555">{lbl}:</span> '
          f'<span style="color:{col};font-weight:600">{val}</span></div>'
          for lbl, val, col in [
            ("Version-confirmed services",   sq.get("version_confirmed",0),      "#30d158"),
            ("Version-unconfirmed services", sq.get("version_unconfirmed",0),    "#aeaeb2"),
            ("Heuristic fingerprints",       sq.get("heuristic_fingerprints",0), "#636366"),
            ("Assets with strong identity",  sq.get("assets_strong_identity",0), "#30d158"),
            ("Assets with unknown identity", sq.get("assets_unknown_identity",0),"#636666"),
            ("CVE checks skipped (no ver.)", sq.get("cve_skipped_no_version",0), "#636366"),
            ("CVEs matched",                 sq.get("cves_matched",0),           "#ff9f0a"),
          ]
        )}
      </div>
    </div>"""

    # ── Host detail cards ─────────────────────────────────────────────────────
    host_html = ""
    for host in hosts:
        if not host["open_ports"]: continue
        os    = host.get("os",{})
        ext   = host.get("external",False)
        ts    = host.get("scan_timestamp","")
        hdur  = host.get("scan_duration","?")
        top_rs= max((p["risk"]["score"] for p in host["open_ports"]), default=0)
        top_rl= next((p["risk"]["level"] for p in host["open_ports"]
                      if p["risk"]["score"]==top_rs),"LOW")

        ports_html = ""
        for p in host["open_ports"]:
            ver     = p.get("version",{})
            cve_res = p.get("cve_result",{})
            cves    = cve_res.get("cves",[])
            advisory= cve_res.get("advisory","")
            conf    = ver.get("confidence", CONF_LOW)
            filt    = cve_res.get("filtered_count",0)

            ver_html = ""
            svc_ev_d  = p.get("service_evidence", {})
            disp_svc  = svc_ev_d.get("display_service", p.get("service",""))
            svc_conf  = svc_ev_d.get("service_confidence", "medium")
            svc_src   = svc_ev_d.get("fingerprint_source", "")
            # Show a qualification note for heuristic-only service labels
            svc_qual_html = ""
            if svc_conf == "low" and svc_src == "heuristic":
                svc_qual_html = (f' <span style="color:#3a3a3c;font-size:10px;font-style:italic">'
                                 f'(heuristic)</span>')

            if ver.get("product") and ver.get("version"):
                ver_html = (f'<div style="color:#0a84ff;font-family:monospace;font-size:11px;margin-top:2px">'
                           f'{e(ver["product"])} {e(ver["version"])} {conf_badge(conf)}</div>')
            elif ver.get("product"):
                ver_html = (f'<div style="color:#636366;font-family:monospace;font-size:11px;margin-top:2px">'
                           f'{e(ver["product"])} {conf_badge(conf)} '
                           f'<span style="color:#3a3a3c;font-size:10px">(version unknown)</span></div>')

            cve_html = ""
            if cves:
                cve_items = ""
                for cve in cves[:5]:
                    v_s = cve.get("vector","")[:40]
                    cve_items += (f'<div style="margin:3px 0;padding:5px 8px;background:#0a0a0a;border-radius:4px">'
                                f'<a href="{cve["url"]}" target="_blank" '
                                f'style="color:#0a84ff;font-family:monospace;font-size:11px;font-weight:700">'
                                f'{e(cve["id"])}</a>'
                                f'<span style="color:{sc(cve["severity"])};font-size:10px;font-weight:700;margin-left:8px">'
                                f'CVSS {cve["score"] or "?"} {cve["severity"]}</span>'
                                f'{f"<span style=color:#2a2a2a;font-size:10px;margin-left:4px>{e(v_s)}</span>" if v_s else ""}'
                                f'<div style="color:#555;font-size:11px;margin-top:2px;line-height:1.4">'
                                f'{e(cve["description"][:180])}</div></div>')
                if filt:
                    cve_items += (f'<div style="color:#2a2a2a;font-size:10px;margin-top:4px">'
                                f'{filt} older/irrelevant CVE(s) filtered out</div>')
                # Wrap in collapsible if more than 1 CVE to reduce visual density
                top_cve = cves[0]
                summary_badge = f'<span style="color:{sc(top_cve["severity"])};font-size:10px;font-weight:700">CVSS {top_cve["score"] or "?"} {top_cve["severity"]}</span>'
                if len(cves) == 1:
                    cve_html = cve_items
                else:
                    cve_html = (f'<details style="cursor:pointer">'
                               f'<summary style="font-size:11px;color:#636366;list-style:none;cursor:pointer;padding:3px 0">'
                               f'▸ {len(cves)} CVE(s) matched — top {summary_badge}'
                               f'</summary>{cve_items}</details>')
            elif advisory:
                cve_html = f'<div style="color:#555;font-size:11px;font-style:italic">{e(advisory)}</div>'
            else:
                cve_html = '<span style="color:#2a2a2a;font-size:11px">No CVEs — confidence too low or no matches</span>'

            sec_html = ""
            for sf in p.get("security",[]):
                sec_html += (f'<div style="margin:3px 0;padding:5px 8px;background:rgba(255,159,10,.04);'
                            f'border:1px solid rgba(255,159,10,.12);border-radius:4px">'
                            f'<span style="color:{sc(sf["severity"])};font-weight:700;font-size:11px">'
                            f'[{sf["category"]}] {e(sf["check"])}</span> '
                            f'{badge(sf["severity"], small=True)}'
                            f'<div style="color:#555;font-size:11px;margin-top:2px">{e(sf["detail"])}</div>'
                            f'{"<div style=color:#3a3a3c;font-size:10px;margin-top:2px>Fix: "+e(sf["remediation"])+"</div>" if sf.get("remediation") else ""}'
                            f'</div>')

            bd    = p.get("risk",{}).get("breakdown",{})
            facts = p.get("risk",{}).get("factors",[])
            brk   = (f'<div style="font-size:10px;color:#2a2a2a;margin-top:2px">'
                    f'base {bd.get("base",0)} + cve {bd.get("cve",0)} + '
                    f'advisory {bd.get("security_advisory",bd.get("auth",0))} + '
                    f'auth_failure {bd.get("auth_failure",0)} + '
                    f'net {bd.get("network_exposure",bd.get("network",0))}</div>')
            facs  = "".join(
                f'<div style="color:#ff9f0a;font-size:10px;margin:1px 0">&#9651; {e(f)}</div>'
                for f in facts)

            ports_html += (f'<tr style="border-bottom:1px solid #0d0d0d">'
                          f'<td style="padding:10px;font-family:monospace;color:#0a84ff;font-weight:700;white-space:nowrap">{p["port"]}</td>'
                          f'<td style="padding:10px;white-space:nowrap">'
                          f'{e(disp_svc)}{svc_qual_html}{ver_html}</td>'
                          f'<td style="padding:10px;white-space:nowrap">{badge(p["risk"]["level"])}{brk}</td>'
                          f'<td style="padding:10px;font-family:monospace;font-size:10px;color:#333;max-width:180px;word-break:break-all;line-height:1.4">{e(p["banner"][:150])}</td>'
                          f'<td style="padding:10px;min-width:240px">{cve_html}</td>'
                          f'<td style="padding:10px;min-width:200px">{sec_html or "<span style=color:#2a2a2a;font-size:11px>—</span>"}</td>'
                          f'<td style="padding:10px;min-width:150px">{facs or "<span style=color:#2a2a2a;font-size:11px>—</span>"}</td>'
                          f'</tr>')

        os_icons = {"windows":"⊞","linux":"🐧","router":"⇄","nas":"▣",
                    "printer":"⊡","freebsd":"◈","macos":"◈","camera":"📷","firewall":"🔥"}
        os_key   = next((k for k in os_icons if k in os.get("os_type","").lower()),"")
        os_icon  = os_icons.get(os_key,"?")

        # ── Asset enrichment data for this host card ──────────────────────────
        asset     = host.get("asset",{})
        a_hostname= asset.get("hostname","Unknown")
        a_dtype   = asset.get("device_type","Unknown Device")
        a_vendor  = asset.get("mac_vendor","")
        a_conf    = asset.get("confidence","low")
        a_sources = asset.get("sources",[])
        # Device icon based on device_type
        dev_icons = {
            "iphone":"📱","ipad":"📱","android":"📱","macbook":"💻","mac":"🖥",
            "windows":"🖥","linux":"🐧","router":"⇄","nas":"▣","printer":"🖨",
            "camera":"📷","smart tv":"📺","tv":"📺","echo":"🔊","speaker":"🔊",
            "raspberry":"🍓","esp":"⚡","iot":"⚡","xbox":"🎮","playstation":"🎮",
            "nintendo":"🎮","server":"🖥","firewall":"🔥","ubiquiti":"📡","ap":"📡",
        }
        dev_icon = "?"
        for kw, ic in dev_icons.items():
            if kw in a_dtype.lower() or kw in a_hostname.lower():
                dev_icon = ic; break

        display_name = a_hostname if a_hostname not in ("Unknown","") else ""
        name_pill = ""
        if display_name:
            conf_colors = {"high":"#30d158","medium":"#ffd60a","low":"#555"}
            nc = conf_colors.get(a_conf,"#555")
            name_pill = (f'<span style="background:rgba(255,255,255,.05);border:1px solid {nc}40;'
                        f'color:{nc};padding:2px 10px;border-radius:12px;font-size:12px;'
                        f'font-weight:600;font-family:monospace">'
                        f'{dev_icon} {e(display_name)}</span>')
        dtype_pill = ""
        if a_dtype not in ("Unknown","Unknown Device",""):
            dtype_pill = (f'<span style="color:#444;font-size:11px">{e(a_dtype)}</span>')
        vendor_pill = ""
        if a_vendor:
            vendor_pill = (f'<span style="background:#111;border:1px solid #222;color:#555;'
                          f'padding:1px 7px;border-radius:10px;font-size:10px">'
                          f'{e(a_vendor)}</span>')
        sources_html = ""
        if a_sources:
            sources_html = (f'<span style="color:#2a2a2a;font-size:10px">'
                           f'via {", ".join(e(s) for s in a_sources[:3])}</span>')

        # Service hints — secondary roles, shown separately from device identity
        a_hints = asset.get("service_hints", [])
        hints_html = ""
        if a_hints:
            hints_html = (f'<div style="color:#3a3a3c;font-size:10px;margin-top:3px">'
                         f'Service hints: {", ".join(e(h) for h in a_hints)}</div>')

        host_html += (f'<div style="margin:0 0 20px;border:1px solid '
                     f'{"rgba(255,45,85,.3)" if top_rl=="CRITICAL" else "#1a1a1a"}'
                     f';border-radius:10px;overflow:hidden">'
                     f'<div style="background:#0d0d0d;padding:12px 20px;display:flex;'
                     f'align-items:center;gap:10px;flex-wrap:wrap;border-bottom:1px solid #111">'
                     f'<span style="font-family:monospace;font-size:16px;font-weight:700;color:#fff">{host["ip"]}</span>'
                     f'{name_pill}'
                     f'{badge(top_rl)}'
                     f'{dtype_pill}'
                     f'{vendor_pill}'
                     f'<span style="color:#333;font-size:11px">{len(host["open_ports"])} port(s)</span>'
                     f'<span style="color:#3a3a3c;font-size:11px">{os_icon} {e(os.get("os_type","Unknown"))}</span>'
                     f'{"<span style=color:#ff6b35;font-size:11px>⚡ External</span>" if ext else "<span style=color:#30d158;font-size:11px>● Internal</span>"}'
                     f'{sources_html}'
                     f'<span style="color:#2a2a2a;font-size:11px;margin-left:auto">'
                     f'Scanned {e(ts[:19].replace("T"," "))} in {hdur}s</span>'
                     f'</div>'
                     f'{hints_html}'
                     f'<div style="overflow-x:auto">'
                     f'<table style="width:100%;border-collapse:collapse;font-size:12px">'
                     f'<thead><tr style="background:#080808;color:#222;font-size:10px;'
                     f'text-transform:uppercase;letter-spacing:1px">'
                     f'<th style="padding:8px 10px;text-align:left">Port</th>'
                     f'<th style="padding:8px 10px;text-align:left">Service / Version</th>'
                     f'<th style="padding:8px 10px;text-align:left">Risk</th>'
                     f'<th style="padding:8px 10px;text-align:left">Banner</th>'
                     f'<th style="padding:8px 10px;text-align:left">CVEs (confirmed)</th>'
                     f'<th style="padding:8px 10px;text-align:left">Security Checks</th>'
                     f'<th style="padding:8px 10px;text-align:left">Risk Factors</th>'
                     f'</tr></thead><tbody>{ports_html}</tbody></table></div></div>')

    # ── Remediation Priorities HTML section ──────────────────────────────────
    pri_html = ""
    if priorities:
        pri_rows = ""
        for p in priorities:
            pri_bg   = {"CRITICAL":"rgba(255,45,85,.15)","HIGH":"rgba(255,107,53,.12)",
                        "MEDIUM":"rgba(255,214,10,.08)","LOW":"rgba(48,209,88,.06)"}.get(p["priority"],"")
            pri_rows += f"""
            <div style="background:{pri_bg};border:1px solid #1a1a1a;border-radius:8px;
                        padding:14px 18px;margin-bottom:10px">
              <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:8px">
                <span style="color:#fff;font-size:13px;font-weight:700;font-family:monospace">{e(str(p['rank']))}.</span>
                <span style="color:#fff;font-size:13px;font-weight:700">{e(p['hostname'])}</span>
                <span style="color:#636366;font-size:12px">port {p['port']}/{e(p['service'])}</span>
                <span style="font-size:11px;color:#444">Priority: {badge(p['priority'],small=True)}</span>
                <span style="font-size:11px;color:#444">Risk: {badge(p['risk'],small=True)}</span>
              </div>
              {"".join(f'<div style="color:#aeaeb2;font-size:12px;margin:2px 0">Reason: {e(r)}</div>' for r in p["reasons"][:2])}
              <div style="color:#0a84ff;font-size:12px;margin-top:6px">Action: {e(p["action"][:200])}{"..." if len(p.get("action",""))>200 else ""}</div>
            </div>"""
        pri_html = pri_rows

    # ── Structured Findings HTML section ──────────────────────────────────────
    sig_findings = [f for f in all_findings if f.get("finding_type") != "http_headers"
                    and f.get("priority","LOW") not in ("LOW",)]
    low_findings = [f for f in all_findings if f.get("finding_type") == "http_headers"]

    find_html = ""
    for f in sig_findings[:12]:
        ev       = f.get("evidence",{})
        pri_c    = {"CRITICAL":"#ff2d55","HIGH":"#ff6b35","MEDIUM":"#ffd60a","LOW":"#30d158"}.get(f.get("priority","LOW"),"#555")
        ev_items = ""
        if ev.get("product") and ev.get("version"):
            ev_items += f'<div style="color:#aeaeb2;font-size:11px">Banner confirms: {e(ev["product"])} {e(ev["version"])}</div>'
        if ev.get("cves_matched"):
            ev_items += f'<div style="color:#aeaeb2;font-size:11px">CVEs matched: {ev["cves_matched"]} — highest CVSS {ev.get("highest_cvss","?")}</div>'
            if ev.get("cve_ids"):
                ev_items += f'<div style="color:#555;font-size:10px;font-family:monospace">{", ".join(ev["cve_ids"])}</div>'
        if ev.get("detail"):
            ev_items += f'<div style="color:#aeaeb2;font-size:11px">{e(str(ev["detail"])[:150])}</div>'

        find_html += f"""
        <div style="border:1px solid {'rgba(255,45,85,.25)' if f.get('priority')=='CRITICAL' else '#1a1a1a'};
                    border-radius:8px;margin-bottom:12px;overflow:hidden">
          <div style="background:#0d0d0d;padding:12px 16px;border-bottom:1px solid #111">
            <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
              <span style="color:{pri_c};font-size:14px;font-weight:700">{e(f['title'])}</span>
              <span style="color:#444;font-size:11px">Priority: {badge(f.get('priority','LOW'),small=True)}</span>
              <span style="color:#444;font-size:11px">Risk: {badge(f.get('risk','LOW'),small=True)}</span>
            </div>
            <div style="color:#555;font-size:11px;margin-top:4px">
              {e(f['ip'])} ({e(f['hostname'])}) — {e(f['service'])}
              {f' port {f["port"]}' if f.get("port") else ""}
              &nbsp;·&nbsp; Confidence: {e(f.get("confidence","").upper())}
              &nbsp;·&nbsp; Device: {e(f.get("device_type",""))}
            </div>
          </div>
          <div style="padding:12px 16px">
            {f'<details style="margin-bottom:8px"><summary style="font-size:11px;color:#555;cursor:pointer">Evidence</summary><div style="margin-top:6px">{ev_items}</div></details>' if ev_items else ""}
            <div style="margin-bottom:6px">
              <span style="font-size:11px;color:#555;font-weight:600">Why it matters:</span>
              <div style="color:#aeaeb2;font-size:12px;line-height:1.5;margin-top:2px">{e(f.get("why_it_matters","")[:300])}</div>
            </div>
            <div style="margin-bottom:6px">
              <span style="font-size:11px;color:#555;font-weight:600">Recommended action:</span>
              <div style="color:#0a84ff;font-size:12px;line-height:1.5;margin-top:2px">{e(f.get("recommendation","")[:300])}</div>
            </div>
            {f'<div style="color:#3a3a3c;font-size:11px;margin-top:6px;font-style:italic">Verification: {e(f.get("verification","")[:200])}</div>' if f.get("verification") else ""}
          </div>
        </div>"""

    if low_findings:
        lf_list = "".join(
            f'<li style="color:#555;font-size:11px;margin:3px 0">{e(f["ip"])} ({e(f.get("hostname",""))}) — '
            f'{e(", ".join(f.get("evidence",{}).get("missing_headers",[])[:3]))}</li>'
            for f in low_findings
        )
        find_html += f"""
        <details style="margin-top:8px">
          <summary style="font-size:12px;color:#444;cursor:pointer;padding:8px 0">
            ▸ HTTP header hardening items ({len(low_findings)} host(s)) — lower priority
          </summary>
          <div style="background:#0a0a0a;border:1px solid #111;border-radius:6px;padding:12px;margin-top:6px">
            <div style="color:#555;font-size:11px;margin-bottom:6px">
              Missing security headers are hardening findings. Lower priority on embedded/IoT devices
              unless the interface is externally accessible.
            </div>
            <ul style="list-style:disc;padding-left:16px">{lf_list}</ul>
          </div>
        </details>"""

    # ── Baseline changes HTML section ─────────────────────────────────────────
    baseline_html = ""
    if baseline_diff and baseline_diff.get("has_changes"):
        bdiff = baseline_diff
        bsumm = bdiff.get("summary",{})
        b_rows = ""
        for nh in bdiff.get("new_hosts",[]):
            b_rows += f'<div style="color:#30d158;font-size:12px;margin:4px 0">+ New: {e(nh["ip"])} ({e(nh.get("hostname",""))}) — {e(nh.get("device_type",""))}</div>'
        for rh in bdiff.get("removed_hosts",[]):
            b_rows += f'<div style="color:#636366;font-size:12px;margin:4px 0">- Removed: {e(rh["ip"])} ({e(rh.get("hostname",""))})</div>'
        for ch in bdiff.get("changed_hosts",[]):
            for np in ch.get("new_ports",[]):
                b_rows += f'<div style="color:#ffd60a;font-size:12px;margin:4px 0">↑ {e(ch["ip"])} ({e(ch.get("hostname",""))}): port {np["port"]}/{e(np["service"])} opened [{e(np["risk"])}]</div>'
            for cp in ch.get("closed_ports",[]):
                b_rows += f'<div style="color:#555;font-size:12px;margin:4px 0">↓ {e(ch["ip"])}: port {cp["port"]}/{e(cp["service"])} closed</div>'
        for v in bdiff.get("finding_verifications",[]):
            vc = {"remediated":"#30d158","still_present":"#ff9f0a","improved":"#0a84ff","changed":"#555"}.get(v["status"],"#555")
            vs = {"remediated":"Remediated","still_present":"Still present","improved":"Improved","changed":"Changed"}.get(v["status"],v["status"])
            b_rows += f'<div style="color:{vc};font-size:12px;margin:4px 0">{vs}: {e(v["ip"])} ({e(v.get("hostname",""))}) port {v["port"]}/{e(v["service"])} — {e(v.get("detail","")[:120])}</div>'

        redacted_note = '<div style="color:#ff9f0a;font-size:11px;margin-bottom:8px">This report was generated in redacted mode for sharing.</div>' if meta.get("redacted") else ""
        baseline_html = f"""
        {redacted_note}
        <div style="background:#0a0a0a;border:1px solid #1a1a1a;border-radius:8px;padding:16px;margin-bottom:20px">
          <div style="font-size:13px;color:#fff;font-weight:600;margin-bottom:10px">
            New: {bsumm.get("new_hosts",0)} &nbsp;·&nbsp;
            Removed: {bsumm.get("removed_hosts",0)} &nbsp;·&nbsp;
            Changed: {bsumm.get("changed_hosts",0)} &nbsp;·&nbsp;
            Remediated: {bsumm.get("remediated",0)} &nbsp;·&nbsp;
            Still present: {bsumm.get("still_present",0)}
          </div>
          {b_rows}
        </div>"""

    redacted_banner = ""
    if meta.get("redacted") and not baseline_diff:
        redacted_banner = '<div style="background:rgba(255,159,10,.1);border:1px solid rgba(255,159,10,.3);border-radius:6px;padding:10px 16px;margin-bottom:16px;color:#ff9f0a;font-size:12px">This report was generated in redacted mode for sharing. Personal hostnames and MAC addresses have been replaced.</div>'
    inv_rows = ""
    for item in inv:
        ports_str   = ", ".join(str(p) for p in item["open_ports"][:8])
        if len(item["open_ports"]) > 8: ports_str += f" +{len(item['open_ports'])-8}"
        svcs_str    = ", ".join(list(dict.fromkeys(item["services"]))[:5])
        vendor_html = (f'<span style="color:#555;font-size:11px">{e(item["mac_vendor"])}</span>'
                       if item["mac_vendor"] else '<span style="color:#222;font-size:11px">—</span>')
        hn_html     = (f'<span style="color:#30d158;font-size:12px;font-weight:600">{e(item["hostname"])}</span>'
                       if item["hostname"] not in ("Unknown","") else
                       '<span style="color:#2a2a2a;font-size:11px">Unknown</span>')
        dt_html     = (f'<span style="color:#aeaeb2;font-size:11px">{e(item["device_type"])}</span>'
                       if item["device_type"] not in ("Unknown","Unknown Device") else
                       '<span style="color:#2a2a2a;font-size:11px">Unknown</span>')
        conf_colors = {"high":"#30d158","medium":"#ffd60a","low":"#555"}
        cc = conf_colors.get(item["confidence"],"#555")
        src_str = ", ".join(item["sources"][:3]) if item["sources"] else "—"
        inv_rows += (f'<tr style="border-bottom:1px solid #0d0d0d">'
                    f'<td style="padding:8px 12px;font-family:monospace;color:#0a84ff;font-weight:700;white-space:nowrap">{e(item["ip"])}</td>'
                    f'<td style="padding:8px 12px">{hn_html}</td>'
                    f'<td style="padding:8px 12px">{dt_html}</td>'
                    f'<td style="padding:8px 12px">{vendor_html}</td>'
                    f'<td style="padding:8px 12px;font-family:monospace;font-size:10px;color:#555;max-width:160px">{e(ports_str)}</td>'
                    f'<td style="padding:8px 12px;white-space:nowrap">{badge(item["risk_level"])}'
                    f'<span style="color:#3a3a3c;font-size:10px;margin-left:4px">{item["risk_score"]}</span></td>'
                    f'<td style="padding:8px 12px"><span style="color:{cc};font-size:11px;font-weight:600">{item["confidence"].upper()}</span></td>'
                    f'<td style="padding:8px 12px;color:#2a2a2a;font-size:10px">{e(src_str)}</td>'
                    f'</tr>')

    inv_html = f"""
    <div style="overflow-x:auto;border:1px solid #1a1a1a;border-radius:10px;margin-bottom:24px">
      <table style="width:100%;border-collapse:collapse;font-size:12px">
        <thead><tr style="background:#0a0a0a;color:#333;font-size:10px;text-transform:uppercase;letter-spacing:1px;border-bottom:1px solid #1a1a1a">
          <th style="padding:10px 12px;text-align:left">IP Address</th>
          <th style="padding:10px 12px;text-align:left">Hostname</th>
          <th style="padding:10px 12px;text-align:left">Device Type</th>
          <th style="padding:10px 12px;text-align:left">MAC Vendor</th>
          <th style="padding:10px 12px;text-align:left">Open Ports</th>
          <th style="padding:10px 12px;text-align:left">Risk</th>
          <th style="padding:10px 12px;text-align:left">Confidence</th>
          <th style="padding:10px 12px;text-align:left">Sources</th>
        </tr></thead>
        <tbody>{inv_rows if inv_rows else "<tr><td colspan=8 style=padding:20px;color:#222;text-align:center>No hosts scanned</td></tr>"}</tbody>
      </table>
    </div>"""

    html_out = f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Heimdall v{VERSION} — {e(meta['target'])}</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Inter:wght@300;400;600;700&display=swap');
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:#050505;color:#fff;font-family:'Inter',sans-serif;min-height:100vh}}
a{{color:#0a84ff;text-decoration:none}}a:hover{{text-decoration:underline}}
.hdr{{background:linear-gradient(135deg,#06060f,#0a0e17,#030610);padding:32px 40px;
      border-bottom:1px solid #111820;position:relative;overflow:hidden}}
.hdr::before{{content:'';position:absolute;inset:0;
  background:radial-gradient(ellipse at 15% 60%,rgba(10,132,255,.06),transparent 55%);pointer-events:none}}
.logo{{font-family:'JetBrains Mono',monospace;font-size:24px;font-weight:700;color:#0a84ff;letter-spacing:4px}}
.sub{{color:#222;font-size:11px;letter-spacing:2px;text-transform:uppercase;margin-top:3px}}
.meta{{font-family:'JetBrains Mono',monospace;font-size:12px;color:#333;margin-top:10px}}
.content{{padding:24px 36px;max-width:1600px;margin:0 auto}}
.sec{{font-size:11px;color:#222;text-transform:uppercase;letter-spacing:2px;
       margin:22px 0 12px;padding-bottom:6px;border-bottom:1px solid #0d0d0d}}
.footer{{text-align:center;color:#111;font-size:11px;padding:32px;font-family:'JetBrains Mono',monospace}}
</style></head><body>
<div class="hdr">
  <div class="logo">&#x2B21; HEIMDALL</div>
  <div class="sub">Network Vulnerability Scanner v{VERSION}</div>
  <div class="meta">
    Target: {e(meta['target'])} &nbsp;&middot;&nbsp;
    {e(meta['scan_time'][:19].replace('T',' '))} &nbsp;&middot;&nbsp;
    {meta['duration']}s &nbsp;&middot;&nbsp;
    Mode: {e(meta.get('mode','standard'))} &nbsp;&middot;&nbsp;
    CVEs: {e(str(meta.get('cve_since', DEFAULT_CVE_SINCE)))}+
  </div>
</div>
<div class="content">
  {redacted_banner}
  <div class="sec">Executive Summary</div>
  {exec_html}
  <div class="sec">Remediation Priorities</div>
  <div style="margin-bottom:24px">{pri_html or '<div style="color:#222;padding:20px;text-align:center">No actionable priorities identified.</div>'}</div>
  <div class="sec">Findings</div>
  <div style="margin-bottom:24px">{find_html or '<div style="color:#222;padding:20px;text-align:center">No significant findings.</div>'}</div>
  {('<div class="sec">Baseline Changes</div>' + baseline_html) if baseline_html else ''}
  <div class="sec">Asset Inventory</div>
  {inv_html}
  <div class="sec">Attack Surface</div>
  {atk_html}
  <div class="sec">Detailed Evidence</div>
  {host_html or '<div style="color:#222;padding:40px;text-align:center">No open ports found.</div>'}
  <div class="sec">Verification Notes</div>
  <div style="background:#0a0a0a;border:1px solid #1a1a1a;border-radius:8px;padding:18px 22px;margin-bottom:24px">
    {"".join(f'<div style="margin:6px 0;color:#555;font-size:12px;line-height:1.6;padding-left:12px;border-left:2px solid #222">{e(n)}</div>' for n in vnotes)}
  </div>
  <div class="sec">Scan Quality</div>
  {sq_html}
</div>
<div class="footer">Heimdall v{VERSION} &nbsp;&middot;&nbsp; {e(meta['scan_time'][:19].replace('T',' '))} &nbsp;&middot;&nbsp; Authorized use only</div>
</body></html>"""

    with open(path,"w",encoding="utf-8") as f:
        f.write(html_out)
    print(f"  {clr('HTML',C.CYAN)} → {path}")


def write_json(results: dict, path: str):
    with open(path,"w",encoding="utf-8") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"  {clr('JSON',C.CYAN)} → {path}")

# ──────────────────────────────────────────────────────────────────────────────
# CLI + MAIN
# ──────────────────────────────────────────────────────────────────────────────
def parse_ports(spec: str) -> list:
    if spec=="quick":  return QUICK_PORTS
    if spec=="common": return COMMON_PORTS
    if spec=="all":    return list(range(1,65536))
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            a,b = part.split("-",1)
            ports.update(range(int(a),int(b)+1))
        else:
            ports.add(int(part))
    return sorted(ports)

def main():
    print(BANNER_ART)

    parser = argparse.ArgumentParser(
        description=f"Heimdall v{VERSION} — Network Asset Discovery and Vulnerability Assessment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
MODES:
  --quick    Fast scan: top ports, banner grab, no CVE or security checks
  --full     Deep scan: all 65535 ports, full CVE + security checks

PROFILES:
  --profile home            Plain-English summary, top findings, no raw data
  --profile small-business  Asset inventory, services, remediations, baseline changes
  --profile technical       Full output — banners, CVE details, scoring breakdowns

CVE POLICY:
  CVEs are only assigned when product and version are confirmed from the banner.
  If version is unknown, CVE matching is skipped and the report says so.
  Default year filter: {DEFAULT_CVE_SINCE}+. Use --cve-since 2010 for a broader sweep.

EXAMPLES:
  python scanner.py --quick
  python scanner.py --full --target 192.168.1.5
  python scanner.py --target 192.168.1.0/24 --profile home
  python scanner.py --baseline previous_report.json
  python scanner.py --redact --output html
        """
    )
    mg = parser.add_mutually_exclusive_group()
    mg.add_argument("--quick", action="store_true", help="Fast scan — top ports, no CVE/checks")
    mg.add_argument("--full",  action="store_true", help="Deep scan — all ports, CVE + security")

    parser.add_argument("--target",       default="192.168.1.0/24",
                        help="IP, hostname, or CIDR range (default: 192.168.1.0/24)")
    parser.add_argument("--ports",        help="Override ports: 'common','all','1-1024','80,443'")
    parser.add_argument("--output",       default="both", choices=["html","json","both"])
    parser.add_argument("--outfile",      default="heimdall_report")
    parser.add_argument("--profile",      default="technical",
                        choices=["home","small-business","technical"],
                        help="Report profile (default: technical)")
    parser.add_argument("--baseline",     default="",
                        help="Compare current scan against a previous JSON report file")
    parser.add_argument("--compare",      default="",
                        help="Alias for --baseline (compare against a previous report)")
    parser.add_argument("--redact",       action="store_true",
                        help="Replace personal hostnames and MACs before saving report")
    parser.add_argument("--threads",      type=int,   default=300)
    parser.add_argument("--host-threads", type=int,   default=8)
    parser.add_argument("--timeout",      type=float, default=0.5)
    parser.add_argument("--cve-since",    type=int,   default=DEFAULT_CVE_SINCE,
                        help=f"Only include CVEs from this year onwards (default: {DEFAULT_CVE_SINCE})")
    parser.add_argument("--no-security",  action="store_true", help="Skip active security checks")
    parser.add_argument("--no-cve",       action="store_true", help="Skip NVD CVE queries")
    parser.add_argument("--no-banner",    action="store_true", help="Skip banner grabbing")
    parser.add_argument("--nvd-key",      default="",
                        help="NVD API key for higher rate limits (free at nvd.nist.gov)")
    args = parser.parse_args()

    # Resolve scan mode settings
    if args.quick:
        mode="quick";    port_spec="quick";   do_cves=False; do_sec=False; do_ban=True
    elif args.full:
        mode="full";     port_spec="all";     do_cves=True;  do_sec=True;  do_ban=True
    else:
        mode="standard"; port_spec="common";  do_cves=True;  do_sec=True;  do_ban=True

    if args.ports:        port_spec = args.ports
    if args.no_cve:       do_cves   = False
    if args.no_security:  do_sec    = False
    if args.no_banner:    do_ban    = False

    profile   = PROFILES.get(args.profile, PROFILE_TECHNICAL)
    ports     = parse_ports(port_spec)
    cve_since = args.cve_since

    # --compare is an alias for --baseline
    baseline_path = args.baseline or args.compare

    # Load baseline before scanning so we can flag if it's invalid early
    baseline_data = {}
    if baseline_path:
        baseline_data = load_baseline(baseline_path)
        print(f"  {clr('Baseline:',C.CYAN)}   {baseline_path} ({len(baseline_data)} host(s))")

    print(f"  {clr('Target:',C.CYAN)}     {args.target}")
    print(f"  {clr('Mode:',C.CYAN)}       {mode}  /  Profile: {profile['name']}")
    print(f"  {clr('Ports:',C.CYAN)}      {len(ports)} ({port_spec})")
    print(f"  {clr('Banners:',C.CYAN)}    {'yes' if do_ban else 'no'}")
    print(f"  {clr('CVE:',C.CYAN)}        {'yes — ' + str(cve_since) + '+ only, version-confirmed' if do_cves else 'no'}")
    print(f"  {clr('Security:',C.CYAN)}   {'yes' if do_sec else 'no'}")
    if args.nvd_key: print(f"  {clr('NVD key:',C.CYAN)}    set")
    if args.redact:  print(f"  {clr('Redact:',C.CYAN)}     enabled")

    start = time.time()
    live  = discover_hosts(args.target)
    if not live:
        print(clr("\n  No live hosts found.", C.YELLOW)); sys.exit(0)

    print(f"\n{clr('[ SCANNING ]',C.CYAN,C.BOLD)}  {len(live)} host(s)\n")

    host_results = []
    with ThreadPoolExecutor(max_workers=args.host_threads) as ex:
        futures = {
            ex.submit(scan_host, ip, ports, args.threads, args.timeout,
                      do_ban, do_cves, do_sec, args.nvd_key, cve_since): ip
            for ip in live
        }
        for fut in as_completed(futures):
            r = fut.result()
            if r: host_results.append(r)

    duration = round(time.time()-start, 1)
    host_results.sort(key=lambda x:[int(p) for p in x["ip"].split(".")])

    # Build all report sections
    exec_summ    = build_exec_summary(host_results, args.target, duration, mode, cve_since)
    atk_surf     = build_attack_surface(host_results)
    asset_inv    = build_asset_inventory(host_results)
    findings     = build_structured_findings(host_results)
    priorities   = build_remediation_priorities(host_results, findings)
    verif_notes  = build_verification_notes()
    scan_quality = build_scan_quality(host_results)

    # Baseline comparison (if requested)
    baseline_diff = None
    if baseline_data:
        baseline_diff = compare_to_baseline(host_results, baseline_data)

    results = {
        "scan_metadata": {
            "target":           args.target,
            "mode":             mode,
            "profile":          profile["name"],
            "scan_time":        datetime.now().isoformat(),
            "duration":         duration,
            "ports_scanned":    len(ports),
            "hosts_discovered": len(live),
            "cve_since":        cve_since,
            "heimdall_version": VERSION,
            "redacted":         args.redact,
        },
        "executive_summary":      exec_summ,
        "scan_quality":           scan_quality,
        "asset_inventory":        asset_inv,
        "findings":               findings,
        "remediation_priorities": priorities,
        "attack_surface":         atk_surf,
        "baseline_changes":       baseline_diff,
        "verification_notes":     verif_notes,
        "hosts":                  host_results,
    }

    # Redact before saving if requested
    if args.redact:
        results = redact_results(results)
        print(f"\n  {clr('[REDACTED]',C.YELLOW)} Personal hostnames and MACs replaced.")

    # ── Terminal summary ──────────────────────────────────────────────────────
    print(f"\n{clr('='*62,C.DIM)}")
    print(f"{clr('[ COMPLETE ]',C.GREEN,C.BOLD)}  {duration}s")
    ov = exec_summ['overall_risk']
    print(f"  {clr('Overall risk:',C.CYAN)} {clr(ov, SEV_CLR.get(ov,C.DIM), C.BOLD)}")
    print(f"  Hosts: {exec_summ['hosts_scanned']}  "
          f"Ports: {exec_summ['open_ports']}  "
          f"CVEs: {exec_summ['cves_matched']}  "
          f"Auth issues: {exec_summ['auth_issues']}")

    if exec_summ.get("top_risk_host"):
        trh = exec_summ["top_risk_host"]
        trs = exec_summ["top_risk_score"]
        # Look up hostname for the top risk host
        trh_hostname = next(
            (h.get("asset",{}).get("hostname","") for h in host_results if h["ip"] == trh), ""
        )
        trh_display = f"{trh} ({trh_hostname})" if trh_hostname not in ("","Unknown") else trh
        print(f"\n  {clr('Top Risk Host:',C.CYAN)} {clr(trh_display,C.BOLD,C.WHITE)} "
              f"{clr(f'score {trs}',C.RED)}")
        for r in exec_summ.get("top_risk_reasons",[])[:2]:
            print(f"    {clr('•',C.YELLOW)} {r}")

    if exec_summ["key_findings"]:
        print(f"\n  {clr('Key Findings:',C.CYAN)}")
        for kf in exec_summ["key_findings"]:
            print(f"    {clr('•',C.YELLOW)} {kf}")

    # Asset inventory — fixed-width columns using ansi_ljust for ANSI-safe alignment
    if asset_inv:
        IP_W  = 18
        HN_W  = 22
        DT_W  = 28

        print(f"\n  {clr('Asset Inventory:',C.CYAN,C.BOLD)}")
        # Headers use plain strings (no ANSI) so standard ljust works
        print(f"  {'IP':<{IP_W}} {'Hostname':<{HN_W}} {'Device Type':<{DT_W}} Risk")
        print(f"  {clr('─'*(IP_W+HN_W+DT_W+12), C.DIM)}")

        for item in asset_inv:
            ip_s = item["ip"]
            hn   = item["hostname"] if item["hostname"] not in ("Unknown","") else "—"
            dt   = item["device_type"] if item["device_type"] not in ("Unknown","Unknown Device") else "—"
            rl   = item["risk_level"]

            # Truncate to column width before colouring — avoids double-counting ANSI bytes
            hn_s = (hn[:HN_W-3] + "…") if len(hn) > HN_W else hn
            dt_s = (dt[:DT_W-3] + "…") if len(dt) > DT_W else dt

            # Use ansi_ljust so coloured IP doesn't break the column
            print("  " + ansi_ljust(clr(ip_s, C.CYAN), IP_W) + " "
                  + f"{hn_s:<{HN_W}}" + " "
                  + f"{dt_s:<{DT_W}}" + " "
                  + clr(rl, SEV_CLR.get(rl, C.DIM)))

    # Attack surface — use confidence-aware display_service from service_entries
    svc_entries = atk_surf.get("service_entries", [])
    if svc_entries:
        print(f"\n  {clr('Attack Surface:',C.CYAN)}")
        for entry in svc_entries[:10]:
            disp   = entry["display_service"]
            n_hosts= entry["hosts"]
            conf   = entry["confidence"]
            conf_c = CONF_CLR.get(conf, C.DIM)
            conf_note = f" {clr('('+conf+')', conf_c)}" if conf != "high" else ""
            print(f"    {clr('•',C.DIM)} {disp} — {n_hosts} host{'s' if n_hosts>1 else ''}{conf_note}")

    hdr = atk_surf.get("header_by_host",{})
    if hdr:
        print(f"\n  {clr('HTTP Header Issues:',C.CYAN)}")
        for ip, count in sorted(hdr.items(), key=lambda x:-x[1]):
            hn = next((h.get("asset",{}).get("hostname","") for h in host_results if h["ip"]==ip),"")
            label = f" ({hn})" if hn not in ("","Unknown") else ""
            print(f"    {clr('•',C.DIM)} {ip}{label} — {count} issue(s)")

    # Scan Quality — shows how much was confirmed vs inferred
    sq = scan_quality
    print(f"\n  {clr('Scan Quality:',C.CYAN,C.BOLD)}")
    print(f"    Version-confirmed services:    {sq['version_confirmed']}")
    print(f"    Version-unconfirmed services:  {sq['version_unconfirmed']}")
    print(f"    Heuristic fingerprints:        {clr(str(sq['heuristic_fingerprints']), C.DIM)}")
    print(f"    Assets with strong identity:   {sq['assets_strong_identity']}")
    print(f"    Assets with unknown identity:  {clr(str(sq['assets_unknown_identity']), C.DIM)}")
    print(f"    CVE checks skipped (no ver.):  {clr(str(sq['cve_skipped_no_version']), C.DIM)}")
    print(f"    CVEs matched (version-conf.):  {sq['cves_matched']}")

    # Remediation priorities — priority and risk shown separately
    if priorities:
        print(f"\n  {clr('Remediation Priorities:',C.CYAN,C.BOLD)}")
        for p in priorities:
            pri_c  = SEV_CLR.get(p["priority"], C.DIM)
            risk_c = SEV_CLR.get(p["risk"], C.DIM)
            host_str = p["hostname"] if p["hostname"] not in ("","Unknown") else p["ip"]
            svc_str  = f"port {p['port']}/{p['service']}" if p["ip"] != "multiple" else p["service"]
            print(f"\n  {clr(str(p['rank'])+'.', C.BOLD)} {clr(host_str, C.WHITE)} — {svc_str}")
            print(f"     {clr('Priority:', C.DIM)} {clr(p['priority'], pri_c)}  "
                  f"{clr('Risk:', C.DIM)} {clr(p['risk'], risk_c)}")
            for reason in p["reasons"][:2]:
                print(f"     {clr('Reason:', C.DIM)} {reason}")
            action_short = p["action"][:120] + ("..." if len(p["action"]) > 120 else "")
            print(f"     {clr('Action:', C.CYAN)} {action_short}")

    # Findings — show non-header, non-LOW findings as brief analyst-style entries
    sig_findings = [f for f in findings
                    if f.get("finding_type") != "http_headers"
                    and f.get("priority","LOW") not in ("LOW",)]
    if sig_findings:
        print(f"\n  {clr('Findings:',C.CYAN,C.BOLD)}")
        for f in sig_findings[:8]:   # cap at 8 in terminal; full list in report
            pri_c  = SEV_CLR.get(f.get("priority","LOW"), C.DIM)
            hn     = f["hostname"] if f["hostname"] not in ("Unknown","") else f["ip"]
            port_s = f"port {f['port']}" if f.get("port") else ""
            print(f"\n  {clr('◆',pri_c)} {f['title']}")
            print(f"     Asset: {clr(f['ip'],C.CYAN)} ({hn})  {port_s}  {f['service']}")
            print(f"     {clr('Risk:',C.DIM)} {clr(f['risk'],SEV_CLR.get(f['risk'],C.DIM))}  "
                  f"{clr('Priority:',C.DIM)} {clr(f.get('priority','LOW'),pri_c)}  "
                  f"{clr('Confidence:',C.DIM)} {f.get('confidence','').upper()}")
            ev = f.get("evidence",{})
            if ev.get("product") and ev.get("version"):
                print(f"     {clr('Evidence:',C.DIM)} {ev['product']} {ev['version']}"
                      + (f", {ev['cves_matched']} CVE(s), top CVSS {ev['highest_cvss']}"
                         if ev.get("cves_matched") else ""))
            elif ev.get("detail"):
                print(f"     {clr('Evidence:',C.DIM)} {ev['detail'][:100]}")
            print(f"     {clr('Action:',C.CYAN)} {f['recommendation'][:100]}"
                  + ("..." if len(f.get("recommendation","")) > 100 else ""))

    # Baseline diff
    if baseline_diff:
        print_baseline_diff(baseline_diff)

    # Verification notes — printed at the end so they're easy to find
    print(f"\n  {clr('Verification Notes:',C.DIM)}")
    for note in verif_notes:
        # Wrap at ~80 chars for clean terminal display
        words = note.split()
        line  = "    "
        for word in words:
            if len(line) + len(word) + 1 > 82:
                print(clr(line, C.DIM))
                line = "    " + word + " "
            else:
                line += word + " "
        if line.strip():
            print(clr(line.rstrip(), C.DIM))

    # Save reports
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = f"{args.outfile}_{ts}"
    print(f"\n{clr('[ REPORTS ]',C.CYAN,C.BOLD)}")
    if args.output in ("json","both"): write_json(results, f"{base}.json")
    if args.output in ("html","both"): write_html(results, f"{base}.html")
    print(f"\n{clr('='*62,C.DIM)}\n")


if __name__ == "__main__":
    main()
