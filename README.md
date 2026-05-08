# Heimdall — Network Asset Discovery & Vulnerability Assessment

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Tests](https://img.shields.io/badge/tests-97%20passing-brightgreen)
![Dependencies](https://img.shields.io/badge/dependencies-none-lightgrey)

Heimdall is a Python-based network scanner built for home labs and small networks. It performs host discovery, port scanning, service fingerprinting, asset enrichment, CVE matching, and risk scoring — then produces clean HTML and JSON reports.

The design goal was to build something that explains its findings rather than just listing them. Every result includes confidence levels, evidence sources, and the reasoning behind the risk score.

> **Authorized use only.** Only scan networks you own or have explicit written permission to test.

---

## Why Heimdall exists

Most scanners produce long lists of alerts without explaining why something was flagged or how confident the detection actually is. Heimdall takes a different approach:

- **CVEs are only assigned when product and version are both confirmed from the service banner** — not from keyword searches that return hundreds of loosely-related results
- **Confidence is explicit** — every service fingerprint and device identification includes its evidence source and certainty tier
- **Heuristic observations are labeled as such** — port 50000 shows as `Possible IBM-DB2-like service`, not `IBM-DB2`
- **Risk scores reflect context** — an internal SSH server with outdated software scores differently than an externally-routable one with no authentication
- **Findings are prioritized for action**, not volume — the goal is fewer, higher-quality findings you can actually act on

*Design philosophy: favor explainability and evidence quality over maximizing finding count.*

---

## Contents

- [Features](#features)
- [How it works](#how-it-works)
- [CVE matching methodology](#cve-matching-methodology)
- [Risk scoring](#risk-scoring)
- [Installation](#installation)
- [Usage](#usage)
- [Report profiles](#report-profiles)
- [Baseline comparison](#baseline-comparison)
- [Redacted output](#redacted-output)
- [Sample output](#sample-output)
- [Screenshots](#screenshots)
- [Project structure](#project-structure)
- [Running tests](#running-tests)
- [Limitations](#limitations)
- [Ethical use](#ethical-use)
- [Roadmap](#roadmap)

---

## Features

**Discovery & scanning**
- ICMP + TCP host discovery across a subnet or single target
- TCP connect scan with configurable port lists (`common`, `all`, or custom range/list)
- Protocol-aware banner grabbing: SSH, FTP, HTTP/S, SMTP, Redis, MySQL, and others

**Service fingerprinting**
- Extracts product name and version from banners using service-specific patterns
- Three confidence tiers: `high` (version confirmed from banner), `medium` (well-known IANA port), `low` (port-convention heuristic)
- Heuristic fingerprints are labeled — `Possible IBM-DB2-like service`, not `IBM-DB2`

**Asset enrichment**
- Multi-source device identification: reverse DNS, NetBIOS (UDP 137), mDNS (port 5353), HTTP page title, TLS certificate CN/SAN, MAC vendor OUI
- 400+ OUI entries for common home and office hardware
- Identity precedence: vendor OUI → hostname keywords → port signatures → OS fingerprint (documented in code)

**CVE matching**
- Queries NIST NVD API 2.0 using banner-confirmed product and version fingerprints
- Only fires when both product and version are confirmed — version-unknown services are skipped and reported
- Year filter (default: 2017+) and product relevance check applied; all skipped results are counted and disclosed

**Active security checks**
- FTP anonymous login, Redis / MongoDB / Elasticsearch open access, VNC no-auth, SNMP default community string
- SMBv1 negotiation, SMB signing status, outdated OpenSSH
- HTTP security header audit: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy

**Risk scoring**
- Composite 0–100 score per port: base exposure + CVE contribution + security advisory + confirmed auth failure + network context
- Internal services capped at MEDIUM unless a critical CVE (CVSS ≥9.0), confirmed auth failure, or external exposure is present
- Full score breakdown included in every finding

**Reporting**
- HTML report: executive summary, remediation priorities, findings, asset inventory, attack surface, baseline changes, scan quality, verification notes
- JSON output with stable schema suitable for further processing
- Terminal summary with aligned columns, ANSI color, and scan quality metrics

**Workflow**
- Baseline comparison (`--compare`): detects new/removed hosts, opened/closed ports, risk changes, and whether prior findings were remediated
- Report profiles: `home`, `small-business`, `technical`
- Redacted mode (`--redact`): replaces all IPs and hostnames with stable category labels for safe sharing

---

## How it works

```
Host Discovery       — ICMP + TCP probes
    ↓
Port Scanning        — TCP connect, configurable port list
    ↓
Banner Grabbing      — Protocol-aware, per-service patterns
    ↓
Service Fingerprinting — Version extraction, confidence assignment
    ↓
Asset Enrichment     — rDNS, NetBIOS, mDNS, OUI, HTTP title, TLS cert
    ↓
OS Fingerprinting    — TTL, SSH banner, port combinations
    ↓
Security Checks      — SMB, Redis, FTP, VNC, HTTP headers...
    ↓
CVE Lookup           — NVD API, banner-confirmed only
    ↓
Risk Scoring         — Composite score with context adjustment
    ↓
Findings & Priorities — Deduplicated, ranked, evidence-backed
    ↓
HTML / JSON Report
```

All enrichment probes run concurrently with short timeouts. A typical /24 home network scan completes in 20–40 seconds depending on host count and port list.

---

## CVE matching methodology

Most tools send a product name to a vulnerability database and return every CVE that mentions it — including results for other products, unrelated packages, and kernel patches. The list looks thorough; most of it doesn't apply.

Heimdall only queries NVD after confirming a specific product and version from the service banner. If a host returns:

```
SSH-2.0-OpenSSH_7.9
```

Heimdall queries NVD for `OpenSSH 7.9` specifically, then applies two additional filters:

- **Publication year** — default 2017+, configurable with `--cve-since`
- **Product relevance** — the CVE description must reference the product name; CRITICAL-rated CVEs bypass this filter

If the version isn't present in the banner, CVE matching is skipped:

```
[CVE] 50000: version unconfirmed — skipped
```

This produces fewer matches, but every match is directly tied to what was observed on the network.

**Confidence levels** are carried through the full report:

| Level    | Meaning                                                    |
|----------|------------------------------------------------------------|
| `high`   | Product and version confirmed from service banner          |
| `medium` | Service inferred from well-known IANA port assignment      |
| `low`    | Heuristic — port associated with service by convention only |

The distinction matters. A port-9000 service labeled `Possible PHP-FPM-like service (heuristic)` is treated differently from a confirmed `OpenSSH 7.9`. Both appear in the attack surface and JSON output with their respective confidence levels.

---

## Risk scoring

Each open port receives a composite score from 0–100:

```
score = base_port_risk
      + cve_contribution       (banner-confirmed CVEs only)
      + security_advisory      (version advisory, e.g. outdated SSH)
      + auth_failure           (confirmed access without credentials)
      + network_exposure       (+15 for external/routable IPs)
```

| Score | Level    |
|-------|----------|
| ≥ 75  | CRITICAL |
| ≥ 50  | HIGH     |
| ≥ 25  | MEDIUM   |
| < 25  | LOW      |

**Context cap for internal services:**

An internal service with CVE matches but no confirmed authentication failure and no critical CVE (CVSS ≥9.0) is capped at MEDIUM (score ≤49).

The reasoning: an SSH server running outdated OpenSSH on a home network is worth fixing, but it represents a different exposure level than a Redis instance accessible without credentials or a service reachable from outside the LAN. Scoring them the same would inflate results without adding signal.

The remediation priority engine scores independently, so capped findings still appear near the top of the priority list. The severity label changes; the urgency does not.

---

## Installation

No external libraries required — standard library only.

```bash
git clone https://github.com/Gab3lewis/heimdall-network-scanner.git
cd heimdall-network-scanner
python scanner.py --help
```

**Requirements:**
- Python 3.8+
- Windows, Linux, or macOS
- NVD API key (optional, free at [nvd.nist.gov](https://nvd.nist.gov/developers/request-an-api-key)) — increases CVE lookup rate limits

---

## Usage

```bash
# Quick scan — top ports, banners, no CVE lookup
python scanner.py --quick

# Standard subnet scan (default target: 192.168.1.0/24)
python scanner.py --target 192.168.1.0/24

# Full scan of a single host — all ports, CVE lookup
python scanner.py --full --target 192.168.1.5

# With NVD API key for faster CVE lookups
python scanner.py --target 192.168.1.0/24 --nvd-key YOUR_KEY

# Limit CVEs to 2019 and later
python scanner.py --cve-since 2019

# HTML report only
python scanner.py --output html

# Home profile — grouped, plain-language summary
python scanner.py --profile home

# Compare against a previous scan
python scanner.py --compare heimdall_report_20250501_120000.json

# Redact all IPs and hostnames before saving
python scanner.py --redact --output both
```

**Full option reference:**

```
Target:
  --target IP/CIDR      IP, hostname, or CIDR range (default: 192.168.1.0/24)
  --ports SPEC          'common', 'all', '1-1024', '80,443,22'

Scan modes:
  --quick               Top ports, banners, no CVE or security checks
  --full                All 65535 ports, CVE + full security checks

Report:
  --output html|json|both
  --outfile PREFIX      Output filename prefix
  --profile PROFILE     home / small-business / technical (default: technical)
  --redact              Replace IPs and hostnames in output

Baseline:
  --compare FILE.json   Compare against a previous Heimdall report

CVE:
  --cve-since YEAR      Earliest CVE publication year (default: 2017)
  --nvd-key KEY         NVD API key
  --no-cve              Skip CVE lookup entirely

Toggles:
  --no-security         Skip active security checks
  --no-banner           Skip banner grabbing

Performance:
  --threads N           Port scan threads per host (default: 300)
  --host-threads N      Concurrent host scans (default: 8)
  --timeout SECS        Socket timeout (default: 0.5)
```

---

## Report profiles

**`--profile home`**
Simplified output for a home network audience. Focuses on unknown devices, open services, and actionable findings. HTTP header issues are grouped as lower-priority hardening items.

**`--profile small-business`**
Asset inventory, exposed services, remediation priorities, and baseline changes. Includes CVSS scores and more detail than the home profile.

**`--profile technical`** *(default)*
Full output: banners, CVE details, confidence levels, score breakdowns, raw evidence. Intended for security review or reporting.

---

## Baseline comparison

Save a scan as JSON, then compare a later scan against it:

```bash
# Save initial scan
python scanner.py --output json

# Later — diff against it
python scanner.py --compare heimdall_report_20250401_120000.json
```

The comparison detects:

- New and removed hosts
- Newly opened or closed ports
- Risk level changes
- Service and version changes
- Whether prior findings have been remediated or are still present

Example terminal output:

```
[ BASELINE CHANGES ]
  New: 1  Removed: 0  Changed: 1  Remediated: 1  Still present: 1

  New devices:
    + IOT-002 (amazon-3a91f2c) — Amazon Smart Device
      Ports: 80, 443

  Finding verification:
    ✓  Remediated  LINUX-001 port 22/SSH
         Version updated: OpenSSH 7.9 → OpenSSH 9.6. No CVEs matched on current version.
    →  Still present  WORKSTATION-001 port 445/SMB
         SMB exposure on port 445 — configuration unchanged.
```

---

## Redacted output

Run with `--redact` before sharing output publicly:

```bash
python scanner.py --target 192.168.1.0/24 --redact --output both
```

Every IP and hostname is replaced with a stable, category-based label derived from device type:

| Real value       | Redacted label  |
|------------------|-----------------|
| 192.168.1.17     | LINUX-001       |
| raspberrypi      | LINUX-001       |
| 192.168.1.248    | WORKSTATION-001 |
| Gabes-PC         | WORKSTATION-001 |
| 192.168.1.1      | ROUTER-001      |
| RT-AC5300-52C0   | ROUTER-001      |
| 192.168.1.28     | IOT-001         |
| ESP_062EF5       | IOT-001         |

Labels are consistent across every report section — `LINUX-001` in the Asset Inventory refers to the same host in Findings, Remediation Priorities, Attack Surface, and the executive summary.

Preserved (not redacted): port numbers, service names, CVE IDs, CVSS scores, risk levels, device type descriptions, and recommendations.

---

## Sample output

```
[ COMPLETE ]  23s
  Overall risk: MEDIUM
  Hosts: 5  Ports: 16  CVEs: 5  Auth issues: 0

  Asset Inventory:
  IP               Hostname          Device Type              Risk
  ──────────────────────────────────────────────────────────────────
  LINUX-001        LINUX-001         Raspberry Pi             MEDIUM
  WORKSTATION-001  WORKSTATION-001   Windows PC/Server        MEDIUM
  ROUTER-001       ROUTER-001        Router (ASUS)            LOW
  CAST-001         Unknown           Google Cast Device       LOW
  IOT-001          IOT-001           IoT Device (ESP-based)   LOW

  Remediation Priorities:

  1. LINUX-001 — port 22/SSH
     Priority: HIGH  Risk: MEDIUM
     Reason: Version confirmed (OpenSSH 7.9), 5 CVE(s) matched, top CVSS 7.8
     Action: Upgrade OpenSSH using the host's package manager...

  2. WORKSTATION-001 — port 445/SMB
     Priority: MEDIUM  Risk: MEDIUM
     Reason: SMB exposed — verify sharing config and SMBv1 status
     Action: Run: Get-SmbServerConfiguration | Select EnableSMB1Protocol...

  Scan Quality:
    Version-confirmed services:    3
    Version-unconfirmed services:  8
    Heuristic fingerprints:        2
    Assets with strong identity:   4
    Assets with unknown identity:  1
    CVE checks skipped (no ver.):  9
    CVEs matched (version-conf.):  5
```

---

## Screenshots

Screenshots are in the [`screenshots/`](screenshots/) folder.

*Run the scanner with `--redact` and add your own.*

---

## Project structure

```
heimdall-network-scanner/
├── scanner.py              # Main script — all logic in one file
├── tests/
│   └── test_heimdall.py    # 97 unit tests
├── examples/
│   └── README.md           # Notes on sample output
├── screenshots/
│   └── README.md
├── .gitignore
├── LICENSE
└── README.md
```

A future refactor could split this into modules (`discovery`, `ports`, `banners`, `enrichment`, `cves`, `risk`, `findings`, `reporting`), but the single-file layout makes it straightforward to run, audit, and share.

---

## Running tests

```bash
# No pytest required
python tests/test_heimdall.py

# With pytest
python -m pytest tests/ -v
```

97 tests covering: banner parsing, CVE year and relevance filtering, device classification, risk scoring (including the internal cap logic), baseline comparison, structured findings generation, finding deduplication, service fingerprint confidence, attack surface confidence, OS fingerprint precedence, scan quality counts, SMB wording constraints, and redaction label consistency.

---

## Limitations

- **CVE matching is conservative by design.** If a service doesn't expose version information in its banner, no CVEs are assigned — even if the underlying software is outdated. The alternative is a long list of results that can't be meaningfully verified.

- **Hostname detection depends on available signals.** Reverse DNS, NetBIOS, and mDNS are passive queries. If a device doesn't respond to any of them, it's listed as `Unknown` rather than guessed from port patterns alone.

- **MAC vendor lookup requires a resolved MAC address.** ARP resolution typically needs elevated privileges or access to the system ARP cache. Without a MAC, OUI-based identification is skipped.

- **Active security checks send real packets.** Probes for Redis, SMB negotiation, FTP anonymous login, and similar checks generate actual traffic. This is expected for a security assessment tool, but worth noting on monitored networks.

- **Risk scores are relative indicators, not verdicts.** A score of 49 (MEDIUM) means there are observations worth reviewing — not that the host will be compromised. Manual verification before remediation is always recommended.

- **This is not a replacement for Nmap, Nessus, or OpenVAS.** It was built for home lab visibility and to demonstrate security engineering concepts. For professional assessments, use purpose-built tools with maintained vulnerability databases.

---

## Ethical use

Only use this tool on networks you own or have explicit written permission to test.

Unauthorized network scanning may violate the Computer Fraud and Abuse Act (CFAA), the Computer Misuse Act, and equivalent laws in other jurisdictions.

- Do not scan networks you do not own or control
- Do not use this against cloud environments, production systems, or third-party services without written authorization
- If you find a real vulnerability on your own network, take reasonable steps to address it

The author is not responsible for misuse.

---

## Roadmap

- [ ] Async scanning for better performance on larger subnets
- [ ] Module split for cleaner long-term maintenance
- [ ] DHCP lease file import for MAC-to-hostname resolution without elevated privileges
- [ ] Optional Shodan integration for external IP context
- [ ] CVE lookup support for firmware version strings on embedded devices
- [ ] Web UI for interactive report browsing

---

## License

MIT — see [LICENSE](LICENSE).
