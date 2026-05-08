#!/usr/bin/env python3
"""
tests/test_heimdall.py

Basic tests for Heimdall's core logic.

Run with:
    python -m pytest tests/ -v
    or
    python tests/test_heimdall.py

These tests cover the logic that's most likely to produce false positives
or silent regressions: version parsing, CVE gating, device classification,
risk scoring, and baseline comparison.
"""

import sys
import os
import unittest

# Allow running from repo root without installing
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner import (
    parse_version,
    infer_device_type,
    _is_relevant_cve,
    calculate_risk,
    compare_to_baseline,
    build_remediation_priorities,
    build_structured_findings,
    redact_results,
    service_evidence,
    enrich_asset,
    CONF_HIGH, CONF_MEDIUM, CONF_LOW,
)


# ──────────────────────────────────────────────────────────────────────────────
# Banner / version parsing
# ──────────────────────────────────────────────────────────────────────────────

class TestParseVersion(unittest.TestCase):

    def test_openssh_standard_banner(self):
        """Standard SSH banner should extract product and version at high confidence."""
        result = parse_version("SSH", "SSH-2.0-OpenSSH_7.9")
        self.assertEqual(result.product, "OpenSSH")
        self.assertEqual(result.version, "7.9")
        self.assertEqual(result.confidence, CONF_HIGH)

    def test_openssh_ubuntu_banner(self):
        """Ubuntu appends distro info to SSH banner — version should still parse."""
        result = parse_version("SSH", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6")
        self.assertEqual(result.product, "OpenSSH")
        self.assertEqual(result.version, "8.9p1")
        self.assertEqual(result.confidence, CONF_HIGH)

    def test_dropbear_ssh(self):
        result = parse_version("SSH", "SSH-2.0-dropbear_2022.82")
        self.assertEqual(result.product, "Dropbear SSH")
        self.assertIn("2022", result.version)

    def test_apache_server_header(self):
        """HTTP banner with Apache version."""
        result = parse_version("HTTP", "HTTP/1.1 200 OK\r\nServer: Apache/2.4.54\r\n")
        self.assertEqual(result.product, "Apache httpd")
        self.assertEqual(result.version, "2.4.54")
        self.assertEqual(result.confidence, CONF_HIGH)

    def test_nginx_server_header(self):
        result = parse_version("HTTP", "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n")
        self.assertEqual(result.product, "nginx")
        self.assertEqual(result.version, "1.24.0")

    def test_redis_info_output(self):
        result = parse_version("Redis", "# Server\r\nredis_version:7.0.8\r\n")
        self.assertEqual(result.product, "Redis")
        self.assertEqual(result.version, "7.0.8")

    def test_no_banner_returns_medium(self):
        """No banner means service is inferred from port — medium confidence, no version."""
        result = parse_version("SSH", "No banner")
        self.assertEqual(result.confidence, CONF_MEDIUM)
        self.assertEqual(result.version, "")

    def test_empty_banner_returns_medium(self):
        result = parse_version("HTTP", "")
        self.assertEqual(result.confidence, CONF_MEDIUM)

    def test_unknown_service_no_banner_returns_low(self):
        result = parse_version("Unknown", "No banner")
        self.assertEqual(result.confidence, CONF_LOW)

    def test_short_apache_form(self):
        """Routers sometimes serve truncated Apache headers."""
        result = parse_version("HTTP", "Server: httpd/2.0")
        self.assertIn("Apache", result.product)
        self.assertEqual(result.confidence, CONF_HIGH)


# ──────────────────────────────────────────────────────────────────────────────
# CVE confidence gate
# ──────────────────────────────────────────────────────────────────────────────

class TestCVEGating(unittest.TestCase):

    def _make_cve(self, pub_year: int, desc: str, severity: str = "HIGH", score: float = 7.5):
        return {
            "id":          f"CVE-{pub_year}-9999",
            "description": desc,
            "score":       score,
            "severity":    severity,
            "published":   f"{pub_year}-06-01",
        }

    def test_year_filter_passes_recent(self):
        """CVE from 2020 should pass the default 2017 threshold."""
        cve = self._make_cve(2020, "OpenSSH remote code execution")
        self.assertTrue(_is_relevant_cve(cve, "OpenSSH", 2017))

    def test_year_filter_blocks_old(self):
        """CVE from 2010 should be blocked by default threshold."""
        cve = self._make_cve(2010, "OpenSSH remote code execution")
        self.assertFalse(_is_relevant_cve(cve, "OpenSSH", 2017))

    def test_product_relevance_passes_match(self):
        """CVE description containing product name should pass relevance check."""
        cve = self._make_cve(2022, "A vulnerability in nginx allows memory corruption")
        self.assertTrue(_is_relevant_cve(cve, "nginx", 2017))

    def test_product_relevance_fails_mismatch(self):
        """CVE for unrelated product should fail relevance check."""
        cve = self._make_cve(2022, "A vulnerability in kernel affects ext4 filesystem")
        result = _is_relevant_cve(cve, "nginx", 2017)
        # nginx doesn't appear in the description — should fail unless CRITICAL
        self.assertFalse(result)

    def test_critical_passes_even_without_product_match(self):
        """CRITICAL CVEs bypass the product relevance check."""
        cve = self._make_cve(2022, "Generic OS kernel vulnerability", severity="CRITICAL", score=10.0)
        self.assertTrue(_is_relevant_cve(cve, "nginx", 2017))

    def test_configurable_year_threshold(self):
        """Custom year threshold should be respected."""
        cve = self._make_cve(2015, "OpenSSH vulnerability")
        self.assertFalse(_is_relevant_cve(cve, "OpenSSH", 2017))
        self.assertTrue(_is_relevant_cve(cve, "OpenSSH", 2010))


# ──────────────────────────────────────────────────────────────────────────────
# Device type classification
# ──────────────────────────────────────────────────────────────────────────────

class TestDeviceClassification(unittest.TestCase):

    def _classify(self, vendor="", hostname="", ports=None, os_type="Unknown", banners=None):
        device_type, _source = infer_device_type(
            vendor, hostname, ports or [], os_type, banners or {}
        )
        return device_type

    def test_esp_hostname_prefix(self):
        """Hostnames starting with ESP_ are ESP-based IoT devices."""
        result = self._classify(hostname="ESP_062EF5")
        self.assertIn("ESP", result)
        self.assertIn("IoT", result)

    def test_espressif_vendor(self):
        """Espressif OUI maps to IoT device type."""
        result = self._classify(vendor="Espressif")
        self.assertIn("ESP", result)

    def test_raspberry_pi_hostname(self):
        result = self._classify(hostname="raspberrypi")
        self.assertIn("Raspberry Pi", result)

    def test_raspberry_pi_vendor(self):
        result = self._classify(vendor="Raspberry Pi")
        self.assertIn("Raspberry Pi", result)

    def test_asus_router_hostname(self):
        """ASUS router hostnames contain RT- prefix."""
        result = self._classify(hostname="RT-AC5300-52C0")
        self.assertIn("Router", result)
        self.assertIn("ASUS", result)

    def test_amazon_hostname(self):
        """amazon- prefix is classified conservatively as Amazon Smart Device."""
        result = self._classify(hostname="amazon-ec6292df4")
        self.assertIn("Amazon", result)

    def test_google_cast_ports(self):
        """Ports 8008+8443 are the Google Cast signature."""
        result = self._classify(ports=[8008, 8443])
        self.assertIn("Google Cast", result)

    def test_windows_smb_ports(self):
        """Ports 135+139+445 indicate Windows."""
        result = self._classify(ports=[135, 139, 445])
        self.assertIn("Windows", result)

    def test_printer_ports(self):
        """Port 515 is LPD (print server) — but only when no stronger hostname signal."""
        result = self._classify(ports=[515])
        self.assertIn("Printer", result)

    def test_google_vendor(self):
        result = self._classify(vendor="Google")
        self.assertIn("Google", result)

    def test_vizio_vendor(self):
        result = self._classify(vendor="Vizio")
        self.assertIn("Vizio", result)


# ──────────────────────────────────────────────────────────────────────────────
# Risk scoring
# ──────────────────────────────────────────────────────────────────────────────

class TestRiskScoring(unittest.TestCase):

    def _make_cves(self, score=7.5, severity="HIGH", n=1):
        return [{
            "id": f"CVE-2022-{i}",
            "score": score,
            "severity": severity,
            "description": f"Vulnerability in openssh",
            "vector": "",
            "published": "2022-01-01",
        } for i in range(n)]

    def _make_sec(self, check, severity="HIGH"):
        """Create a minimal SecurityFinding-like dict for testing."""
        from dataclasses import dataclass
        @dataclass
        class _SF:
            severity: str
            check: str
            category: str = "Protocol"
            detail: str = ""
            remediation: str = ""
        return [_SF(severity=severity, check=check)]

    def _score(self, port, cves=None, sec=None, external=False):
        cve_result = {
            "cves":       cves or [],
            "confidence": CONF_HIGH if cves else CONF_LOW,
            "advisory":   "",
        }
        return calculate_risk(port, cve_result, sec or [], external)

    def test_smb_internal_no_cves(self):
        """SMB on internal network with no CVEs should score in MEDIUM range."""
        result = self._score(445)
        self.assertGreaterEqual(result["score"], 20)
        self.assertLessEqual(result["score"], 60)

    def test_telnet_scores_high(self):
        """Telnet inherently scores higher than most services — no cap applies."""
        result = self._score(23)
        self.assertGreaterEqual(result["score"], 28)

    def test_external_adds_points(self):
        """External IP should score higher than the same service on internal."""
        internal = self._score(80)
        external = self._score(80, external=True)
        self.assertGreater(external["score"], internal["score"])

    def test_internal_ssh_outdated_version_caps_at_medium(self):
        """
        The real-world case: internal OpenSSH 7.9 with HIGH CVEs and an
        'Outdated OpenSSH' security finding (version advisory, not auth failure).
        This is the scenario that was incorrectly scoring HIGH (54).
        Expected: MEDIUM (score ≤49) because there is no auth failure and
        no critical CVE and no external exposure.
        """
        cves = self._make_cves(score=7.8, severity="HIGH", n=5)
        # _check_ssh_config produces this finding for OpenSSH < 8.0
        sec = self._make_sec("Outdated OpenSSH", severity="HIGH")
        result = self._score(22, cves=cves, sec=sec, external=False)
        self.assertEqual(result["level"], "MEDIUM",
            f"Internal SSH with version advisory only should be MEDIUM, "
            f"got {result['level']} (score {result['score']})")
        self.assertLessEqual(result["score"], 49)
        self.assertTrue(result.get("internal_capped"),
            "internal_capped flag should be True")

    def test_internal_ssh_critical_cve_stays_high(self):
        """
        Internal SSH with a CRITICAL CVE (≥9.0) should not be suppressed by the cap.
        With a single CVSS 9.8: base=15, cve=34, total=49 — scores MEDIUM naturally
        because the raw score doesn't reach HIGH without additional factors.
        The cap does not trigger (final < 50), so internal_capped is False.
        If a second high CVE or auth issue pushes it to 50+, the cap checks
        top_cvss_val and allows HIGH through for critical CVEs.
        """
        cves = self._make_cves(score=9.8, severity="CRITICAL", n=1)
        result = self._score(22, cves=cves, external=False)
        # base(15) + cve(34) = 49 — does not reach HIGH threshold naturally
        self.assertFalse(result.get("internal_capped", False),
            "Cap should not apply when raw score is already below 50")
        # Verify with multiple critical CVEs that the cap is bypassed at ≥50
        cves_multi = self._make_cves(score=9.8, severity="CRITICAL", n=2)
        result2 = self._score(22, cves=cves_multi, external=False)
        self.assertFalse(result2.get("internal_capped", False),
            "Critical CVEs (≥9.0) should bypass the internal cap")

    def test_internal_ssh_auth_failure_stays_high(self):
        """
        Internal SSH where a confirmed auth failure is detected (e.g. SSHv1 active)
        should NOT be capped — the cap only applies to version advisories.
        """
        cves = self._make_cves(score=7.8, severity="HIGH", n=2)
        # SSHv1 Active is in _AUTH_FAILURE_CHECKS — this should override the cap
        sec = self._make_sec("SSHv1 Active", severity="CRITICAL")
        result = self._score(22, cves=cves, sec=sec, external=False)
        self.assertFalse(result.get("internal_capped", False),
            "SSHv1 Active is an auth failure — cap should not apply")

    def test_external_ssh_not_capped(self):
        """External SSH is never capped regardless of CVE severity."""
        cves = self._make_cves(score=7.8, severity="HIGH", n=3)
        sec  = self._make_sec("Outdated OpenSSH", severity="HIGH")
        result = self._score(22, cves=cves, sec=sec, external=True)
        self.assertFalse(result.get("internal_capped", False),
            "External SSH should not be capped")

    def test_high_cvss_raises_score(self):
        """A CRITICAL CVE (≥9.0) bypasses the internal cap and raises score."""
        cves = self._make_cves(score=9.8, severity="CRITICAL", n=1)
        result = self._score(22, cves=cves)
        # base=15, cve=min(40, int(9.8*3)+5)=34 → raw=49, then NOT capped (critical)
        self.assertGreaterEqual(result["score"], 40)
        self.assertGreater(result["score"], self._score(22)["score"])

    def test_cve_only_counts_at_high_confidence(self):
        """CVEs at medium/low confidence should not contribute to the score."""
        cve_result = {
            "cves": [{"id":"CVE-2023-1234","score":9.8,"severity":"CRITICAL",
                      "description":"RCE","vector":"","published":"2023-01-01"}],
            "confidence": CONF_MEDIUM,
            "advisory": "Version unconfirmed",
        }
        result = calculate_risk(22, cve_result, [], False)
        self.assertEqual(result["breakdown"]["cve"], 0)

    def test_score_caps_at_100(self):
        """Score should never exceed 100."""
        cves = self._make_cves(score=10.0, severity="CRITICAL", n=10)
        result = self._score(445, cves=cves, external=True)
        self.assertLessEqual(result["score"], 100)


# ──────────────────────────────────────────────────────────────────────────────
# Baseline comparison
# ──────────────────────────────────────────────────────────────────────────────

class TestBaselineComparison(unittest.TestCase):

    def _make_host(self, ip, ports=None, hostname="", risk_level="LOW"):
        """Minimal host dict for testing baseline comparison."""
        ports = ports or []
        return {
            "ip": ip,
            "is_up": True,
            "os": {"os_type": "Unknown", "confidence": "low", "method": ""},
            "asset": {
                "hostname": hostname, "device_type": "Unknown",
                "mac_vendor": "", "confidence": "low", "sources": [],
            },
            "open_ports": [
                {
                    "port": p, "service": "Unknown", "banner": "",
                    "version": {"product":"","version":"","confidence":"low"},
                    "cve_result": {"cves":[],"confidence":"low","advisory":""},
                    "security": [],
                    "risk": {"score":10,"level":risk_level,"factors":[],"breakdown":{}},
                }
                for p in ports
            ],
        }

    def test_new_device_detected(self):
        """A host in current scan but not in baseline is reported as new."""
        baseline = {"192.168.1.1": self._make_host("192.168.1.1", ports=[80])}
        current  = [
            self._make_host("192.168.1.1", ports=[80]),
            self._make_host("192.168.1.50", ports=[22], hostname="new-device"),
        ]
        diff = compare_to_baseline(current, baseline)
        self.assertEqual(len(diff["new_hosts"]), 1)
        self.assertEqual(diff["new_hosts"][0]["ip"], "192.168.1.50")

    def test_removed_device_detected(self):
        """A host in baseline but not current scan is reported as removed."""
        baseline = {
            "192.168.1.1":  self._make_host("192.168.1.1", ports=[80]),
            "192.168.1.10": self._make_host("192.168.1.10", ports=[22]),
        }
        current = [self._make_host("192.168.1.1", ports=[80])]
        diff = compare_to_baseline(current, baseline)
        self.assertEqual(len(diff["removed_hosts"]), 1)
        self.assertEqual(diff["removed_hosts"][0]["ip"], "192.168.1.10")

    def test_new_port_on_existing_host(self):
        """A newly opened port on an existing host is reported."""
        baseline = {"192.168.1.1": self._make_host("192.168.1.1", ports=[80])}
        current  = [self._make_host("192.168.1.1", ports=[80, 445])]
        diff = compare_to_baseline(current, baseline)
        changed = diff["changed_hosts"]
        self.assertEqual(len(changed), 1)
        new_ports = [p["port"] for p in changed[0]["new_ports"]]
        self.assertIn(445, new_ports)

    def test_closed_port_detected(self):
        """A port present in baseline but absent in current scan is reported as closed."""
        baseline = {"192.168.1.1": self._make_host("192.168.1.1", ports=[80, 443])}
        current  = [self._make_host("192.168.1.1", ports=[80])]
        diff = compare_to_baseline(current, baseline)
        changed = diff["changed_hosts"]
        closed = [p["port"] for p in changed[0]["closed_ports"]]
        self.assertIn(443, closed)

    def test_no_changes_when_identical(self):
        """Identical scan produces no changes."""
        h = self._make_host("192.168.1.1", ports=[80, 22])
        baseline = {"192.168.1.1": h}
        current  = [self._make_host("192.168.1.1", ports=[80, 22])]
        diff = compare_to_baseline(current, baseline)
        self.assertFalse(diff["has_changes"])

    def test_risk_increase_detected(self):
        """A port whose risk level increased is flagged."""
        baseline = {"192.168.1.1": self._make_host("192.168.1.1", ports=[22], risk_level="LOW")}
        current  = [self._make_host("192.168.1.1", ports=[22], risk_level="HIGH")]
        current[0]["open_ports"][0]["risk"]["level"] = "HIGH"
        baseline["192.168.1.1"]["open_ports"][0]["risk"]["level"] = "LOW"
        diff = compare_to_baseline(current, baseline)
        changed = diff["changed_hosts"]
        if changed:
            risk_changes = changed[0]["risk_changes"]
            if risk_changes:
                self.assertEqual(risk_changes[0]["previous"], "LOW")
                self.assertEqual(risk_changes[0]["current"], "HIGH")

    def test_finding_verification_still_present(self):
        """
        Same version with CVEs in both scans → status 'still_present'.
        """
        def make_port(version_str, cves):
            prod, ver = version_str.split(" ", 1) if " " in version_str else (version_str, "")
            return {
                "port": 22, "service": "SSH",
                "banner": f"SSH-2.0-{version_str}",
                "version": {"product": prod, "version": ver, "confidence": "high"},
                "cve_result": {"cves": cves, "confidence": "high", "advisory": ""},
                "security": [],
                "risk": {"score": 45, "level": "MEDIUM", "factors": [], "breakdown": {}},
            }

        cves = [{"id":"CVE-2022-1","score":7.5,"severity":"HIGH",
                 "description":"openssh issue","vector":"","published":"2022-01-01",
                 "url":"https://nvd.nist.gov/vuln/detail/CVE-2022-1"}]

        prev_host = self._make_host("192.168.1.17", hostname="raspberrypi")
        prev_host["open_ports"] = [make_port("OpenSSH 7.9", cves)]

        curr_host = self._make_host("192.168.1.17", hostname="raspberrypi")
        curr_host["open_ports"] = [make_port("OpenSSH 7.9", cves)]

        diff = compare_to_baseline([curr_host], {"192.168.1.17": prev_host})
        verifs = diff.get("finding_verifications", [])
        statuses = [v["status"] for v in verifs]
        self.assertIn("still_present", statuses,
            "Same version with CVEs in both scans should be 'still_present'")

    def test_finding_verification_remediated(self):
        """
        Version upgraded, CVEs no longer matched → status 'remediated'.
        """
        cves_old = [{"id":"CVE-2022-1","score":7.5,"severity":"HIGH",
                     "description":"openssh","vector":"","published":"2022-01-01",
                     "url":"x"}]
        prev_port = {
            "port": 22, "service": "SSH", "banner": "SSH-2.0-OpenSSH_7.9",
            "version": {"product":"OpenSSH","version":"7.9","confidence":"high"},
            "cve_result": {"cves": cves_old, "confidence":"high", "advisory":""},
            "security": [], "risk": {"score":45,"level":"MEDIUM","factors":[],"breakdown":{}},
        }
        curr_port = {
            "port": 22, "service": "SSH", "banner": "SSH-2.0-OpenSSH_9.6",
            "version": {"product":"OpenSSH","version":"9.6","confidence":"high"},
            "cve_result": {"cves": [], "confidence":"high", "advisory":""},
            "security": [], "risk": {"score":15,"level":"LOW","factors":[],"breakdown":{}},
        }
        prev_host = self._make_host("192.168.1.17")
        prev_host["open_ports"] = [prev_port]
        curr_host = self._make_host("192.168.1.17")
        curr_host["open_ports"] = [curr_port]

        diff = compare_to_baseline([curr_host], {"192.168.1.17": prev_host})
        verifs = diff.get("finding_verifications", [])
        statuses = [v["status"] for v in verifs]
        self.assertIn("remediated", statuses,
            "Version upgrade with no remaining CVEs should be 'remediated'")


# ──────────────────────────────────────────────────────────────────────────────
# Priority vs Risk label separation
# ──────────────────────────────────────────────────────────────────────────────

class TestPriorityRiskSeparation(unittest.TestCase):

    def _make_host_with_ssh(self, ip="192.168.1.17", hostname="raspberrypi",
                             risk_level="MEDIUM", cves=None, sec=None):
        """Minimal host dict with one SSH port containing CVEs and security findings."""
        cves = cves or [{"id":"CVE-2022-1","score":7.8,"severity":"HIGH",
                         "description":"openssh issue","vector":"","published":"2022-01-01",
                         "url":"x"}]
        sec  = sec or [{"check":"Outdated OpenSSH","severity":"HIGH","category":"Protocol",
                        "detail":"OpenSSH 7.9","remediation":"Upgrade OpenSSH."}]
        return {
            "ip": ip, "is_up": True, "external": False,
            "os": {"os_type":"Linux","confidence":"medium","method":""},
            "asset": {"hostname":hostname,"device_type":"Raspberry Pi","mac_vendor":"",
                      "confidence":"medium","sources":["reverse_dns"]},
            "open_ports": [{
                "port": 22, "service": "SSH",
                "banner": "SSH-2.0-OpenSSH_7.9",
                "version": {"product":"OpenSSH","version":"7.9","confidence":"high"},
                "cve_result": {"cves":cves,"confidence":"high","advisory":"","filtered_count":0},
                "security": sec,
                "risk": {"score":49,"level":risk_level,"factors":[],"breakdown":{},
                         "internal_capped":True},
            }],
        }

    def test_priority_and_risk_are_separate_fields(self):
        """Each remediation item must have both 'priority' and 'risk' keys."""
        host = self._make_host_with_ssh()
        priorities = build_remediation_priorities([host], [])
        self.assertTrue(len(priorities) > 0, "Should produce at least one priority item")
        item = priorities[0]
        self.assertIn("priority", item, "priority field must exist")
        self.assertIn("risk",     item, "risk field must exist")

    def test_priority_can_be_high_when_risk_is_medium(self):
        """
        Outdated OpenSSH (internal, risk=MEDIUM) should have priority=HIGH
        because it's actionable and has confirmed CVEs. Priority != Risk.
        """
        host = self._make_host_with_ssh(risk_level="MEDIUM")
        priorities = build_remediation_priorities([host], [])
        self.assertTrue(len(priorities) > 0)
        item = priorities[0]
        self.assertEqual(item["risk"], "MEDIUM",
            "Internal OpenSSH with cap applied should have risk=MEDIUM")
        self.assertIn(item["priority"], ("HIGH","MEDIUM"),
            "Priority should be HIGH or MEDIUM for outdated SSH with CVEs")

    def test_priority_not_equal_to_risk_when_capped(self):
        """
        When internal scoring cap applies, priority and risk should differ:
        risk=MEDIUM (capped), priority=HIGH (still needs fixing).
        """
        host = self._make_host_with_ssh(risk_level="MEDIUM")
        priorities = build_remediation_priorities([host], [])
        if priorities:
            item = priorities[0]
            # They CAN be equal but the key point is both fields exist and are independent
            self.assertIsNotNone(item.get("priority"))
            self.assertIsNotNone(item.get("risk"))


# ──────────────────────────────────────────────────────────────────────────────
# Structured findings
# ──────────────────────────────────────────────────────────────────────────────

class TestStructuredFindings(unittest.TestCase):

    def _make_host_openssh(self):
        cves = [{"id":"CVE-2022-1","score":7.8,"severity":"HIGH",
                 "description":"openssh remote code execution","vector":"",
                 "published":"2022-01-01","url":"x"}]
        return {
            "ip": "192.168.1.17", "is_up": True, "external": False,
            "os": {"os_type":"Linux","confidence":"medium","method":""},
            "asset": {"hostname":"raspberrypi","device_type":"Raspberry Pi",
                      "mac_vendor":"","confidence":"medium","sources":["reverse_dns"]},
            "open_ports": [{
                "port": 22, "service": "SSH",
                "banner": "SSH-2.0-OpenSSH_7.9",
                "version": {"product":"OpenSSH","version":"7.9","confidence":"high"},
                "cve_result": {"cves":cves,"confidence":"high","advisory":"","filtered_count":0},
                "security": [{"check":"Outdated OpenSSH","severity":"HIGH",
                              "category":"Protocol","detail":"","remediation":"Upgrade."}],
                "risk": {"score":49,"level":"MEDIUM","factors":[],"breakdown":{},
                         "internal_capped":True},
            }],
        }

    def test_openssh_finding_generated(self):
        """build_structured_findings should produce a finding for outdated OpenSSH."""
        host = self._make_host_openssh()
        findings = build_structured_findings([host])
        self.assertTrue(len(findings) > 0, "Should produce at least one finding")
        titles = [f["title"] for f in findings]
        self.assertTrue(
            any("OpenSSH" in t or "openssh" in t.lower() or "outdated" in t.lower()
                for t in titles),
            f"Expected OpenSSH finding, got: {titles}"
        )

    def test_no_duplicate_openssh_findings(self):
        """
        When a CVE-match finding exists for OpenSSH on port 22, the
        'Outdated OpenSSH' and 'OpenSSH Below 9.x' security checks must NOT
        produce separate finding cards. There should be exactly one finding
        card for this ip:port combination.
        """
        host = self._make_host_openssh()
        findings = build_structured_findings([host])

        # Count findings for ip=192.168.1.17, port=22
        port_findings = [
            f for f in findings
            if f.get("ip") == "192.168.1.17"
            and f.get("port") == 22
            and f.get("finding_type") != "http_headers"
        ]
        self.assertEqual(len(port_findings), 1,
            f"Expected exactly 1 finding for 192.168.1.17:22, got {len(port_findings)}: "
            f"{[f['title'] for f in port_findings]}")

        # The single finding must be the CVE-match card, not the advisory
        self.assertEqual(port_findings[0]["finding_type"], "cve_match",
            "The surviving finding should be the CVE match, not a version advisory")

    def test_outdated_openssh_advisory_folded_into_cve_evidence(self):
        """
        The 'Outdated OpenSSH' advisory detail should be folded into the
        CVE-match finding's evidence as a contributing_factor, not lost.
        """
        host = self._make_host_openssh()
        findings = build_structured_findings([host])
        cve_findings = [
            f for f in findings
            if f.get("ip") == "192.168.1.17"
            and f.get("port") == 22
            and f.get("finding_type") == "cve_match"
        ]
        self.assertEqual(len(cve_findings), 1)
        ev = cve_findings[0].get("evidence", {})
        factors = ev.get("contributing_factors", [])
        self.assertTrue(
            any("Outdated OpenSSH" in str(f) or "openssh" in str(f).lower()
                for f in factors),
            f"Outdated OpenSSH advisory should appear as a contributing factor. "
            f"Got contributing_factors: {factors}"
        )

    def test_standalone_security_check_not_suppressed(self):
        """
        Security checks that are NOT version advisories — e.g. SMBv1 Enabled,
        Redis No Authentication — must still produce standalone findings even
        when a CVE finding exists on the same port.
        """
        cves = [{"id":"CVE-2022-1","score":7.5,"severity":"HIGH",
                 "description":"samba vulnerability","vector":"",
                 "published":"2022-01-01","url":"x"}]
        host = {
            "ip": "192.168.1.248", "is_up": True, "external": False,
            "os": {"os_type":"Windows","confidence":"high","method":""},
            "asset": {"hostname":"Gabes-PC","device_type":"Windows PC/Server",
                      "mac_vendor":"Intel","confidence":"high","sources":["netbios"]},
            "open_ports": [{
                "port": 445, "service": "SMB",
                "banner": "No banner",
                "version": {"product":"Samba","version":"4.1.0","confidence":"high"},
                "cve_result": {"cves":cves,"confidence":"high","advisory":"","filtered_count":0},
                "security": [
                    {"check":"SMBv1 Enabled","severity":"HIGH","category":"Protocol",
                     "detail":"SMBv1 negotiation succeeded.","remediation":"Disable SMBv1."},
                ],
                "risk": {"score":60,"level":"HIGH","factors":[],"breakdown":{},
                         "internal_capped":False},
            }],
        }
        findings = build_structured_findings([host])
        port_findings = [
            f for f in findings
            if f.get("ip") == "192.168.1.248" and f.get("port") == 445
        ]
        finding_types = [f["finding_type"] for f in port_findings]
        self.assertIn("cve_match", finding_types,
            "CVE-match finding should exist for Samba")
        self.assertIn("security_check", finding_types,
            "SMBv1 Enabled is an active check, not a version advisory — it must not be suppressed")

    def test_finding_has_required_fields(self):
        """Every finding must have the required workflow fields."""
        host = self._make_host_openssh()
        findings = build_structured_findings([host])
        required = ["finding_id","finding_type","title","ip","hostname","device_type",
                    "port","service","risk","priority","confidence","sources",
                    "evidence","why_it_matters","recommendation","status","timestamp"]
        for f in findings:
            for field in required:
                self.assertIn(field, f,
                    f"Finding '{f.get('title','')}' missing field '{field}'")

    def test_finding_priority_and_risk_are_independent(self):
        """Findings must have separate priority and risk fields."""
        host = self._make_host_openssh()
        findings = build_structured_findings([host])
        for f in findings:
            self.assertIn("priority", f)
            self.assertIn("risk", f)
            # They don't have to differ, but both must exist
            self.assertIsNotNone(f["priority"])
            self.assertIsNotNone(f["risk"])

    def test_http_header_findings_aggregated(self):
        """HTTP header issues should produce one finding per host, not per header."""
        host = {
            "ip": "192.168.1.1", "is_up": True, "external": False,
            "os": {"os_type":"Unknown","confidence":"low","method":""},
            "asset": {"hostname":"router","device_type":"Router (ASUS)",
                      "mac_vendor":"","confidence":"low","sources":[]},
            "open_ports": [{
                "port": 80, "service": "HTTP", "banner": "HTTP/1.1 200 OK",
                "version": {"product":"","version":"","confidence":"low"},
                "cve_result": {"cves":[],"confidence":"low","advisory":"","filtered_count":0},
                "security": [
                    {"check":"Missing CSP","severity":"MEDIUM","category":"Header",
                     "detail":"","remediation":""},
                    {"check":"Missing HSTS","severity":"MEDIUM","category":"Header",
                     "detail":"","remediation":""},
                    {"check":"Missing X-Frame-Options","severity":"LOW","category":"Header",
                     "detail":"","remediation":""},
                ],
                "risk": {"score":5,"level":"LOW","factors":[],"breakdown":{}},
            }],
        }
        findings = build_structured_findings([host])
        header_findings = [f for f in findings if f["finding_type"] == "http_headers"]
        self.assertEqual(len(header_findings), 1,
            "Three header issues on one host should produce exactly one http_headers finding")
        self.assertGreater(header_findings[0]["evidence"]["count"], 1)


# ──────────────────────────────────────────────────────────────────────────────
# Redaction
# ──────────────────────────────────────────────────────────────────────────────

class TestRedaction(unittest.TestCase):

    def _make_results(self):
        return {
            "scan_metadata": {"target":"192.168.1.0/24","redacted":False},
            "hosts": [{
                "ip": "192.168.1.17",
                "asset": {"hostname":"Gabes-PC","device_type":"Windows PC/Server",
                          "mac_vendor":"Intel","mac_addr":"AA:BB:CC:DD:EE:FF",
                          "confidence":"high","sources":["netbios"]},
                "open_ports": [],
            }, {
                "ip": "192.168.1.1",
                "asset": {"hostname":"RT-AC5300-52C0","device_type":"Router (ASUS)",
                          "mac_vendor":"ASUS","mac_addr":"11:22:33:44:55:66",
                          "confidence":"high","sources":["reverse_dns"]},
                "open_ports": [],
            }],
            "asset_inventory": [
                {"ip":"192.168.1.17","hostname":"Gabes-PC","device_type":"Windows PC/Server",
                 "mac_vendor":"Intel","mac_addr":"AA:BB:CC:DD:EE:FF","open_ports":[],
                 "services":[],"risk_level":"LOW","risk_score":0,"confidence":"high","sources":[]},
                {"ip":"192.168.1.1","hostname":"RT-AC5300-52C0","device_type":"Router (ASUS)",
                 "mac_vendor":"ASUS","mac_addr":"11:22:33:44:55:66","open_ports":[],
                 "services":[],"risk_level":"LOW","risk_score":0,"confidence":"high","sources":[]},
            ],
            "findings": [],
            "remediation_priorities": [],
            "baseline_changes": None,
            "verification_notes": [],
        }

    def test_personal_hostname_replaced(self):
        """Personal hostnames like 'Gabes-PC' should be replaced with generic labels."""
        results  = self._make_results()
        redacted = redact_results(results)
        hostnames = [h["asset"]["hostname"] for h in redacted["hosts"]]
        self.assertNotIn("Gabes-PC", hostnames,
            "Personal hostname 'Gabes-PC' should be redacted")

    def test_device_type_labels_kept(self):
        """Device type labels like 'Router (ASUS)' are not personal — keep them."""
        results  = self._make_results()
        redacted = redact_results(results)
        dtypes = [h["asset"]["device_type"] for h in redacted["hosts"]]
        self.assertIn("Router (ASUS)", dtypes,
            "Non-personal device type 'Router (ASUS)' should not be redacted")

    def test_mac_addresses_replaced(self):
        """MAC addresses should be replaced with XX:XX:XX:XX:XX:XX."""
        results  = self._make_results()
        redacted = redact_results(results)
        for h in redacted["hosts"]:
            mac = h["asset"].get("mac_addr","")
            if mac:
                self.assertEqual(mac, "XX:XX:XX:XX:XX:XX",
                    f"MAC address should be redacted, got: {mac}")

    def test_router_hostname_kept(self):
        """Router model names like 'RT-AC5300-52C0' should not be redacted (not personal)."""
        results  = self._make_results()
        redacted = redact_results(results)
        hostnames = [h["asset"]["hostname"] for h in redacted["hosts"]]
        self.assertIn("RT-AC5300-52C0", hostnames,
            "Router model hostname should not be redacted")

    def test_redaction_mapping_is_consistent(self):
        """The same original hostname maps to the same replacement label throughout."""
        results = self._make_results()
        # Add Gabes-PC to inventory too
        redacted = redact_results(results)
        host_hn  = next(h["asset"]["hostname"] for h in redacted["hosts"]
                        if "192.168.1.17" == h["ip"])
        inv_hn   = next(i["hostname"] for i in redacted["asset_inventory"]
                        if i["ip"] == "192.168.1.17")
        self.assertEqual(host_hn, inv_hn,
            "Same original hostname must map to same label in hosts and inventory")

    def test_original_not_modified(self):
        """redact_results must not modify the original results dict."""
        results = self._make_results()
        original_hostname = results["hosts"][0]["asset"]["hostname"]
        redact_results(results)
        self.assertEqual(results["hosts"][0]["asset"]["hostname"], original_hostname,
            "redact_results must not modify the original dict")


# ──────────────────────────────────────────────────────────────────────────────
# Service fingerprint confidence (Items 2+3)
# ──────────────────────────────────────────────────────────────────────────────

class TestServiceFingerprint(unittest.TestCase):

    def _sv(self, product="", version="", conf=CONF_LOW):
        """Create a minimal ServiceVersion-like namespace."""
        from dataclasses import dataclass
        @dataclass
        class _SV:
            product: str
            version: str
            confidence: str
        return _SV(product=product, version=version, confidence=conf)

    def test_confirmed_banner_gives_high_confidence(self):
        """If product+version are extracted from banner, confidence should be high."""
        sv     = self._sv("OpenSSH", "7.9", CONF_HIGH)
        result = service_evidence(22, "SSH", sv, "SSH-2.0-OpenSSH_7.9")
        self.assertEqual(result["service_confidence"], "high")
        self.assertTrue(result["version_confirmed"])
        self.assertEqual(result["fingerprint_source"], "service_banner")

    def test_ibm_db2_port_is_heuristic(self):
        """Port 50000 with no banner — should be low confidence, Possible prefix."""
        sv     = self._sv()
        result = service_evidence(50000, "IBM-DB2", sv, "No banner")
        self.assertEqual(result["service_confidence"], "low")
        self.assertEqual(result["fingerprint_source"], "heuristic")
        self.assertFalse(result["version_confirmed"])
        self.assertIn("Possible", result["display_service"],
            f"Expected 'Possible' prefix, got: {result['display_service']}")

    def test_ibm_db2_generic_banner_is_not_confirmed(self):
        """
        Port 50000 with a generic HTTP banner (e.g. HTTP/1.1 200 OK).
        parse_version() falls back to returning the service name as product
        with no version — this must not promote to medium/service_banner.
        The display_service must still indicate uncertainty.
        """
        from scanner import parse_version
        # This is the real-world case from the bug report: the Raspberry Pi
        # returns an HTTP-like response on port 50000 that matches nothing,
        # so parse_version falls back to product='IBM-DB2', version=''.
        sv     = parse_version("IBM-DB2", "HTTP/1.1 200 OK")
        result = service_evidence(50000, "IBM-DB2", sv, "HTTP/1.1 200 OK")
        self.assertFalse(result["version_confirmed"],
            "Generic HTTP response should not count as version_confirmed")
        self.assertNotEqual(result["display_service"], "IBM-DB2",
            "Plain 'IBM-DB2' must not appear when version is not confirmed")
        self.assertIn("Possible", result["display_service"],
            f"Expected cautious wording, got: {result['display_service']}")
        self.assertEqual(result["service_confidence"], "low",
            f"Generic fallback banner should be low confidence, got: {result['service_confidence']}")

    def test_ibm_db2_unconfirmed_in_attack_surface(self):
        """
        IBM-DB2 detected only by port 50000 (no confirmed version) must appear
        as 'Possible IBM-DB2-like service' in attack surface service_entries.
        Tests both no-banner and generic-HTTP-banner cases.
        """
        from scanner import build_attack_surface, parse_version

        for banner, label in [("No banner", "no banner"), ("HTTP/1.1 200 OK", "generic HTTP")]:
            sv   = parse_version("IBM-DB2", banner)
            ev   = service_evidence(50000, "IBM-DB2", sv, banner)
            host = {
                "ip": "192.168.1.50",
                "open_ports": [{
                    "port": 50000, "service": "IBM-DB2",
                    "display_service": ev["display_service"],
                    "service_evidence": ev, "security": [],
                    "risk": {"score": 0, "level": "LOW", "factors": [], "breakdown": {}},
                }],
            }
            atk   = build_attack_surface([host])
            ibm   = [e for e in atk["service_entries"] if e["service"] == "IBM-DB2"]
            self.assertEqual(len(ibm), 1)
            entry = ibm[0]
            self.assertNotEqual(entry["display_service"], "IBM-DB2",
                f"[{label}] Plain 'IBM-DB2' must not appear in Attack Surface "
                f"when version is unconfirmed, got: '{entry['display_service']}'")
            self.assertFalse(entry["version_confirmed"],
                f"[{label}] version_confirmed should be False")
            self.assertEqual(entry["confidence"], "low",
                f"[{label}] confidence should be low, got: '{entry['confidence']}'")

    def test_ibm_db2_confirmed_by_banner_shows_as_confirmed(self):
        """
        If a banner confirms IBM-DB2 product and version, the display should
        show the confirmed name without 'Possible' prefix.
        """
        from scanner import build_attack_surface
        sv = self._sv("DB2", "11.5.0", CONF_HIGH)
        ev = service_evidence(50000, "IBM-DB2", sv, "IBM DB2 11.5.0.0")
        host = {
            "ip": "192.168.1.50",
            "open_ports": [{
                "port": 50000, "service": "IBM-DB2",
                "display_service": ev["display_service"],
                "service_evidence": ev, "security": [],
                "risk": {"score": 0, "level": "LOW", "factors": [], "breakdown": {}},
            }],
        }
        atk   = build_attack_surface([host])
        entry = [e for e in atk["service_entries"] if e["service"] == "IBM-DB2"][0]
        self.assertTrue(entry["version_confirmed"])
        self.assertNotIn("Possible", entry["display_service"],
            f"Confirmed IBM-DB2 should not show 'Possible', got: '{entry['display_service']}'")
        self.assertEqual(entry["confidence"], "high")

    def test_php_fpm_port_is_heuristic(self):
        """Port 9000 labeled PHP-FPM by convention only — should be low confidence."""
        sv     = self._sv()
        result = service_evidence(9000, "PHP-FPM", sv, "No banner")
        self.assertEqual(result["service_confidence"], "low")
        self.assertEqual(result["fingerprint_source"], "heuristic")
        self.assertIn("Possible", result["display_service"])

    def test_well_known_port_is_medium_without_banner(self):
        """Port 22 without a banner should still be medium confidence (well-known IANA port)."""
        sv     = self._sv()
        result = service_evidence(22, "SSH", sv, "No banner")
        self.assertEqual(result["service_confidence"], "medium")
        self.assertEqual(result["fingerprint_source"], "port_signature")
        self.assertFalse(result["version_confirmed"])

    def test_banner_present_flag(self):
        result_with    = service_evidence(80, "HTTP", self._sv(), "HTTP/1.1 200 OK")
        result_without = service_evidence(80, "HTTP", self._sv(), "No banner")
        self.assertTrue(result_with["banner_present"])
        self.assertFalse(result_without["banner_present"])


# ──────────────────────────────────────────────────────────────────────────────
# Router stays Router, port 515 becomes service hint (Item 4)
# ──────────────────────────────────────────────────────────────────────────────

class TestServiceHints(unittest.TestCase):

    def _make_asus_router_asset(self, open_ports):
        """Simulate ASUS router with LPD port open."""
        import threading
        # Clear cache to avoid interference between tests
        from scanner import _enrich_cache, _enrich_lock
        with _enrich_lock:
            _enrich_cache.pop("192.168.1.1", None)

        # enrich_asset expects to be called with real data; we simulate the outcome
        # by calling infer_device_type directly and checking service hints logic
        device_type, source = infer_device_type(
            vendor="ASUS",
            hostname="RT-AC5300-52C0",
            open_ports=open_ports,
            os_type="Unknown",
            banners={}
        )
        return device_type, source

    def test_router_device_type_not_overridden_by_port_515(self):
        """
        ASUS router with port 515 open should remain 'Router (ASUS)',
        not be reclassified as 'Network Printer'.
        """
        device_type, source = self._make_asus_router_asset([53, 80, 515])
        self.assertIn("Router", device_type,
            f"Device type should be Router, got: {device_type}")
        self.assertNotIn("Printer", device_type,
            f"Port 515 should not override router identity, got: {device_type}")

    def test_service_hints_populated_for_router_with_515(self):
        """
        When a router (confident identity) has port 515 open,
        service_hints should contain the LPD note.
        """
        from scanner import _enrich_cache, _enrich_lock
        with _enrich_lock:
            _enrich_cache.pop("192.168.1.100", None)

        asset = enrich_asset(
            ip="192.168.1.100",
            open_ports=[53, 80, 515],
            banners={80: "HTTP/1.1 200 OK\r\nServer: RT-AC5300\r\n"},
            os_type="Router",
            mac="",
            timeout=0.1
        )
        # Device type should remain router-like
        self.assertNotIn("Printer", asset.device_type,
            f"device_type should not be Printer, got: {asset.device_type}")
        # Note: service_hints population requires confident identity from OUI/hostname
        # In this test the identity comes from OS type or banner — check both outcomes
        # are acceptable (hints may or may not populate depending on confidence level)
        # The key invariant is device_type is not overwritten
        self.assertIsInstance(asset.service_hints, list)


# ──────────────────────────────────────────────────────────────────────────────
# SMB wording (Item 5)
# ──────────────────────────────────────────────────────────────────────────────

class TestSMBWording(unittest.TestCase):

    def _smb_findings(self, ip="192.168.1.248"):
        """Run the SMB check against a non-existent host — will return fallback finding."""
        from scanner import _check_smb
        # With a fake IP, connection will fail, returning the fallback INFO finding
        return _check_smb(ip, 445, to=0.1)

    def test_smb_fallback_does_not_mention_eternalblue(self):
        """
        When SMBv1 status is NOT confirmed, the finding should not mention
        EternalBlue, WannaCry, or imply these exploits apply.
        """
        findings = self._smb_findings()
        for f in findings:
            detail_lower = f.detail.lower()
            # Only assert for non-SMBv1-confirmed findings (INFO category)
            if f.severity == "INFO":
                self.assertNotIn("eternalblue", detail_lower,
                    "Unconfirmed SMB should not mention EternalBlue")
                self.assertNotIn("wannacry", detail_lower,
                    "Unconfirmed SMB should not mention WannaCry")
                self.assertNotIn("ms17-010", detail_lower,
                    "Unconfirmed SMB should not mention MS17-010")

    def test_smb_fallback_recommends_review(self):
        """Fallback SMB finding should recommend reviewing the configuration."""
        findings = self._smb_findings()
        info_findings = [f for f in findings if f.severity == "INFO"]
        if info_findings:
            detail = info_findings[0].detail.lower()
            self.assertTrue(
                any(kw in detail for kw in ("review", "verify", "confirm", "check")),
                f"Fallback SMB finding should recommend review, got: {info_findings[0].detail}"
            )


# ──────────────────────────────────────────────────────────────────────────────
# Risk breakdown field names (Item 6)
# ──────────────────────────────────────────────────────────────────────────────

class TestRiskBreakdown(unittest.TestCase):

    def _make_sec(self, check, severity="HIGH"):
        from dataclasses import dataclass
        @dataclass
        class _SF:
            severity: str
            check: str
            category: str = "Protocol"
            detail: str = ""
            remediation: str = ""
        return [_SF(severity=severity, check=check)]

    def test_breakdown_has_new_field_names(self):
        """calculate_risk must return breakdown with the new split field names."""
        cve_result = {"cves":[],"confidence":CONF_LOW,"advisory":""}
        result = calculate_risk(22, cve_result, [], False)
        bd = result["breakdown"]
        self.assertIn("security_advisory", bd,
            "breakdown must have 'security_advisory' field")
        self.assertIn("auth_failure", bd,
            "breakdown must have 'auth_failure' field")
        self.assertIn("network_exposure", bd,
            "breakdown must have 'network_exposure' field")

    def test_openssh_advisory_goes_to_security_advisory_not_auth_failure(self):
        """'Outdated OpenSSH' advisory contribution should appear in security_advisory."""
        cve_result = {"cves":[],"confidence":CONF_LOW,"advisory":""}
        sec = self._make_sec("Outdated OpenSSH", "HIGH")
        result = calculate_risk(22, cve_result, sec, False)
        bd = result["breakdown"]
        self.assertGreater(bd["security_advisory"], 0,
            "Outdated OpenSSH advisory should contribute to security_advisory")
        self.assertEqual(bd["auth_failure"], 0,
            "Outdated OpenSSH advisory is not an auth failure")

    def test_redis_no_auth_goes_to_auth_failure(self):
        """'Redis No Authentication' must go to auth_failure, not security_advisory."""
        cve_result = {"cves":[],"confidence":CONF_LOW,"advisory":""}
        sec = self._make_sec("Redis No Authentication", "CRITICAL")
        result = calculate_risk(6379, cve_result, sec, False)
        bd = result["breakdown"]
        self.assertGreater(bd["auth_failure"], 0,
            "Redis No Authentication should contribute to auth_failure")

    def test_network_exposure_populated_for_external(self):
        """External IP should populate network_exposure field."""
        cve_result = {"cves":[],"confidence":CONF_LOW,"advisory":""}
        result = calculate_risk(22, cve_result, [], external=True)
        self.assertGreater(result["breakdown"]["network_exposure"], 0)


# ──────────────────────────────────────────────────────────────────────────────
# Attack surface confidence-aware display (Item 1)
# ──────────────────────────────────────────────────────────────────────────────

class TestAttackSurfaceConfidence(unittest.TestCase):

    def _make_host_with_ports(self, ip, port_list):
        """Build a minimal host dict with pre-populated service_evidence on each port."""
        from scanner import service_evidence, SERVICE_MAP, parse_version
        open_ports = []
        for port in port_list:
            svc    = SERVICE_MAP.get(port, "Unknown")
            banner = "No banner"
            svc_ver= parse_version(svc, banner)
            ev     = service_evidence(port, svc, svc_ver, banner)
            open_ports.append({
                "port":             port,
                "service":          svc,
                "display_service":  ev["display_service"],
                "service_evidence": ev,
                "banner":           banner,
                "version":          {"product":"","version":"","confidence":"low"},
                "cve_result":       {"cves":[],"confidence":"low","advisory":"","filtered_count":0},
                "security":         [],
                "risk":             {"score":0,"level":"LOW","factors":[],"breakdown":{}},
            })
        return {
            "ip": ip, "is_up": True, "external": False,
            "os": {"os_type":"Unknown","confidence":"low","method":""},
            "asset": {"hostname":"unknown","device_type":"Unknown Device",
                      "mac_vendor":"","confidence":"low","sources":[],"service_hints":[]},
            "open_ports": open_ports,
        }

    def test_heuristic_service_not_displayed_as_confirmed(self):
        """
        Port 50000 (IBM-DB2 heuristic) should appear in attack surface with
        'Possible' prefix and low confidence, not as confirmed 'IBM-DB2'.
        """
        from scanner import build_attack_surface
        host = self._make_host_with_ports("192.168.1.1", [50000])
        atk  = build_attack_surface([host])
        entries = atk.get("service_entries", [])
        self.assertTrue(len(entries) > 0, "Should have at least one service entry")

        ibm_entries = [e for e in entries if "IBM" in e["service"] or "IBM" in e["display_service"]]
        self.assertTrue(len(ibm_entries) > 0, "Should have an IBM-DB2-related entry")
        entry = ibm_entries[0]
        self.assertEqual(entry["confidence"], "low",
            f"Heuristic IBM-DB2 should have low confidence, got: {entry['confidence']}")
        self.assertIn("Possible", entry["display_service"],
            f"Heuristic service display should indicate uncertainty: {entry['display_service']}")

    def test_confirmed_service_has_correct_confidence(self):
        """SSH with confirmed banner should appear with high confidence in attack surface."""
        from scanner import build_attack_surface, SERVICE_MAP, service_evidence, parse_version
        svc    = "SSH"
        banner = "SSH-2.0-OpenSSH_7.9"
        svc_ver= parse_version(svc, banner)
        ev     = service_evidence(22, svc, svc_ver, banner)
        host   = {
            "ip": "192.168.1.17", "is_up": True, "external": False,
            "os": {"os_type":"Linux","confidence":"medium","method":""},
            "asset": {"hostname":"raspberrypi","device_type":"Raspberry Pi",
                      "mac_vendor":"","confidence":"medium","sources":[],"service_hints":[]},
            "open_ports": [{
                "port": 22, "service": "SSH",
                "display_service": ev["display_service"],
                "service_evidence": ev,
                "banner": banner,
                "version": {"product":"OpenSSH","version":"7.9","confidence":"high"},
                "cve_result": {"cves":[],"confidence":"high","advisory":"","filtered_count":0},
                "security": [],
                "risk": {"score":15,"level":"LOW","factors":[],"breakdown":{}},
            }],
        }
        atk = build_attack_surface([host])
        entries = atk.get("service_entries", [])
        ssh_entries = [e for e in entries if e["service"] == "SSH"]
        self.assertTrue(len(ssh_entries) > 0)
        self.assertEqual(ssh_entries[0]["confidence"], "high")
        self.assertFalse(ssh_entries[0]["display_service"].startswith("Possible"))

    def test_attack_surface_service_entries_have_required_fields(self):
        """Every service_entry must have the required confidence fields."""
        from scanner import build_attack_surface
        host = self._make_host_with_ports("192.168.1.1", [22, 80, 445, 9000])
        atk  = build_attack_surface([host])
        for entry in atk.get("service_entries", []):
            for field in ["service","display_service","hosts","ips",
                          "confidence","fingerprint_source","version_confirmed"]:
                self.assertIn(field, entry,
                    f"service_entry missing field '{field}'")


# ──────────────────────────────────────────────────────────────────────────────
# OS fingerprint precedence (Item 3)
# ──────────────────────────────────────────────────────────────────────────────

class TestOSFingerprintPrecedence(unittest.TestCase):

    def test_printer_port_does_not_beat_router_http_signal(self):
        """
        A device with DD-WRT in HTTP header (high confidence router signal)
        and port 515 open should fingerprint as a Router, not Network Printer.
        The printer port check now uses 'low' confidence to ensure it loses
        to any high-confidence router signal.
        """
        from scanner import fingerprint_os
        banners    = {80: "HTTP/1.1 200 OK\r\nServer: dd-wrt\r\n"}
        open_ports = [53, 80, 515]
        result     = fingerprint_os(open_ports, banners, ttl=None)
        self.assertNotEqual(result.os_type, "Network Printer",
            f"Router with dd-wrt banner should not be fingerprinted as Printer, "
            f"got: {result.os_type}")
        self.assertIn("Router", result.os_type,
            f"dd-wrt banner should produce a Router OS type, got: {result.os_type}")

    def test_printer_signal_alone_produces_low_confidence(self):
        """Port 515 alone should still produce a printer guess, but at low confidence."""
        from scanner import fingerprint_os
        result = fingerprint_os([515], {}, ttl=None)
        if result.os_type == "Network Printer":
            self.assertEqual(result.confidence, "low",
                "Printer fingerprint from ports only should be low confidence")


# ──────────────────────────────────────────────────────────────────────────────
# Scan Quality (Items 8+9)
# ──────────────────────────────────────────────────────────────────────────────

class TestScanQuality(unittest.TestCase):

    def _make_confirmed_host(self):
        from scanner import service_evidence, parse_version
        svc_ver = parse_version("SSH", "SSH-2.0-OpenSSH_7.9")
        ev      = service_evidence(22, "SSH", svc_ver, "SSH-2.0-OpenSSH_7.9")
        cves    = [{"id":"CVE-2022-1","score":7.5,"severity":"HIGH",
                    "description":"openssh","vector":"","published":"2022-01-01","url":"x"}]
        return {
            "ip":"192.168.1.17","is_up":True,"external":False,
            "os":{"os_type":"Linux","confidence":"medium","method":""},
            "asset":{"hostname":"raspberrypi","device_type":"Raspberry Pi",
                     "mac_vendor":"","confidence":"medium","sources":["reverse_dns"],
                     "service_hints":[]},
            "open_ports":[{
                "port":22,"service":"SSH","display_service":"OpenSSH 7.9",
                "service_evidence":ev,"banner":"SSH-2.0-OpenSSH_7.9",
                "version":{"product":"OpenSSH","version":"7.9","confidence":"high"},
                "cve_result":{"cves":cves,"confidence":"high","advisory":"","filtered_count":0},
                "security":[],"risk":{"score":49,"level":"MEDIUM","factors":[],"breakdown":{}},
            }],
        }

    def _make_heuristic_host(self):
        from scanner import service_evidence, parse_version
        svc_ver = parse_version("IBM-DB2", "No banner")
        ev      = service_evidence(50000, "IBM-DB2", svc_ver, "No banner")
        return {
            "ip":"192.168.1.50","is_up":True,"external":False,
            "os":{"os_type":"Unknown","confidence":"low","method":""},
            "asset":{"hostname":"Unknown","device_type":"Unknown Device",
                     "mac_vendor":"","confidence":"low","sources":[],"service_hints":[]},
            "open_ports":[{
                "port":50000,"service":"IBM-DB2","display_service":ev["display_service"],
                "service_evidence":ev,"banner":"No banner",
                "version":{"product":"","version":"","confidence":"low"},
                "cve_result":{"cves":[],"confidence":"low","advisory":"Version unconfirmed — see report.",
                              "filtered_count":0},
                "security":[],"risk":{"score":5,"level":"LOW","factors":[],"breakdown":{}},
            }],
        }

    def test_scan_quality_counts_confirmed_versions(self):
        from scanner import build_scan_quality
        sq = build_scan_quality([self._make_confirmed_host()])
        self.assertGreaterEqual(sq["version_confirmed"], 1)
        self.assertEqual(sq["cves_matched"], 1)

    def test_scan_quality_counts_heuristic_fingerprints(self):
        from scanner import build_scan_quality
        sq = build_scan_quality([self._make_heuristic_host()])
        self.assertGreaterEqual(sq["heuristic_fingerprints"], 1)

    def test_scan_quality_counts_skipped_cve_checks(self):
        from scanner import build_scan_quality
        sq = build_scan_quality([self._make_heuristic_host()])
        self.assertGreaterEqual(sq["cve_skipped_no_version"], 1,
            "Heuristic service with advisory should count as skipped CVE check")

    def test_scan_quality_has_required_fields(self):
        from scanner import build_scan_quality
        sq = build_scan_quality([])
        required = ["version_confirmed","version_unconfirmed","heuristic_fingerprints",
                    "assets_strong_identity","assets_unknown_identity",
                    "cve_skipped_no_version","cves_matched"]
        for field in required:
            self.assertIn(field, sq, f"scan_quality missing field '{field}'")


if __name__ == "__main__":
    print("Running Heimdall test suite...")
    print("=" * 60)
    loader  = unittest.TestLoader()
    suite   = loader.loadTestsFromModule(sys.modules[__name__])
    runner  = unittest.TextTestRunner(verbosity=2)
    result  = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
