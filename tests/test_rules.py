"""
GASV Test Suite
Tests each detection rule against known-vulnerable and known-clean fixtures.
"""
import pytest
from pathlib import Path
from gasv.scanner import Scanner

VULNERABLE = Path(__file__).parent / "fixtures" / "vulnerable" / "vulnerable_workflow.yml"
CLEAN = Path(__file__).parent / "fixtures" / "clean" / "clean_workflow.yml"

scanner = Scanner()


def findings_by_rule(path, rule_id):
    return [f for f in scanner.scan_file(path) if f["rule_id"] == rule_id]


# ── GASV-PERM-001: Overpermissive permissions ──────────────────────────────────

class TestOverpermissivePermissions:
    def test_detects_write_all(self):
        findings = findings_by_rule(VULNERABLE, "GASV-PERM-001")
        assert len(findings) >= 1
        assert any("write-all" in f["message"] for f in findings)

    def test_clean_workflow_no_finding(self):
        findings = findings_by_rule(CLEAN, "GASV-PERM-001")
        assert len(findings) == 0

    def test_severity_is_high(self):
        findings = findings_by_rule(VULNERABLE, "GASV-PERM-001")
        assert all(f["severity"] == "HIGH" for f in findings)


# ── GASV-PERM-002: Missing top-level permissions ───────────────────────────────

class TestMissingPermissions:
    def test_clean_has_permissions_no_finding(self):
        findings = findings_by_rule(CLEAN, "GASV-PERM-002")
        assert len(findings) == 0

    def test_missing_permissions_detected(self, tmp_path):
        wf = tmp_path / "no_perms.yml"
        wf.write_text("name: Test\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps: []\n")
        findings = findings_by_rule(wf, "GASV-PERM-002")
        assert len(findings) == 1


# ── GASV-PIN-001: Unpinned actions ─────────────────────────────────────────────

class TestUnpinnedActions:
    def test_detects_tag_pinned_actions(self):
        findings = findings_by_rule(VULNERABLE, "GASV-PIN-001")
        assert len(findings) >= 2  # checkout@v4 and super-linter@v5

    def test_clean_sha_pinned_no_finding(self):
        findings = findings_by_rule(CLEAN, "GASV-PIN-001")
        assert len(findings) == 0

    def test_third_party_higher_severity_than_github_owned(self):
        findings = findings_by_rule(VULNERABLE, "GASV-PIN-001")
        third_party = [f for f in findings if "super-linter" in f["message"]]
        github_owned = [f for f in findings if "actions/checkout" in f["message"]]
        assert third_party[0]["severity"] == "HIGH"
        assert github_owned[0]["severity"] == "MEDIUM"


# ── GASV-INJ-001: Expression injection ────────────────────────────────────────

class TestExpressionInjection:
    def test_detects_issue_title_injection(self):
        findings = findings_by_rule(VULNERABLE, "GASV-INJ-001")
        assert len(findings) >= 1

    def test_safe_env_var_pattern_not_flagged(self):
        findings = findings_by_rule(CLEAN, "GASV-INJ-001")
        assert len(findings) == 0

    def test_severity_is_critical(self):
        findings = findings_by_rule(VULNERABLE, "GASV-INJ-001")
        assert all(f["severity"] == "CRITICAL" for f in findings)


# ── GASV-TRIG-001: Dangerous triggers ─────────────────────────────────────────

class TestDangerousTriggers:
    def test_detects_pwn_request(self):
        findings = findings_by_rule(VULNERABLE, "GASV-TRIG-001")
        assert len(findings) >= 1
        pwn = [f for f in findings if "pwn request" in f["message"].lower() or "pull_request_target" in f["message"]]
        assert len(pwn) >= 1

    def test_clean_workflow_no_trigger_finding(self):
        findings = findings_by_rule(CLEAN, "GASV-TRIG-001")
        assert len(findings) == 0

    def test_prt_with_head_checkout_is_critical(self):
        findings = findings_by_rule(VULNERABLE, "GASV-TRIG-001")
        prt_findings = [f for f in findings if "pull_request_target" in f["message"]]
        assert prt_findings[0]["severity"] == "CRITICAL"


# ── Integration: full scan ─────────────────────────────────────────────────────

class TestFullScan:
    def test_vulnerable_has_multiple_findings(self):
        findings = scanner.scan_file(VULNERABLE)
        assert len(findings) >= 5

    def test_clean_has_zero_findings(self):
        findings = scanner.scan_file(CLEAN)
        assert len(findings) == 0

    def test_all_findings_have_required_keys(self):
        findings = scanner.scan_file(VULNERABLE)
        required = {"rule_id", "severity", "file", "message", "remediation"}
        for f in findings:
            assert required.issubset(f.keys()), f"Finding missing keys: {f}"

    def test_parse_error_handled_gracefully(self, tmp_path):
        bad = tmp_path / "bad.yml"
        bad.write_text("on: [\nbadly: {{unclosed")
        findings = scanner.scan_file(bad)
        assert any("PARSE" in f["rule_id"] for f in findings)
