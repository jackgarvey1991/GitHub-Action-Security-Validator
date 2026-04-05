"""
GASV-SEC-001: Potential hardcoded secrets in workflow files.

Secrets should always be passed via ${{ secrets.NAME }}.
Direct embedding of tokens/passwords/keys in workflow YAML exposes them
in repository history and GitHub's workflow logs.
"""
import re
from typing import List, Dict, Any
from gasv.rules import BaseRule

# Patterns that suggest hardcoded secrets rather than secret references
SECRET_PATTERNS = [
    # Common env var names that suggest a secret value is hardcoded
    (re.compile(r"(?i)(password|passwd|token|api[_-]?key|secret|private[_-]?key|access[_-]?key)\s*:\s*['\"]?[A-Za-z0-9+/=_\-]{8,}['\"]?"), "Potential hardcoded credential"),
    # AWS access key pattern
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS Access Key ID pattern"),
    # Generic high-entropy string in an env block (heuristic)
    (re.compile(r"(?i)(gh[ps]_[A-Za-z0-9]{36,})"), "GitHub Personal Access Token pattern"),
]

SECRET_REF_RE = re.compile(r"\$\{\{\s*secrets\.\w+\s*\}\}")


class HardcodedSecretRule(BaseRule):
    rule_id = "GASV-SEC-001"
    severity = "CRITICAL"
    description = "Potential hardcoded secret or credential found in workflow file."
    remediation = (
        "Store secrets in GitHub Encrypted Secrets and reference them via "
        "${{ secrets.MY_SECRET }}. Never hardcode credentials in workflow YAML. "
        "See: https://docs.github.com/en/actions/security-guides/encrypted-secrets"
    )

    def check(self, workflow: Dict, filepath: str, raw: str) -> List[Dict[str, Any]]:
        findings = []
        lines = raw.splitlines()
        for line_no, line in enumerate(lines, start=1):
            # Skip lines that are purely secret references (safe)
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            for pattern, description in SECRET_PATTERNS:
                match = pattern.search(line)
                if match:
                    # Don't flag if the value IS a ${{ secrets.X }} reference
                    if SECRET_REF_RE.search(line):
                        continue
                    # Don't flag example/placeholder strings
                    value = match.group(0)
                    if any(p in value.lower() for p in ["example", "placeholder", "your-", "changeme", "xxxxx"]):
                        continue
                    findings.append(self._finding(
                        filepath,
                        f"{description} detected on line {line_no}: '{value[:40]}...' "
                        f"— verify this is not a real credential.",
                        line=line_no,
                    ))
        return findings
