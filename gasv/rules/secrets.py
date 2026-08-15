import re
from typing import List, Dict, Any
from gasv.rules import BaseRule

SECRET_PATTERNS = [
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
    remediation = "Move the value to a GitHub secret and reference it with ${{ secrets.NAME }} instead of hardcoding it in the workflow."

    def check(self, workflow: Dict, filepath: str, raw: str) -> List[Dict[str, Any]]:
        findings = []
        lines = raw.splitlines()
        for line_no, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            for pattern, description in SECRET_PATTERNS:
                match = pattern.search(line)
                if match:
                    if SECRET_REF_RE.search(line):
                        continue
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
