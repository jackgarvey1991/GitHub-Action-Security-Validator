"""
Scanner: loads a workflow YAML file, parses it, and runs all rules.
"""
from pathlib import Path
from typing import List, Dict, Any

import yaml

from gasv.rules.permissions import OverpermissivePermissionsRule, MissingTopLevelPermissionsRule
from gasv.rules.pinning import UnpinnedActionRule
from gasv.rules.injection import ExpressionInjectionRule
from gasv.rules.secrets import HardcodedSecretRule
from gasv.rules.triggers import DangerousTriggerRule

RULES = [
    OverpermissivePermissionsRule(),
    MissingTopLevelPermissionsRule(),
    UnpinnedActionRule(),
    ExpressionInjectionRule(),
    HardcodedSecretRule(),
    DangerousTriggerRule(),
]


class Scanner:
    """Orchestrates YAML parsing and rule execution for a single workflow file."""

    def scan_file(self, path: Path) -> List[Dict[str, Any]]:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                raw = fh.read()
            workflow = yaml.safe_load(raw)
        except yaml.YAMLError as exc:
            return [{
                "rule_id": "GASV-PARSE-ERROR",
                "severity": "HIGH",
                "file": str(path),
                "line": 1,
                "message": f"YAML parse error: {exc}",
                "remediation": "Ensure the workflow file is valid YAML.",
            }]
        except Exception as exc:
            return [{
                "rule_id": "GASV-READ-ERROR",
                "severity": "HIGH",
                "file": str(path),
                "line": 1,
                "message": f"Could not read file: {exc}",
                "remediation": "Check file permissions and encoding.",
            }]

        if not isinstance(workflow, dict):
            return []

        findings = []
        for rule in RULES:
            try:
                rule_findings = rule.check(workflow, str(path), raw)
                findings.extend(rule_findings)
            except Exception as exc:
                findings.append({
                    "rule_id": f"{rule.rule_id}-ERROR",
                    "severity": "INFO",
                    "file": str(path),
                    "line": 1,
                    "message": f"Rule execution error: {exc}",
                    "remediation": "Report this as a GASV bug.",
                })
        return findings
