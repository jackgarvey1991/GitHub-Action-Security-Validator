"""Base class for all GASV detection rules."""
from abc import ABC, abstractmethod
from typing import List, Dict, Any


class BaseRule(ABC):
    rule_id: str = "GASV-BASE"
    severity: str = "MEDIUM"
    description: str = ""
    remediation: str = ""

    @abstractmethod
    def check(self, workflow: Dict, filepath: str, raw: str) -> List[Dict[str, Any]]:
        """
        Inspect the parsed workflow dict (and optionally raw YAML text) for findings.

        Returns a list of finding dicts with keys:
          rule_id, severity, file, line, message, remediation
        """

    def _finding(self, filepath: str, message: str, line: int = 1, severity: str = None) -> Dict:
        return {
            "rule_id": self.rule_id,
            "severity": severity or self.severity,
            "file": filepath,
            "location": f"line {line}",
            "line": line,
            "message": message,
            "remediation": self.remediation,
        }
