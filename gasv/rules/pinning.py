
import re
from typing import List, Dict, Any
from gasv.rules import BaseRule

SHA_RE = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)

GITHUB_OWNED = {"actions", "github"}


class UnpinnedActionRule(BaseRule):
    rule_id = "GASV-PIN-001"
    severity = "HIGH"
    description = "Action is not pinned to a full commit SHA, making it vulnerable to attacks."
    remediation = "Pin the action to a specific commit SHA instead of a tag — tags can be changed or deleted by the action owner."

    def check(self, workflow: Dict, filepath: str, raw: str) -> List[Dict[str, Any]]:
        findings = []
        jobs = workflow.get("jobs", {}) or {}
        for job_name, job in jobs.items():
            if not isinstance(job, dict):
                continue
            steps = job.get("steps", []) or []
            for step in steps:
                if not isinstance(step, dict):
                    continue
                uses = step.get("uses")
                if not uses or not isinstance(uses, str):
                    continue
                if uses.startswith("docker://") or uses.startswith("./"):
                    continue
                if "@" not in uses:
                    findings.append(self._finding(
                        filepath,
                        f"Job '{job_name}': action '{uses}' has no version reference at all.",
                    ))
                    continue
                action_ref, _, ref = uses.partition("@")
                if not SHA_RE.match(ref):
                    owner = action_ref.split("/")[0] if "/" in action_ref else action_ref
                    sev = "MEDIUM" if owner.lower() in GITHUB_OWNED else "HIGH"
                    findings.append(self._finding(
                        filepath,
                        f"Job '{job_name}': action '{uses}' is pinned to tag/branch '{ref}', not a commit SHA.",
                        severity=sev,
                    ))
        return findings
