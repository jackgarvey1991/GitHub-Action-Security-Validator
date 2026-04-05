"""
GASV-PIN-001: Third-party actions not pinned to a full-length commit SHA.

Pinning by tag (e.g. @v3) is unsafe because tags are mutable — an attacker
who compromises the action's repo can move the tag to malicious code.
The only safe reference is a full 40-character commit SHA.
"""
import re
from typing import List, Dict, Any
from gasv.rules import BaseRule

SHA_RE = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)
# Actions maintained by GitHub/actions org are still checked, but flagged separately
GITHUB_OWNED = {"actions", "github"}


class UnpinnedActionRule(BaseRule):
    rule_id = "GASV-PIN-001"
    severity = "HIGH"
    description = "Action is not pinned to a full commit SHA, making it vulnerable to supply chain attacks."
    remediation = (
        "Pin each third-party action to a full 40-character commit SHA, e.g.:\n"
        "  uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2\n"
        "Use a tool like Dependabot or pin-github-action to manage SHA pins automatically."
    )

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
                # Docker and local actions are out of scope for this rule
                if uses.startswith("docker://") or uses.startswith("./"):
                    continue
                # Parse owner/repo@ref
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
                        f"Job '{job_name}': action '{uses}' is pinned to tag/branch '{ref}', "
                        f"not a commit SHA. Supply chain attack risk.",
                        severity=sev,
                    ))
        return findings
