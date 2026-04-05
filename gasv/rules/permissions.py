"""
GASV-PERM-001: Overpermissive permissions (write-all or blanket write)
GASV-PERM-002: Missing top-level permissions block
"""
from typing import List, Dict, Any
from gasv.rules import BaseRule

WRITE_ALL_VALUES = {"write-all", "write"}


class OverpermissivePermissionsRule(BaseRule):
    rule_id = "GASV-PERM-001"
    severity = "HIGH"
    description = "Workflow or job grants overly broad write permissions."
    remediation = (
        "Apply the principle of least privilege. Replace 'permissions: write-all' with "
        "explicit per-scope permissions (e.g. contents: read). "
        "See: https://docs.github.com/en/actions/security-guides/automatic-token-authentication"
    )

    def check(self, workflow: Dict, filepath: str, raw: str) -> List[Dict[str, Any]]:
        findings = []

        # Top-level permissions
        top_perms = workflow.get("permissions")
        if isinstance(top_perms, str) and top_perms in WRITE_ALL_VALUES:
            findings.append(self._finding(
                filepath,
                f"Top-level 'permissions' is set to '{top_perms}', granting all scopes write access.",
            ))
        elif isinstance(top_perms, dict):
            for scope, value in top_perms.items():
                if value == "write" and scope not in ("contents",):
                    findings.append(self._finding(
                        filepath,
                        f"Top-level permission '{scope}: write' may be overly broad.",
                        severity="MEDIUM",
                    ))

        # Per-job permissions
        jobs = workflow.get("jobs", {}) or {}
        for job_name, job in jobs.items():
            if not isinstance(job, dict):
                continue
            job_perms = job.get("permissions")
            if isinstance(job_perms, str) and job_perms in WRITE_ALL_VALUES:
                findings.append(self._finding(
                    filepath,
                    f"Job '{job_name}' sets 'permissions: {job_perms}', granting all scopes write access.",
                ))
            elif isinstance(job_perms, dict):
                for scope, value in job_perms.items():
                    if value == "write" and scope in ("id-token", "packages", "deployments"):
                        findings.append(self._finding(
                            filepath,
                            f"Job '{job_name}' grants '{scope}: write' — verify this is intentional.",
                            severity="MEDIUM",
                        ))
        return findings


class MissingTopLevelPermissionsRule(BaseRule):
    rule_id = "GASV-PERM-002"
    severity = "MEDIUM"
    description = "No top-level permissions block; GITHUB_TOKEN inherits broad default permissions."
    remediation = (
        "Add 'permissions: read-all' at the top of the workflow to restrict defaults, "
        "then grant only the specific write scopes each job needs. "
        "See: https://docs.github.com/en/actions/security-guides/automatic-token-authentication"
    )

    def check(self, workflow: Dict, filepath: str, raw: str) -> List[Dict[str, Any]]:
        if workflow.get("permissions") is None:
            return [self._finding(
                filepath,
                "No top-level 'permissions' block found. GITHUB_TOKEN may have broad default permissions.",
            )]
        return []
