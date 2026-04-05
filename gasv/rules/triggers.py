"""
GASV-TRIG-001: Dangerous workflow triggers that elevate risk.

pull_request_target runs with write permissions in the context of the BASE
repository, even for PRs from forks. If combined with a checkout of the
PR head ref, this creates a critical pwn-request vulnerability.

workflow_run triggered from untrusted events inherits elevated context.
"""
from typing import List, Dict, Any
from gasv.rules import BaseRule


class DangerousTriggerRule(BaseRule):
    rule_id = "GASV-TRIG-001"
    severity = "HIGH"
    description = "Workflow uses a trigger that may grant elevated permissions to untrusted code."
    remediation = (
        "Review use of 'pull_request_target' carefully:\n"
        "- Never checkout the PR head ref (github.event.pull_request.head.sha) in a "
        "pull_request_target workflow unless you fully understand the security implications.\n"
        "- Prefer 'pull_request' for CI checks on fork PRs (runs with read-only token).\n"
        "- If pull_request_target is required, avoid running any code from the PR branch.\n"
        "See: https://securitylab.github.com/research/github-actions-preventing-pwn-requests/"
    )

    def check(self, workflow: Dict, filepath: str, raw: str) -> List[Dict[str, Any]]:
        findings = []
        on_triggers = workflow.get("on", workflow.get(True, {}))  # 'on' is a YAML reserved word
        if not on_triggers:
            return findings

        # Normalise: 'on' can be a string, list, or dict
        if isinstance(on_triggers, str):
            trigger_names = [on_triggers]
        elif isinstance(on_triggers, list):
            trigger_names = on_triggers
        elif isinstance(on_triggers, dict):
            trigger_names = list(on_triggers.keys())
        else:
            return findings

        if "pull_request_target" in trigger_names:
            # Check if workflow also checks out PR head code (makes it exploitable)
            jobs = workflow.get("jobs", {}) or {}
            checks_out_pr_head = False
            for job in jobs.values():
                if not isinstance(job, dict):
                    continue
                for step in (job.get("steps") or []):
                    if not isinstance(step, dict):
                        continue
                    uses = step.get("uses", "") or ""
                    with_block = step.get("with", {}) or {}
                    ref_val = str(with_block.get("ref", ""))
                    if "checkout" in uses and (
                        "head" in ref_val.lower() or
                        "pull_request.head" in ref_val or
                        "github.head_ref" in ref_val
                    ):
                        checks_out_pr_head = True

            sev = "CRITICAL" if checks_out_pr_head else "HIGH"
            msg = (
                "Workflow uses 'pull_request_target' trigger AND checks out the PR head ref — "
                "this is a 'pwn request' vulnerability allowing arbitrary code execution with "
                "write permissions."
                if checks_out_pr_head else
                "Workflow uses 'pull_request_target' trigger, which runs with write permissions. "
                "Ensure no PR head code is executed in this workflow."
            )
            findings.append(self._finding(filepath, msg, severity=sev))

        if "workflow_run" in trigger_names:
            findings.append(self._finding(
                filepath,
                "Workflow uses 'workflow_run' trigger. Verify the triggering workflow is trusted "
                "and that secrets are not inadvertently exposed to untrusted contexts.",
                severity="MEDIUM",
            ))

        return findings
