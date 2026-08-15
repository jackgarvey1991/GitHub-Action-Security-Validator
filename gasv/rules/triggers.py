from typing import List, Dict, Any
from gasv.rules import BaseRule


class DangerousTriggerRule(BaseRule):
    rule_id = "GASV-TRIG-001"
    severity = "HIGH"
    description = "Workflow uses a trigger that may grant elevated permissions to untrusted code."
    remediation = "Be careful with pull_request_target as it runs with write permissions. Don't check out or run code from the PR branch."

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
