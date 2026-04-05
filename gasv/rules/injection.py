"""
GASV-INJ-001: GitHub Actions expression injection vulnerability.

Untrusted user-controlled context values (e.g. github.event.issue.title,
github.head_ref) passed directly into 'run' steps via ${{ }} expressions
allow attackers to inject arbitrary shell commands.

Reference: Koishybayev et al. (2022), GitHub Security Lab advisory
"""
import re
from typing import List, Dict, Any
from gasv.rules import BaseRule

# Context values that are fully attacker-controlled (from external events)
UNTRUSTED_CONTEXTS = [
    r"github\.event\.issue\.title",
    r"github\.event\.issue\.body",
    r"github\.event\.pull_request\.title",
    r"github\.event\.pull_request\.body",
    r"github\.event\.pull_request\.head\.ref",
    r"github\.event\.pull_request\.head\.label",
    r"github\.event\.pull_request\.head\.repo\.default_branch",
    r"github\.event\.comment\.body",
    r"github\.event\.review\.body",
    r"github\.event\.review_comment\.body",
    r"github\.event\.pages\[\d+\]\.page_name",
    r"github\.event\.commits\[\d+\]\.message",
    r"github\.event\.commits\[\d+\]\.author\.email",
    r"github\.event\.commits\[\d+\]\.author\.name",
    r"github\.head_ref",
    r"github\.event\.inputs\.\w+",  # workflow_dispatch inputs can be attacker-controlled
]

UNTRUSTED_RE = re.compile(
    r"\$\{\{[^}]*(" + "|".join(UNTRUSTED_CONTEXTS) + r")[^}]*\}\}",
    re.IGNORECASE,
)

RUN_INLINE_RE = re.compile(r"\$\{\{(.+?)\}\}")


class ExpressionInjectionRule(BaseRule):
    rule_id = "GASV-INJ-001"
    severity = "CRITICAL"
    description = (
        "Untrusted user-controlled GitHub context value interpolated directly into a run step, "
        "enabling expression injection / RCE."
    )
    remediation = (
        "Pass the value through an intermediate environment variable instead:\n"
        "  env:\n"
        "    TITLE: ${{ github.event.issue.title }}\n"
        "  run: echo \"$TITLE\"\n"
        "This prevents the shell from interpreting the value as code. "
        "See: https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions"
    )

    def check(self, workflow: Dict, filepath: str, raw: str) -> List[Dict[str, Any]]:
        findings = []
        jobs = workflow.get("jobs", {}) or {}
        for job_name, job in jobs.items():
            if not isinstance(job, dict):
                continue
            steps = job.get("steps", []) or []
            for i, step in enumerate(steps):
                if not isinstance(step, dict):
                    continue
                run_cmd = step.get("run")
                if not run_cmd or not isinstance(run_cmd, str):
                    continue
                if UNTRUSTED_RE.search(run_cmd):
                    # Extract the offending expression for the message
                    matches = UNTRUSTED_RE.findall(run_cmd)
                    findings.append(self._finding(
                        filepath,
                        f"Job '{job_name}', step {i+1}: untrusted context value "
                        f"({', '.join(matches)}) interpolated directly into 'run' command. "
                        f"Expression injection / remote code execution risk.",
                    ))
        return findings
