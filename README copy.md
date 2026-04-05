# GASV — GitHub Actions Security Validator

[![CI](https://github.com/jackgarvey/gasv/actions/workflows/ci.yml/badge.svg)](https://github.com/jackgarvey/gasv/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A static analysis tool that scans GitHub Actions workflow YAML files for security vulnerabilities and produces structured, actionable remediation guidance.

> **Academic context:** This tool is being developed as the capstone project (TM470) for the Open University Computing and IT degree programme (2026B).

---

## The Problem

GitHub Actions workflow files are widely used to automate CI/CD pipelines, but misconfigured workflows routinely expose secrets, grant excessive permissions, and use unverified third-party actions — creating significant supply chain security risks.

The [March 2025 tj-actions supply chain attack](https://unit42.paloaltonetworks.com/supply-chain-attack-compromises-widely-used-github-action/) affected over 23,000 repositories through a single compromised action. Koishybayev et al. (USENIX Security 2022) found systemic misconfiguration across 316,000 public workflows.

GASV addresses this by catching these issues *before* code reaches production.

---

## Features

| Rule ID | Vulnerability | Severity |
|---|---|---|
| `GASV-PERM-001` | Overpermissive `permissions: write-all` | HIGH |
| `GASV-PERM-002` | Missing top-level permissions block | MEDIUM |
| `GASV-PIN-001` | Actions pinned to mutable tags, not commit SHAs | HIGH / MEDIUM |
| `GASV-INJ-001` | Expression injection via untrusted context values | CRITICAL |
| `GASV-SEC-001` | Hardcoded secrets / credentials | CRITICAL |
| `GASV-TRIG-001` | Dangerous triggers (`pull_request_target` pwn-request) | CRITICAL / HIGH |

**Output formats:** Rich terminal table · JSON · SARIF 2.1.0 (GitHub Code Scanning compatible)

---

## Installation

**Requirements:** Python 3.10 or later

```bash
# Install from source
git clone https://github.com/jackgarvey/gasv.git
cd gasv
pip install -e .

# Or install with dev dependencies (pytest etc.)
pip install -e ".[dev]"
```

---

## Usage

### Scan a single file

```bash
gasv scan .github/workflows/ci.yml
```

### Scan an entire workflows directory

```bash
gasv scan .github/workflows/
```

### Filter by minimum severity

```bash
gasv scan .github/workflows/ --severity HIGH
```

### JSON output (machine-readable)

```bash
gasv scan .github/workflows/ --format json
```

### SARIF output (for GitHub Code Scanning upload)

```bash
gasv scan .github/workflows/ --format sarif > results.sarif
```

### Use as a CI gate (exits 1 on HIGH/CRITICAL findings)

```yaml
- name: Run GASV
  run: gasv scan .github/workflows/
```

Use `--exit-zero` to report findings without failing the build.

---

## Example Output

```
GASV — scanned 1 file(s)

╭─────────────────────────────────────────────────────────────────────╮
│                        6 finding(s)                                  │
├──────────┬──────────────┬─────────────────┬──────────┬──────────────┤
│ Severity │ Rule         │ File            │ Location │ Description  │
├──────────┼──────────────┼─────────────────┼──────────┼──────────────┤
│ CRITICAL │ GASV-INJ-001 │ ci.yml          │ line 24  │ Untrusted... │
│ CRITICAL │ GASV-TRIG-001│ ci.yml          │ line 1   │ pwn-request  │
│ HIGH     │ GASV-PERM-001│ ci.yml          │ line 7   │ write-all... │
...
```

---

## Project Structure

```
gasv/
├── gasv/
│   ├── __init__.py         # Package metadata
│   ├── cli.py              # Click CLI entry point
│   ├── scanner.py          # YAML parsing + rule orchestration
│   └── rules/
│       ├── __init__.py     # BaseRule abstract class
│       ├── permissions.py  # GASV-PERM-001/002
│       ├── pinning.py      # GASV-PIN-001
│       ├── injection.py    # GASV-INJ-001
│       ├── secrets.py      # GASV-SEC-001
│       └── triggers.py     # GASV-TRIG-001
├── tests/
│   ├── fixtures/
│   │   ├── vulnerable/     # Known-bad workflow fixtures
│   │   └── clean/          # Known-good workflow fixtures
│   └── test_rules.py       # pytest test suite (18 tests)
├── .github/
│   └── workflows/
│       └── ci.yml          # GASV's own CI (eats its own cooking)
├── pyproject.toml
├── README.md
└── LICENSE
```

---

## Running the Tests

```bash
pytest tests/ -v

# With coverage report
pytest tests/ -v --cov=gasv --cov-report=term-missing
```

---

## Architecture

GASV uses a three-layer design:

1. **Parsing layer** (`scanner.py`) — PyYAML `safe_load()` deserialises the workflow YAML. `safe_load()` is used deliberately over `load()` to prevent arbitrary code execution from malicious YAML tags.

2. **Rule engine layer** (`rules/`) — Each vulnerability category is an independent class implementing the `BaseRule` interface. Rules receive both the parsed dict and the raw YAML text (the secrets rule operates on raw text for line-number accuracy).

3. **Reporting layer** (`cli.py`) — Click handles argument parsing; Rich renders the terminal table; JSON and SARIF outputs are produced directly from the findings list.

Adding a new rule requires only creating a new file in `rules/` and registering it in `scanner.py`.

---

## Scope and Limitations

GASV performs **intra-file static analysis only**. It does not:
- Follow `uses:` references to analyse third-party action source code
- Perform cross-repository or cross-workflow taint analysis
- Connect to the GitHub API or access any network resource
- Execute workflow code

These limitations are by design. Full cross-file taint analysis is implemented in research tools such as [ARGUS](https://github.com/muralee/argus) (Muralee et al., USENIX Security 2023). GASV targets the most common misconfigurations that are detectable from the workflow file alone.

---

## References

- Koishybayev, I. et al. (2022) *Characterizing the Security of GitHub CI Workflows*, USENIX Security.
- Muralee, S. et al. (2023) *ARGUS: A Framework for Staged Static Taint Analysis of GitHub Workflows and Actions*, USENIX Security.
- OWASP (2022) [Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/)
- GitHub Security Lab (2021) [Preventing pwn requests](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/)

---

## License

MIT — see [LICENSE](LICENSE)
