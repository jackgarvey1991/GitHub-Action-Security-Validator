# Contributing to GASV

Thank you for your interest in contributing. GASV is a capstone project tool — contributions that improve rule accuracy, add new detection categories, or fix bugs are all welcome.

## Development Setup

```bash
git clone https://github.com/jackgarvey/gasv.git
cd gasv
pip install -e ".[dev]"
```

## Adding a New Rule

1. Create a new file in `gasv/rules/` — e.g. `gasv/rules/artifact_integrity.py`
2. Define a class that inherits from `BaseRule` (imported from `gasv/rules/__init__.py`)
3. Implement the `check(self, workflow, filepath, raw)` method — return a list of finding dicts
4. Register the rule in `gasv/scanner.py` by importing it and adding an instance to the `RULES` list
5. Add fixture files in `tests/fixtures/vulnerable/` and `tests/fixtures/clean/`
6. Write tests in `tests/test_rules.py` following the existing pattern

### Rule template

```python
from gasv.rules import BaseRule

class MyNewRule(BaseRule):
    rule_id = "GASV-XXX-001"
    severity = "HIGH"
    description = "One-line description of what this rule detects."
    remediation = "Step-by-step guidance for fixing this issue."

    def check(self, workflow, filepath, raw):
        findings = []
        # ... detection logic ...
        return findings
```

### Finding schema

Every finding dict must have these keys:

| Key | Type | Description |
|---|---|---|
| `rule_id` | str | e.g. `"GASV-XXX-001"` |
| `severity` | str | `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO` |
| `file` | str | Path to the workflow file |
| `line` | int | Line number (1-indexed, best effort) |
| `location` | str | Human-readable location e.g. `"line 24"` |
| `message` | str | Specific description of this finding |
| `remediation` | str | How to fix it |

Use `self._finding(filepath, message, line=N)` to generate a conforming dict automatically.

## Running Tests

```bash
# All tests
pytest tests/ -v

# Single rule
pytest tests/ -v -k "TestUnpinnedActions"

# With coverage
pytest tests/ --cov=gasv --cov-report=term-missing
```

All tests must pass before a PR will be reviewed.

## Commit Style

Use conventional commits:
- `feat: add GASV-ART-001 artifact integrity rule`
- `fix: GASV-INJ-001 false positive on workflow_dispatch inputs`
- `test: add edge case fixture for reusable workflows`
- `docs: update README with SARIF upload example`
