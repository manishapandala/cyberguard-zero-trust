# Engineering Review

This document preserves CyberGuard's design and safety rules independently of chat history. It should be updated whenever event contracts, rule priority, scoring, or control mappings change.

## Architecture

| Layer | Responsibility | File |
|---|---|---|
| Parsing and contract | Parse CSV/JSON and validate controlled fields | `classifier/core.py` |
| Classification | Apply prioritized, deterministic attack rules | `classifier/core.py` |
| Assessment | Add risk, severity, reasons, and control mappings | `cyberguard.py` |
| Interfaces | CLI and bounded Flask endpoints | `classify_activity.py`, `app.py` |
| Evaluation | Generate labeled events and benchmark decisions | `run_demo.py` |

The web layer delegates to the same classifier used by the CLI and tests. Rules remain inspectable and do not depend on a remote model.

## Verification contract

```bash
python -m ruff check .
python -m compileall -q .
python -m unittest discover -s tests -v
python run_demo.py
```

The 45 tests cover parsing, aliases, invalid inputs, CLI exit behavior, attack rules, benign events, severity boundaries, scoring, control mappings, and API limits.

## Change-safety checklist

- Review rule ordering and require tests for both the new rule and nearby existing rules.
- Keep batch count, request size, and individual event size bounded.
- Never treat deterministic fixture accuracy as a production detection rate.
- Keep reasons and matched controls in every assessment for auditability.
- Never commit real security logs, IP inventories, credentials, or vendor records.
- Benchmark event latency after changes to parsing or rule evaluation.
- Use reversible commits and preserve the last passing test baseline.

## Known boundaries

CyberGuard is an explainable baseline, not a SIEM, intrusion-prevention system, or compliance certification. Its mappings identify controls to review; they do not demonstrate that an organization satisfies NIST or Zero Trust requirements.
