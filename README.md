# CyberGuard: Explainable Threat Classification

CyberGuard is a deterministic data-breach activity classifier for CSV or JSON security events. It maps visible indicators to an attack type, produces a traceable reason, assigns an explainable risk score, and suggests relevant Zero Trust and NIST control families.

This repository is a cleaned, publishable version of the original prototype. Virtual environments, large spreadsheets, and generated caches are excluded.

## Capabilities

- accepts one CSV row or JSON object;
- validates required fields and controlled values;
- detects backup access, path traversal, privilege escalation, suspicious login, malware upload, SQL injection tooling, and network reconnaissance;
- returns a deterministic 0-100 risk score and severity;
- maps classifications to Zero Trust concepts and selected NIST SP 800-53 controls;
- supports a bounded Flask batch API;
- includes 42 automated tests across parsing, CLI behavior, rules, scoring, and control mapping.

## Run

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m unittest discover -s tests -v
python run_demo.py
python app.py
```

Classify one event from the command line:

```bash
python classify_activity.py '2024-07-31T00:00:00,177.52.183.80,192.168.1.50,HTTPS,blocked,suspicious,ids,45164,"Mozilla/5.0",/download?backup.sql'
```

## Scope

The public demo uses deterministic synthetic security events to verify rule behavior and latency. It is not a substitute for a production SIEM, human incident response, or validation against an organization's environment. Future work can compare hybrid ML anomaly detection against this auditable baseline without removing the rule trace.
