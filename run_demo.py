"""Produce a deterministic public CyberGuard evaluation summary."""

from __future__ import annotations

import json
from pathlib import Path
import statistics
import time

from cyberguard import CyberGuard


HEADER = "timestamp,source_ip,dest_ip,protocol,action,threat_label,log_type,bytes_transferred,user_agent,request_path"
SAMPLES = [
    ('2024-07-31T00:00:00,177.52.183.80,192.168.1.50,HTTPS,blocked,suspicious,ids,45164,"Mozilla/5.0",/download?backup.sql', "Unauthorized backup access"),
    ('2024-12-05T00:00:00,141.26.13.167,192.168.1.50,HTTPS,allowed,suspicious,ids,512,"Mozilla/5.0",/../../etc/passwd', "Path traversal attempt"),
    ('2024-06-01T00:00:00,185.225.185.68,192.168.1.50,HTTPS,failed,benign,application,100,"Mozilla/5.0",/admin/config', "Privilege escalation attempt"),
    ('2024-03-06T00:00:00,137.197.33.33,192.168.1.50,HTTPS,blocked,suspicious,ids,700,"Mozilla/5.0",/upload?phpmyadmin', "Malware upload attempt"),
    ('2024-12-05T00:00:00,141.26.13.167,192.168.1.50,HTTPS,allowed,suspicious,ids,256,"SQLMap/1.6-dev",/api/test', "SQL injection attempt"),
    ('2024-05-01T00:00:00,192.168.1.125,192.168.1.50,TCP,blocked,benign,firewall,0,"Nmap Scripting Engine",/', "Network reconnaissance"),
    ('2024-04-07T00:00:00,192.168.1.248,192.168.1.15,HTTP,allowed,benign,application,20652,"Mozilla/5.0",/home', "None"),
]


def main() -> None:
    guard = CyberGuard()
    repeats = 5_000
    latencies = []
    correct = 0
    examples = []
    for index in range(repeats):
        event, expected = SAMPLES[index % len(SAMPLES)]
        started = time.perf_counter()
        assessment = guard.assess(event)
        latencies.append((time.perf_counter() - started) * 1000)
        correct += assessment.attack_type == expected
        if len(examples) < len(SAMPLES):
            examples.append({"expected": expected, "assessment": assessment.to_dict()})

    ordered = sorted(latencies)
    summary = {
        "scope": "deterministic rule-pipeline validation",
        "events_processed": repeats,
        "attack_types_exercised": len({expected for _, expected in SAMPLES if expected != "None"}),
        "expected_classification_rate": round(correct / repeats, 4),
        "median_event_ms": round(statistics.median(latencies), 4),
        "p95_event_ms": round(ordered[int(0.95 * (len(ordered) - 1))], 4),
        "examples": examples,
    }
    Path("demo_summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
