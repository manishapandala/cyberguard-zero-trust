"""Risk-scoring and control-mapping layer for CyberGuard classifications."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Iterable

from classifier.core import ActivityClassifier


CONTROL_MAP = {
    "Unauthorized backup access": ["ZTA: least privilege", "NIST AC-6", "NIST AU-6"],
    "Path traversal attempt": ["ZTA: continuous verification", "NIST SI-4", "NIST AC-3"],
    "Privilege escalation attempt": ["ZTA: least privilege", "NIST AC-2", "NIST AC-6"],
    "Suspicious login attempt": ["ZTA: explicit verification", "NIST IA-2", "NIST AC-7"],
    "Malware upload attempt": ["ZTA: inspect traffic", "NIST SI-3", "NIST SI-4"],
    "SQL injection attempt": ["ZTA: inspect traffic", "NIST SI-10", "NIST SI-4"],
    "Network reconnaissance": ["ZTA: continuous monitoring", "NIST SI-4", "NIST SC-7"],
    "Suspicious activity": ["ZTA: continuous monitoring", "NIST SI-4", "NIST AU-6"],
    "None": ["NIST AU-2: retain auditable event record"],
}


@dataclass(frozen=True)
class Assessment:
    status: str
    attack_type: str
    reason: str
    risk_score: int
    severity: str
    controls: tuple[str, ...]

    def to_dict(self) -> dict:
        data = asdict(self)
        data["controls"] = list(self.controls)
        return data


def score_event(record: dict[str, str], status: str, attack_type: str) -> int:
    """Assign an explainable 0-100 score from visible event attributes."""
    if status != "Malicious":
        return 5 if record.get("action", "").lower() in {"blocked", "failed"} else 0

    score = 55
    if record.get("threat_label", "").lower() == "suspicious":
        score += 15
    if record.get("action", "").lower() in {"blocked", "failed"}:
        score += 10
    if attack_type in {
        "Unauthorized backup access",
        "Path traversal attempt",
        "Privilege escalation attempt",
        "SQL injection attempt",
        "Malware upload attempt",
    }:
        score += 15
    user_agent = record.get("user_agent", "").lower()
    if any(tool in user_agent for tool in ("nmap", "sqlmap", "nikto", "nessus", "masscan")):
        score += 10
    return min(score, 100)


def severity_for(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 35:
        return "medium"
    return "low"


class CyberGuard:
    def __init__(self) -> None:
        self.classifier = ActivityClassifier()

    def assess(self, raw_event: str) -> Assessment:
        parsed, record, parse_error = self.classifier.parse_input(raw_event)
        if not parsed:
            raise ValueError(parse_error)
        valid, validation_error = self.classifier.validate_record(record)
        if not valid:
            raise ValueError(validation_error)
        status, attack_type, reason = self.classifier.classify_activity(record)
        risk_score = score_event(record, status, attack_type)
        return Assessment(
            status=status,
            attack_type=attack_type,
            reason=reason,
            risk_score=risk_score,
            severity=severity_for(risk_score),
            controls=tuple(CONTROL_MAP.get(attack_type, CONTROL_MAP["Suspicious activity"])),
        )

    def assess_many(self, events: Iterable[str]) -> list[Assessment]:
        return [self.assess(event) for event in events if event.strip()]
