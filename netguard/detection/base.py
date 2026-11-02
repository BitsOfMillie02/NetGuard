from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Finding:
    alert_type: str
    detector: str
    rule_name: str
    severity: str
    confidence: float
    src_ip: str
    dst_ip: Optional[str]
    dst_port: Optional[int]
    start_ts: float
    end_ts: float
    stage: str
    summary: str
    details: Dict[str, Any]
    evidence_refs: List[Dict[str, Any]] = field(default_factory=list)


def calculate_severity(observed: float, threshold: float) -> str:
    """
    Calculate severity level ('low', 'medium', 'high', 'critical') based on observed/threshold ratio.
    """
    if threshold <= 0:
        return "low"

    ratio = observed / threshold

    if ratio >= 8.0:
        return "critical"
    elif ratio >= 4.0:
        return "high"
    elif ratio >= 2.0:
        return "medium"
    else:
        return "low"
