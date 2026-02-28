"""Core vulnerability scanner engine."""
import re
from typing import Dict, List
from core.detectors import DETECTORS


class Scanner:
    """Scans Solidity source code for vulnerability patterns."""

    def __init__(self, detectors=None):
        self.detectors = detectors or DETECTORS

    def scan(self, source: str, filename: str = "contract.sol") -> Dict:
        findings = []
        lines = source.split("\n")

        for detector in self.detectors:
            results = detector.detect(source, lines)
            findings.extend(results)

        findings.sort(key=lambda f: ["critical","high","medium","low","info"].index(f["severity"].lower()))

        return {
            "contract": filename,
            "total": len(findings),
            "critical": sum(1 for f in findings if f["severity"] == "CRITICAL"),
            "high": sum(1 for f in findings if f["severity"] == "HIGH"),
            "medium": sum(1 for f in findings if f["severity"] == "MEDIUM"),
            "low": sum(1 for f in findings if f["severity"] == "LOW"),
            "findings": findings,
        }
