"""Vulnerability detectors for Solidity smart contracts."""
import re
from abc import ABC, abstractmethod
from typing import List, Dict


class BaseDetector(ABC):
    name: str = ""
    severity: str = "MEDIUM"

    @abstractmethod
    def detect(self, source: str, lines: List[str]) -> List[Dict]:
        pass


class ReentrancyDetector(BaseDetector):
    name = "reentrancy"
    severity = "CRITICAL"

    def detect(self, source: str, lines: List[str]) -> List[Dict]:
        findings = []
        call_pattern = re.compile(r"\.(call|send|transfer)\s*[({]")
        state_pattern = re.compile(r"\b\w+\s*[+\-*/]?=\s*")

        for i, line in enumerate(lines):
            if call_pattern.search(line):
                # Check if state changes happen after this call
                for j in range(i + 1, min(i + 10, len(lines))):
                    if state_pattern.search(lines[j]) and "require" not in lines[j]:
                        findings.append({
                            "detector": self.name,
                            "severity": self.severity,
                            "line": i + 1,
                            "description": f"State change after external call at line {j + 1}",
                            "recommendation": "Use checks-effects-interactions pattern or ReentrancyGuard",
                        })
                        break
        return findings


class IntegerOverflowDetector(BaseDetector):
    name = "integer-overflow"
    severity = "HIGH"

    def detect(self, source: str, lines: List[str]) -> List[Dict]:
        findings = []
        if "pragma solidity" in source:
            version_match = re.search(r"pragma solidity\s*\^?(\d+\.\d+)", source)
            if version_match and float(version_match.group(1)) < 0.8:
                if "SafeMath" not in source:
                    for i, line in enumerate(lines):
                        if re.search(r"[+\-*/]\s*=|\+\+|--", line):
                            findings.append({
                                "detector": self.name,
                                "severity": self.severity,
                                "line": i + 1,
                                "description": "Arithmetic without SafeMath in Solidity < 0.8",
                                "recommendation": "Use SafeMath library or upgrade to Solidity >= 0.8",
                            })
        return findings


class AccessControlDetector(BaseDetector):
    name = "access-control"
    severity = "CRITICAL"

    def detect(self, source: str, lines: List[str]) -> List[Dict]:
        findings = []
        sensitive_funcs = ["selfdestruct", "suicide", "delegatecall", "transfer", "send"]

        for i, line in enumerate(lines):
            for func in sensitive_funcs:
                if func in line.lower():
                    # Check if function has access modifier
                    func_start = self._find_function_start(lines, i)
                    if func_start is not None:
                        header = lines[func_start]
                        if not any(mod in header for mod in ["onlyOwner", "onlyAdmin", "require(msg.sender", "modifier"]):
                            findings.append({
                                "detector": self.name,
                                "severity": self.severity,
                                "line": i + 1,
                                "description": f"Sensitive function '{func}' without access control",
                                "recommendation": "Add onlyOwner or similar access control modifier",
                            })
        return findings

    def _find_function_start(self, lines, current):
        for i in range(current, max(current - 20, 0), -1):
            if "function" in lines[i]:
                return i
        return None


class UncheckedReturnDetector(BaseDetector):
    name = "unchecked-return"
    severity = "HIGH"

    def detect(self, source: str, lines: List[str]) -> List[Dict]:
        findings = []
        for i, line in enumerate(lines):
            if ".call{" in line or ".call(" in line:
                if "require" not in line and "(bool" not in line and "success" not in line:
                    findings.append({
                        "detector": self.name,
                        "severity": self.severity,
                        "line": i + 1,
                        "description": "Return value of low-level call not checked",
                        "recommendation": "Check return value: (bool success, ) = addr.call(...); require(success);",
                    })
        return findings


class FrontRunningDetector(BaseDetector):
    name = "front-running"
    severity = "MEDIUM"

    def detect(self, source: str, lines: List[str]) -> List[Dict]:
        findings = []
        if "approve" in source and "transferFrom" in source:
            for i, line in enumerate(lines):
                if "approve" in line and "function" in line:
                    findings.append({
                        "detector": self.name,
                        "severity": self.severity,
                        "line": i + 1,
                        "description": "ERC20 approve() is vulnerable to front-running",
                        "recommendation": "Use increaseAllowance/decreaseAllowance instead",
                    })
        return findings


DETECTORS = [
    ReentrancyDetector(),
    IntegerOverflowDetector(),
    AccessControlDetector(),
    UncheckedReturnDetector(),
    FrontRunningDetector(),
]
