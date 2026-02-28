#!/usr/bin/env python3
"""Smart Contract Auditor — CLI Entry Point"""
import argparse
import json
import sys
from pathlib import Path
from core.scanner import Scanner
from core.report import ReportGenerator


def main():
    parser = argparse.ArgumentParser(description="Smart Contract Security Auditor")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--file", "-f", help="Path to Solidity file")
    group.add_argument("--address", "-a", help="Contract address to audit")
    parser.add_argument("--chain", default="ethereum", choices=["ethereum", "bsc", "polygon", "arbitrum"])
    parser.add_argument("--format", default="json", choices=["json", "markdown", "text"])
    parser.add_argument("--output", "-o", help="Output file path")
    parser.add_argument("--severity", default="low", choices=["critical", "high", "medium", "low", "info"])
    args = parser.parse_args()

    scanner = Scanner()

    if args.file:
        source = Path(args.file).read_text()
        results = scanner.scan(source, filename=args.file)
    else:
        from core.etherscan import fetch_contract_source
        source = fetch_contract_source(args.address, chain=args.chain)
        results = scanner.scan(source, filename=f"{args.address}.sol")

    # Filter by severity
    severity_order = ["critical", "high", "medium", "low", "info"]
    min_idx = severity_order.index(args.severity)
    results["findings"] = [
        f for f in results["findings"]
        if severity_order.index(f["severity"].lower()) <= min_idx
    ]
    results["total"] = len(results["findings"])

    report = ReportGenerator.generate(results, fmt=args.format)

    if args.output:
        Path(args.output).write_text(report)
        print(f"Report saved to {args.output}")
    else:
        print(report)


if __name__ == "__main__":
    main()
