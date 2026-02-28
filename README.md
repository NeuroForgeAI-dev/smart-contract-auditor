# 🔍 Smart Contract Auditor

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-blue?logo=python" />
  <img src="https://img.shields.io/badge/Solidity-0.8+-363636?logo=solidity" />
  <img src="https://img.shields.io/badge/License-MIT-yellow" />
</p>

> Automated smart contract vulnerability scanner detecting reentrancy, overflow, access control, and 15+ vulnerability patterns.

## 🚀 Features

- **15+ Detectors**: Reentrancy, integer overflow, unchecked calls, front-running, etc.
- **Multi-chain**: Ethereum, BSC, Polygon, Arbitrum, Solana
- **CLI & API**: Command-line tool + REST API
- **Report Generation**: JSON and Markdown vulnerability reports
- **Etherscan Integration**: Fetch and audit verified contracts by address
- **Severity Classification**: Critical, High, Medium, Low, Informational

## ⚡ Quick Start

```bash
pip install -r requirements.txt

# Audit a local contract
python auditor.py --file contracts/vulnerable.sol

# Audit by address (requires Etherscan API key)
python auditor.py --address 0x1234...abcd --chain ethereum

# Generate markdown report
python auditor.py --file contracts/token.sol --format markdown -o report.md
```

## 🔎 Supported Detectors

| # | Detector | Severity | Description |
|---|----------|----------|-------------|
| 1 | Reentrancy | Critical | State changes after external calls |
| 2 | Integer Overflow | High | Unchecked arithmetic operations |
| 3 | Unchecked Return | High | Ignored return values from calls |
| 4 | Access Control | Critical | Missing or weak access modifiers |
| 5 | Front-Running | Medium | Transaction ordering dependence |
| 6 | Timestamp Dependence | Low | Block.timestamp manipulation |
| 7 | Delegatecall Injection | Critical | Unsafe delegatecall usage |
| 8 | Self-Destruct | High | Unprotected selfdestruct |
| 9 | Gas Limit DoS | Medium | Unbounded loops |
| 10 | Flash Loan Attack | High | Price oracle manipulation |

## 📊 Sample Report

```json
{
  "contract": "VulnerableToken.sol",
  "findings": 3,
  "critical": 1,
  "high": 1,
  "medium": 1,
  "details": [
    {
      "detector": "reentrancy",
      "severity": "CRITICAL",
      "line": 42,
      "description": "State variable 'balance' modified after external call"
    }
  ]
}
```

## 📄 License
MIT — see [LICENSE](LICENSE)

---
Built by [NeuroForge AI](https://github.com/NeuroForgeAI-dev)
