"""Report generation in multiple formats."""
import json
from typing import Dict


class ReportGenerator:
    @staticmethod
    def generate(results: Dict, fmt: str = "json") -> str:
        if fmt == "json":
            return json.dumps(results, indent=2)
        elif fmt == "markdown":
            return ReportGenerator._to_markdown(results)
        else:
            return ReportGenerator._to_text(results)

    @staticmethod
    def _to_markdown(r: Dict) -> str:
        lines = [
            f"# Security Audit Report: {r['contract']}\n",
            f"**Total findings:** {r['total']}\n",
            f"| Severity | Count |",
            f"|----------|-------|",
            f"| 🔴 Critical | {r['critical']} |",
            f"| 🟠 High | {r['high']} |",
            f"| 🟡 Medium | {r['medium']} |",
            f"| 🟢 Low | {r['low']} |\n",
            "## Findings\n",
        ]
        for i, f in enumerate(r["findings"], 1):
            lines.append(f"### {i}. [{f['severity']}] {f['detector']}")
            lines.append(f"- **Line:** {f['line']}")
            lines.append(f"- **Description:** {f['description']}")
            lines.append(f"- **Recommendation:** {f.get('recommendation', 'N/A')}\n")
        return "\n".join(lines)

    @staticmethod
    def _to_text(r: Dict) -> str:
        lines = [f"=== Audit: {r['contract']} === ({r['total']} findings)\n"]
        for f in r["findings"]:
            lines.append(f"[{f['severity']}] L{f['line']}: {f['description']}")
        return "\n".join(lines)
