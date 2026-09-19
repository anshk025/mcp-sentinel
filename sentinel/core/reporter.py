import json
from pathlib import Path
from typing import Any, Dict
from sentinel.models import ScanSummary, Severity


class ReportExporter:
    """Generates JSON, Markdown, and SARIF vulnerability reports from ScanSummary."""

    @staticmethod
    def to_json(summary: ScanSummary, file_path: str):
        data = summary.model_dump(mode="json")
        data["security_score"] = summary.security_score
        data["metrics"] = {
            "critical": summary.critical_count,
            "high": summary.high_count,
            "medium": summary.medium_count,
            "low": summary.low_count,
            "info": summary.info_count,
        }
        Path(file_path).write_text(json.dumps(data, indent=2), encoding="utf-8")

    @staticmethod
    def to_markdown(summary: ScanSummary, file_path: str):
        md = []
        md.append(f"# 🛡️ MCP-Sentinel Security Audit Report\n")
        md.append(f"**Target:** `{summary.target}`  ")
        md.append(f"**Audit Timestamp:** {summary.start_time.isoformat()}  ")
        md.append(f"**Security Health Score:** `{summary.security_score}/100`  \n")

        md.append("## 📊 Summary Metrics\n")
        md.append("| Severity | Count |")
        md.append("|---|---|")
        md.append(f"| 🚨 Critical | **{summary.critical_count}** |")
        md.append(f"| 🔥 High | **{summary.high_count}** |")
        md.append(f"| ⚠️ Medium | **{summary.medium_count}** |")
        md.append(f"| ℹ️ Low | **{summary.low_count}** |")
        md.append(f"| Total Findings | **{len(summary.findings)}** |\n")

        md.append("## 🔍 Detailed Vulnerabilities\n")
        if not summary.findings:
            md.append("✅ **No vulnerabilities detected.** Target MCP Server configuration is hardened.\n")
        else:
            for idx, f in enumerate(summary.findings, 1):
                md.append(f"### {idx}. [{f.severity.value}] {f.title}\n")
                md.append(f"- **Tool Name:** `{f.tool_name}`")
                if f.parameter:
                    md.append(f"- **Parameter:** `{f.parameter}`")
                md.append(f"- **Category:** {f.category.value}")
                md.append(f"- **CWE:** {f.cwe_id}")
                md.append(f"\n**Description:**\n{f.description}\n")
                if f.proof_of_concept:
                    md.append(f"**Proof of Concept:**\n```\n{f.proof_of_concept}\n```\n")
                if f.payload:
                    md.append(f"**Payload:**\n`{f.payload}`\n")
                md.append(f"**Remediation:**\n> {f.remediation}\n")
                md.append("---\n")

        Path(file_path).write_text("\n".join(md), encoding="utf-8")

    @staticmethod
    def to_sarif(summary: ScanSummary, file_path: str):
        """Generates standard SARIF v2.1.0 report for GitHub Security integration."""
        rules = []
        results = []

        seen_rules = set()

        for f in summary.findings:
            rule_id = f.cwe_id or "MCP-VULN"
            if rule_id not in seen_rules:
                seen_rules.add(rule_id)
                rules.append({
                    "id": rule_id,
                    "name": f.category.name,
                    "shortDescription": {"text": f.title},
                    "help": {"text": f.remediation},
                })

            level = "error" if f.severity in (Severity.CRITICAL, Severity.HIGH) else "warning" if f.severity == Severity.MEDIUM else "note"

            results.append({
                "ruleId": rule_id,
                "level": level,
                "message": {"text": f"{f.title}: {f.description}"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f"mcp://tools/{f.tool_name}"},
                    }
                }]
            })

        sarif_doc = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "MCP-Sentinel",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/mcp-sentinel/mcp-sentinel",
                        "rules": rules,
                    }
                },
                "results": results,
            }]
        }
        Path(file_path).write_text(json.dumps(sarif_doc, indent=2), encoding="utf-8")
