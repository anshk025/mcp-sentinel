import asyncio
import time
from typing import Any, Callable, Dict, List, Optional
from datetime import datetime, timezone

from sentinel.models import Finding, ScanSummary, ToolDefinition
from sentinel.modules.static.schema_audit import StaticSchemaAuditor
from sentinel.modules.dynamic.path_traversal import PathTraversalFuzzer
from sentinel.modules.dynamic.cmd_injection import CommandInjectionFuzzer
from sentinel.modules.dynamic.ssrf_probe import SSRFFuzzer
from sentinel.modules.dynamic.unicode_smuggle import UnicodeSmugglingProber


class ScanOrchestrator:
    """Coordinates static analysis and dynamic fuzzing across all discovered MCP tools."""

    def __init__(self, target_label: str, dynamic_caller: Optional[Callable] = None):
        self.target_label = target_label
        self.dynamic_caller = dynamic_caller
        self.static_auditor = StaticSchemaAuditor()
        self.path_fuzzer = PathTraversalFuzzer()
        self.cmd_fuzzer = CommandInjectionFuzzer()
        self.ssrf_fuzzer = SSRFFuzzer()
        self.unicode_prober = UnicodeSmugglingProber()

    async def scan_tools(self, tools: List[ToolDefinition], enable_dynamic: bool = True) -> ScanSummary:
        start_time = datetime.now(timezone.utc)
        start_clock = time.perf_counter()

        all_findings: List[Finding] = []
        scanned_tools: List[str] = []

        for tool in tools:
            scanned_tools.append(tool.name)

            # 1. Static Schema Analysis
            static_results = self.static_auditor.audit_tool(tool)
            all_findings.extend(static_results)

            # 2. Dynamic Fuzzing (if enabled and dynamic caller available)
            if enable_dynamic and self.dynamic_caller:
                path_results = await self.path_fuzzer.probe_tool(tool, self.dynamic_caller)
                all_findings.extend(path_results)

                cmd_results = await self.cmd_fuzzer.probe_tool(tool, self.dynamic_caller)
                all_findings.extend(cmd_results)

                ssrf_results = await self.ssrf_fuzzer.probe_tool(tool, self.dynamic_caller)
                all_findings.extend(ssrf_results)

                unicode_results = await self.unicode_prober.probe_tool(tool, self.dynamic_caller)
                all_findings.extend(unicode_results)

        duration = time.perf_counter() - start_clock

        return ScanSummary(
            target=self.target_label,
            total_tools=len(tools),
            scanned_tools=scanned_tools,
            findings=all_findings,
            start_time=start_time,
            end_time=datetime.now(timezone.utc),
            duration_seconds=duration,
        )
