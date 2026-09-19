import uuid
from typing import Any, Callable, Dict, List
from sentinel.models import Finding, Severity, ToolDefinition, VulnCategory

URL_PARAM_HINTS = {"url", "uri", "endpoint", "link", "target_url", "webhook", "address"}

SSRF_PROBES = [
    ("http://127.0.0.1:80", "Loopback IPv4 address access"),
    ("http://localhost:80", "Localhost host resolution"),
    ("http://169.254.169.254/latest/meta-data/", "Cloud Instance Metadata Service (IMDSv1)"),
    ("http://[::1]:80", "IPv6 Loopback address access"),
]


class SSRFFuzzer:
    """Dynamically tests URL/web fetching MCP tools for loopback and cloud metadata SSRF."""

    async def probe_tool(self, tool: ToolDefinition, caller_fn: Callable) -> List[Finding]:
        findings: List[Finding] = []
        props = tool.input_schema.get("properties", {})

        target_params = [
            p for p, info in props.items()
            if any(hint in p.lower() for hint in URL_PARAM_HINTS) and info.get("type", "string") == "string"
        ]

        if not target_params:
            return findings

        for param in target_params:
            for probe_url, probe_desc in SSRF_PROBES:
                args = {param: probe_url}
                try:
                    res = await caller_fn(tool.name, args)
                    res_str = str(res).lower()

                    # Indicators of connection attempted or accepted (not outright blocked by client schema validator)
                    if any(indicator in res_str for indicator in ["connection refused", "instance-id", "ami-id", "iam/security-credentials", "meta-data", "http/1.", "html"]):
                        findings.append(
                            Finding(
                                id=f"DYN-SSRF-{uuid.uuid4().hex[:6]}",
                                title=f"Potential SSRF on Parameter '{param}' ({probe_desc})",
                                severity=Severity.HIGH,
                                category=VulnCategory.SSRF,
                                tool_name=tool.name,
                                parameter=param,
                                description=(
                                    f"Tool '{tool.name}' accepts internal/cloud metadata addresses (`{probe_url}`) "
                                    f"without blocking private IP ranges (RFC 1918 / 169.254.169.254)."
                                ),
                                proof_of_concept=f"Calling {tool.name}({param}='{probe_url}') attempted connection to private network.",
                                payload=probe_url,
                                response_snippet=str(res)[:250],
                                remediation=(
                                    "Validate all URLs before making outbound network requests. Resolve DNS and disallow "
                                    "connections to loopback (127.0.0.0/8, ::1), link-local (169.254.0.0/16), and private RFC1918 subnets."
                                ),
                                cwe_id="CWE-918",
                            )
                        )
                        break
                except Exception:
                    continue

        return findings
