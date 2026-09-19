import uuid
from typing import Any, Callable, Dict, List, Optional
from sentinel.models import Finding, Severity, ToolDefinition, VulnCategory

PATH_PARAM_HINTS = {"path", "file", "filename", "filepath", "target", "dest", "source", "dir", "directory"}

TRAVERSAL_PAYLOADS = [
    # Linux / Unix standard
    "../../../../../../../../../../etc/passwd",
    "../../../../../../../../../../etc/hosts",
    # Windows standard
    "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\Windows\\win.ini",
    "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts",
    # Encoded / Bypass variants
    "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
    "....//....//....//....//etc/passwd",
    "/etc/passwd",
    "C:\\Windows\\win.ini",
]

SENSITIVE_INDICATORS = [
    "root:x:",
    "daemon:x:",
    "[extensions]",
    "[fonts]",
    "[files]",
    "127.0.0.1",
    "localhost",
]


class PathTraversalFuzzer:
    """Dynamically fuzzes file & filesystem tools for path traversal and arbitrary file read."""

    async def probe_tool(self, tool: ToolDefinition, caller_fn: Callable) -> List[Finding]:
        findings: List[Finding] = []
        props = tool.input_schema.get("properties", {})

        # Identify candidate path parameters
        target_params = [
            p for p, info in props.items()
            if any(hint in p.lower() for hint in PATH_PARAM_HINTS) and info.get("type", "string") == "string"
        ]

        if not target_params:
            return findings

        for param in target_params:
            for payload in TRAVERSAL_PAYLOADS:
                args = {param: payload}
                try:
                    res = await caller_fn(tool.name, args)
                    res_str = str(res)

                    # Check if response leaked sensitive system file contents
                    if any(indicator in res_str for indicator in SENSITIVE_INDICATORS):
                        findings.append(
                            Finding(
                                id=f"DYN-TRAVERSAL-{uuid.uuid4().hex[:6]}",
                                title=f"Confirmed Path Traversal (Arbitrary File Read) on '{param}'",
                                severity=Severity.CRITICAL,
                                category=VulnCategory.PATH_TRAVERSAL,
                                tool_name=tool.name,
                                parameter=param,
                                description=(
                                    f"Tool '{tool.name}' allows directory traversal when parameter '{param}' "
                                    f"is supplied with relative traversal sequences, granting unauthenticated arbitrary file read."
                                ),
                                proof_of_concept=f"Calling {tool.name}({param}='{payload}') returned host system file contents.",
                                payload=payload,
                                response_snippet=res_str[:300],
                                remediation=(
                                    "Enforce a strict base directory jail using `os.path.abspath` or `pathlib.Path.resolve()`. "
                                    "Verify that `resolved_path.startswith(base_directory)` before performing any I/O operation."
                                ),
                                cwe_id="CWE-22",
                            )
                        )
                        break  # Found confirmed vulnerability on this param, move to next
                except Exception:
                    continue

        return findings
