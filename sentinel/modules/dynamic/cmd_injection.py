import uuid
from typing import Any, Callable, Dict, List
from sentinel.models import Finding, Severity, ToolDefinition, VulnCategory

CMD_PARAM_HINTS = {"cmd", "command", "query", "script", "code", "input", "exec", "args"}


class CommandInjectionFuzzer:
    """Dynamically tests execution tools for unescaped shell metacharacter command injection."""

    async def probe_tool(self, tool: ToolDefinition, caller_fn: Callable) -> List[Finding]:
        findings: List[Finding] = []
        props = tool.input_schema.get("properties", {})

        target_params = [
            p for p, info in props.items()
            if any(hint in p.lower() for hint in CMD_PARAM_HINTS) and info.get("type", "string") == "string"
        ]

        if not target_params:
            return findings

        canary_token = f"SENTINEL_CANARY_{uuid.uuid4().hex[:8]}"

        payloads = [
            f"; echo {canary_token};",
            f"| echo {canary_token}",
            f"& echo {canary_token}",
            f"`echo {canary_token}`",
            f"$(echo {canary_token})",
        ]

        for param in target_params:
            for payload in payloads:
                args = {param: payload}
                try:
                    res = await caller_fn(tool.name, args)
                    res_str = str(res)

                    if canary_token in res_str:
                        findings.append(
                            Finding(
                                id=f"DYN-CMDI-{uuid.uuid4().hex[:6]}",
                                title=f"Confirmed Command Injection (RCE) on Parameter '{param}'",
                                severity=Severity.CRITICAL,
                                category=VulnCategory.COMMAND_INJECTION,
                                tool_name=tool.name,
                                parameter=param,
                                description=(
                                    f"Tool '{tool.name}' passes input parameter '{param}' directly to a shell or command interpreter "
                                    f"without proper sanitization, allowing arbitrary command execution."
                                ),
                                proof_of_concept=f"Calling {tool.name}({param}='{payload}') reflected injected canary token '{canary_token}'.",
                                payload=payload,
                                response_snippet=res_str[:300],
                                remediation=(
                                    "Avoid passing raw strings to shell execution (`shell=True`, `sh -c`, `system()`). "
                                    "Pass arguments as discrete arrays using `subprocess.run(['cmd', arg1, arg2], shell=False)` and enforce an allowlist."
                                ),
                                cwe_id="CWE-78",
                            )
                        )
                        break
                except Exception:
                    continue

        return findings
