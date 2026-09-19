import re
import uuid
from typing import List
from sentinel.models import Finding, Severity, ToolDefinition, VulnCategory

# High-confidence secret detection patterns
SECRET_PATTERNS = [
    (r"sk-[a-zA-Z0-9_-]{20,}", "OpenAI / Anthropic API Key"),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
    (r"ghp_[a-zA-Z0-9]{36}", "GitHub Personal Access Token"),
    (r"xox[baprs]-[0-9a-zA-Z]{10,48}", "Slack Token"),
    (r"(postgres|mysql|mongodb|redis):\/\/[^\s:]+:[^\s@]+@[^\s\/]+", "Database Connection URI with Credentials"),
    (r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}", "JSON Web Token (JWT)"),
    (r"Bearer\s+[a-zA-Z0-9_\-\.]{20,}", "Authorization Bearer Token"),
]

SUSPICIOUS_PROMPT_INJECTIONS = [
    (r"(?i)ignore\s+(previous|all)\s+instructions", "Direct Prompt Override in Tool Description"),
    (r"(?i)always\s+(call|run|execute)\s+this\s+tool\s+first", "Tool Hijacking / Priority Coercion"),
    (r"(?i)do\s+not\s+inform\s+the\s+user", "Covert Execution Coercion"),
    (r"(?i)system\s*:\s*you\s+are", "Simulated System Prompt Injection"),
]


class StaticSchemaAuditor:
    """Performs fast, static security analysis on MCP Tool Schemas & Descriptions."""

    def audit_tool(self, tool: ToolDefinition) -> List[Finding]:
        findings: List[Finding] = []

        # 1. Check for Leaked Secrets in Description
        for pattern, secret_type in SECRET_PATTERNS:
            match = re.search(pattern, tool.description or "")
            if match:
                findings.append(
                    Finding(
                        id=f"STATIC-SECRET-{uuid.uuid4().hex[:6]}",
                        title=f"Hardcoded Credential in Tool Description ({secret_type})",
                        severity=Severity.CRITICAL,
                        category=VulnCategory.SECRET_LEAK,
                        tool_name=tool.name,
                        description=f"Tool '{tool.name}' exposes a sensitive credential ({secret_type}) directly inside its public description schema.",
                        proof_of_concept=f"Matched secret pattern in description: {match.group(0)[:12]}...",
                        remediation="Remove hardcoded credentials from tool metadata and schemas. Use environment variables or secure secret managers at runtime.",
                        cwe_id="CWE-798",
                    )
                )

        # 2. Check for Prompt Hijacking in Tool Description
        for pattern, injection_type in SUSPICIOUS_PROMPT_INJECTIONS:
            if re.search(pattern, tool.description or ""):
                findings.append(
                    Finding(
                        id=f"STATIC-SHADOW-{uuid.uuid4().hex[:6]}",
                        title=f"Suspicious Instruction in Description ({injection_type})",
                        severity=Severity.HIGH,
                        category=VulnCategory.TOOL_SHADOWING,
                        tool_name=tool.name,
                        description=f"Tool '{tool.name}' contains text resembling a prompt injection or override directive: '{tool.description}'",
                        proof_of_concept=tool.description,
                        remediation="Ensure tool descriptions accurately describe functionality without meta-instructions attempting to dictate LLM priority or suppress user visibility.",
                        cwe_id="CWE-1021",
                    )
                )

        # 3. Check for Overprivileged Execution Tools
        name_lower = tool.name.lower()
        if any(keyword in name_lower for keyword in ["exec", "shell", "bash", "cmd", "run_command", "eval", "system"]):
            props = tool.input_schema.get("properties", {})
            for param_name, param_info in props.items():
                if param_info.get("type") == "string":
                    findings.append(
                        Finding(
                            id=f"STATIC-PRIV-{uuid.uuid4().hex[:6]}",
                            title=f"Unrestricted Command Execution Surface on Parameter '{param_name}'",
                            severity=Severity.HIGH,
                            category=VulnCategory.OVERPRIVILEGED,
                            tool_name=tool.name,
                            parameter=param_name,
                            description=f"Tool '{tool.name}' exposes raw string execution via parameter '{param_name}' without schema-level constraints (enum, regex pattern, or strict path whitelist).",
                            remediation="Implement strict parameter validation, define allowlists for allowed subcommands/arguments, or run in an isolated sandbox container.",
                            cwe_id="CWE-78",
                        )
                    )

        # 4. Check for Unbounded Input Validation
        properties = tool.input_schema.get("properties", {})
        for param_name, param_info in properties.items():
            param_type = param_info.get("type")
            if param_type == "array" and "maxItems" not in param_info:
                findings.append(
                    Finding(
                        id=f"STATIC-BOUND-{uuid.uuid4().hex[:6]}",
                        title=f"Unbounded Array Input on '{param_name}'",
                        severity=Severity.LOW,
                        category=VulnCategory.MISSING_VALIDATION,
                        tool_name=tool.name,
                        parameter=param_name,
                        description=f"Parameter '{param_name}' does not define 'maxItems'. Large payload arrays could trigger context window exhaustion or memory consumption.",
                        remediation="Specify 'maxItems' in the JSON Schema definition for array inputs.",
                        cwe_id="CWE-400",
                    )
                )

        return findings
