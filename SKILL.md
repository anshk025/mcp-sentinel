---
name: mcp-sentinel
description: Automated dynamic security auditor and fuzzer for Model Context Protocol (MCP) servers. Use when auditing, fuzzing, testing, or securing MCP tools and servers against Path Traversal, Command Injection (RCE), SSRF, Secret Leaks, and Unicode Tag Smuggling.
triggers:
  - mcp security
  - audit mcp
  - test mcp server
  - mcp vulnerability
  - fuzzer mcp
  - mcp sentinel
---

# MCP-Sentinel: Agent Security Skill

Use this skill whenever you are building, configuring, auditing, or testing a Model Context Protocol (MCP) server.

## Installation & Prerequisites

Ensure `mcp-sentinel` is available:
```bash
# Using uv (fastest)
uv tool install mcp-sentinel

# Or directly from GitHub
uv tool install git+https://github.com/anshk025/mcp-sentinel.git
```

## When to Run MCP-Sentinel

Run `mcp-sentinel` when:
1. **Developing a new MCP server:** Verify no sensitive files or command injection vectors are exposed.
2. **Auditing third-party MCP servers:** Test untrusted tools before connecting them to agent workflows.
3. **CI/CD Security Verification:** Generate SARIF security reports for pull requests.

## Key Commands

### 1. Interactive Demo & Self-Test
```bash
mcp-sentinel demo --output demo-report.md
```

### 2. Audit a Stdio-Based MCP Server
```bash
# Python MCP server
mcp-sentinel scan --stdio "python server.py" --output report.md

# Node.js MCP server
mcp-sentinel scan --stdio "npx -y @modelcontextprotocol/server-filesystem /path" --output report.md
```

### 3. Fast Static Schema & Secret Audit
```bash
mcp-sentinel scan --stdio "python server.py" --static-only
```

### 4. Export SARIF for GitHub CodeQL
```bash
mcp-sentinel scan --stdio "python server.py" --output security.sarif --format sarif
```

## Vulnerability Remediation Guide

- **Path Traversal (CWE-22):** Resolve absolute paths and verify `resolved_path.startswith(base_dir)`.
- **Command Injection (CWE-78):** Use `subprocess.run(["cmd", arg], shell=False)` with argument arrays; avoid raw shell strings.
- **SSRF (CWE-918):** Disallow connections to loopback (`127.0.0.1`, `::1`), link-local (`169.254.169.254`), and private RFC 1918 subnets.
- **Secret Leaks (CWE-798):** Remove hardcoded API keys/tokens from tool descriptions; load credentials via environment variables at runtime.
- **Unicode Tag Smuggling (CWE-116):** Normalize inputs with NFKC and strip non-printable Unicode tag characters (`U+E0000`-`U+E007F`).
