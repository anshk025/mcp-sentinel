# ⚡ MCP-Sentinel: Dynamic Security Scanner & Linter for Model Context Protocol (MCP)

<div align="center">

[![Python](https://img.shields.io/badge/Python-3.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-3776AB?logo=python&logoColor=white)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![MCP Specification](https://img.shields.io/badge/MCP-2.0-8A2BE2)](https://modelcontextprotocol.io)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](http://makeapullrequest.com)

**Automated Dynamic Fuzzing, Schema Auditing, and Vulnerability Assessment for AI Agent Toolkits.**

[Quickstart](#-quickstart) • [Vulnerability Classes](#-attack-taxonomy) • [CLI Usage](#-cli-usage) • [CI/CD Integration](#-github-actions--cicd)

</div>

---

## 🎯 Why MCP-Sentinel?

The **Model Context Protocol (MCP)** enables AI agents to interact with host filesystems, databases, APIs, and execution environments. However, exposing tools to LLMs creates critical trust-boundary vulnerabilities:

- **Path Traversal & Arbitrary File Reads** through unrestricted file parameters.
- **Uncontrolled Command Injection (RCE)** in terminal/shell tools.
- **Server-Side Request Forgery (SSRF)** to cloud metadata (`169.254.169.254`) and internal microservices.
- **Hardcoded Secret Leaks** (API keys, DB URIs, JWTs) embedded in tool schemas.
- **Invisible Unicode Tag & ASCII Smuggling** (`U+E0000`-`U+E007F`) used to hide prompt injections from human operators.

**`mcp-sentinel`** is an automated, high-speed security auditor and dynamic fuzzer that verifies whether your MCP servers are hardened before connecting them to agentic LLM runtimes.

---

## ✨ Features

- 🎨 **Vibrant Cyberpunk CLI UI:** Rich terminal tables, telemetry cards, and color-coded risk gauges.
- ⚡ **Static Schema & Secret Linter:** Scans tool descriptions, parameter bounds, and metadata for 40+ secret patterns and overprivileged permissions.
- 🧪 **Active Dynamic Fuzzer:** Probes live MCP servers across stdio/SSE for Path Traversal (LFI), Command Injection (RCE), SSRF, and Unicode tag smuggling.
- 📊 **Multi-Format Reporting:** Instant exports to **Markdown**, **JSON**, and **SARIF v2.1.0** (for native GitHub Security CodeQL integration).
- 🎮 **Instant Demo Mode:** Includes a built-in mock server to test and demonstrate capabilities with zero configuration.

---

## 🚀 Quickstart

### Installation

```bash
# Using uv (recommended)
uv tool install mcp-sentinel

# Or using pip
pip install mcp-sentinel
```

### 1-Minute Interactive Demo
Run a complete dynamic vulnerability scan against the built-in vulnerable test server:

```bash
mcp-sentinel demo
```

---

## 💻 CLI Usage

### 1. Scan any Stdio-based MCP Server
Audit any Python, Node.js, or binary MCP server executed over standard I/O:

```bash
# Scan a Node.js Filesystem MCP server
mcp-sentinel scan --stdio "npx -y @modelcontextprotocol/server-filesystem /path/to/dir" --output report.md

# Scan a Python-based custom MCP server
mcp-sentinel scan --stdio "python my_mcp_server.py" --output report.sarif --format sarif
```

### 2. Static Schema & Secret Audit Only
Disable dynamic fuzzing and perform an ultra-fast static lint:

```bash
mcp-sentinel scan --stdio "python my_server.py" --static-only
```

### 3. Generate CI/CD Security Artifacts
Export scan findings to SARIF for direct visualization in GitHub Pull Requests:

```bash
mcp-sentinel scan --stdio "python server.py" --output mcp-security.sarif --format sarif
```

---

## 🛡️ Attack Taxonomy

| Vulnerability Class | Severity | Detection Mode | CWE |
|---|---|---|---|
| **Path Traversal / Arbitrary File Read** | `CRITICAL` | Dynamic Fuzzing | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) |
| **Command & Shell Injection (RCE)** | `CRITICAL` | Dynamic Fuzzing | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) |
| **Hardcoded Secret / Token Leak** | `CRITICAL` | Static Schema Analysis | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) |
| **Server-Side Request Forgery (SSRF)** | `HIGH` | Dynamic Probing | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) |
| **Overprivileged Tool Interface** | `HIGH` | Static Analysis | [CWE-250](https://cwe.mitre.org/data/definitions/250.html) |
| **Tool Shadowing & Description Hijacking** | `HIGH` | Static Analysis | [CWE-1021](https://cwe.mitre.org/data/definitions/1021.html) |
| **Invisible Unicode Tag Smuggling** | `LOW` | Dynamic Probing | [CWE-116](https://cwe.mitre.org/data/definitions/116.html) |
| **Missing Parameter Bounds (DoS)** | `LOW` | Static Analysis | [CWE-400](https://cwe.mitre.org/data/definitions/400.html) |

---

## 🔄 GitHub Actions / CI/CD

Add `mcp-sentinel` directly into your GitHub Actions workflow to block pull requests introducing vulnerable MCP tool interfaces:

```yaml
name: MCP Security Audit

on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v3

      - name: Run MCP-Sentinel Security Scan
        run: |
          uvx mcp-sentinel scan --stdio "python server.py" --output results.sarif --format sarif

      - name: Upload SARIF report to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

---

## 🤝 Contributing

Contributions are warmly welcomed! Feel free to open issues or PRs to add new vulnerability detectors, fuzzing heuristics, or transport protocols.

```bash
# Clone and install locally
git clone https://github.com/anshk025/mcp-sentinel.git
cd mcp-sentinel
uv sync
uv run pytest
```

---

## 📜 License

Distributed under the **MIT License**. Built with ❤️ for the Agentic AI and Cybersecurity community.
