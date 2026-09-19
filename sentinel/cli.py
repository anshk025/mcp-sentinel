import asyncio
import sys
from typing import Optional
import typer
from rich.prompt import Prompt

from sentinel.ui.console import (
    console,
    print_banner,
    print_target_info,
    print_tools_table,
    print_detailed_findings,
    print_findings_summary,
)
from sentinel.core.client import MCPClientAdapter
from sentinel.core.runner import ScanOrchestrator
from sentinel.core.reporter import ReportExporter
from sentinel.demo_server import get_demo_tools, mock_demo_caller

app = typer.Typer(
    name="mcp-sentinel",
    help="⚡ MCP-Sentinel: Dynamic Security Scanner & Linter for Model Context Protocol (MCP) Servers ⚡",
    no_args_is_help=True,
)


@app.command()
def scan(
    command: Optional[str] = typer.Option(
        None,
        "--stdio",
        "-c",
        help="Stdio command to launch the MCP server (e.g. 'npx -y @modelcontextprotocol/server-filesystem C:\\data')",
    ),
    demo: bool = typer.Option(
        False,
        "--demo",
        "-d",
        help="Run an instant interactive security scan against the built-in vulnerable MCP test server",
    ),
    dynamic: bool = typer.Option(
        True,
        "--dynamic/--static-only",
        help="Enable/disable active dynamic fuzzing (path traversal, SSRF, command injection)",
    ),
    output: Optional[str] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file path to export the audit report",
    ),
    format: str = typer.Option(
        "markdown",
        "--format",
        "-f",
        help="Report export format: 'markdown', 'json', or 'sarif'",
    ),
):
    """Run an automated security audit against a target MCP server."""
    print_banner()

    if not command and not demo:
        console.print("[bold red]❌ Error: You must specify a target using `--stdio '<command>'` or run with `--demo`.[/]\n")
        console.print("[dim]Example usage:[/dim]")
        console.print("  [cyan]mcp-sentinel scan --demo[/]")
        console.print("  [cyan]mcp-sentinel scan --stdio 'python server.py' --output report.md[/]")
        raise typer.Exit(code=1)

    async def _execute_scan():
        if demo:
            target_label = "Built-in Vulnerable FastMCP Demo Target"
            transport_type = "In-Memory / FastMCP"
            tools = get_demo_tools()
            caller = mock_demo_caller
        else:
            target_label = command
            transport_type = "Stdio Subprocess"
            parts = command.split()
            adapter = MCPClientAdapter(command=parts[0], args=parts[1:])
            with console.status("[bold cyan]Connecting to MCP server and enumerating tools...[/]", spinner="dots"):
                try:
                    tools = await adapter.connect_and_list_tools()
                except Exception as e:
                    console.print(f"[bold red]❌ Failed to connect to MCP server:[/] {e}")
                    raise typer.Exit(code=1)
            caller = adapter.call_tool_stdio

        print_target_info(target_label, transport_type, len(tools))
        print_tools_table(tools)

        orchestrator = ScanOrchestrator(target_label=target_label, dynamic_caller=caller)

        with console.status("[bold magenta]🚀 Executing static schema linter and dynamic fuzzing probes...[/]", spinner="bouncingBar"):
            summary = await orchestrator.scan_tools(tools, enable_dynamic=dynamic)

        print_detailed_findings(summary.findings)
        print_findings_summary(summary)

        if output:
            fmt_lower = format.lower()
            if fmt_lower == "json":
                ReportExporter.to_json(summary, output)
            elif fmt_lower == "sarif":
                ReportExporter.to_sarif(summary, output)
            else:
                ReportExporter.to_markdown(summary, output)

            console.print(f"\n[bold green]💾 Successfully exported {fmt_lower.upper()} report to:[/] [bold cyan]{output}[/]\n")

    asyncio.run(_execute_scan())


@app.command()
def demo(
    output: Optional[str] = typer.Option(
        "mcp-demo-audit.md",
        "--output",
        "-o",
        help="File path to save the generated report",
    ),
    format: str = typer.Option(
        "markdown",
        "--format",
        "-f",
        help="Export format (markdown, json, sarif)",
    ),
):
    """Run an instant demonstration scan against the built-in vulnerable test server."""
    scan(command=None, demo=True, dynamic=True, output=output, format=format)


@app.command()
def version():
    """Show MCP-Sentinel version and system info."""
    print_banner()
    console.print("[bold green]MCP-Sentinel v0.1.0[/] - [dim]Next-Generation Model Context Protocol Security Auditor[/]")


def main():
    app()


if __name__ == "__main__":
    main()
