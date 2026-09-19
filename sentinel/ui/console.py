import sys
from typing import List, Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.columns import Columns

from sentinel.models import Finding, ScanSummary, Severity, ToolDefinition

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

console = Console(highlight=False)

BANNER = """[bold cyan]
  __  __  ____ ____         ____             _   _            _ 
 |  \/  |/ ___|  _ \       / ___|  ___ _ __ | |_(_)_ __   ___| |
 | |\/| | |   | |_) |_____ \___ \ / _ \ '_ \| __| | '_ \ / _ \ |
 | |  | | |___|  __/|_____| ___) |  __/ | | | |_| | | | |  __/ |
 |_|  |_|\____|_|          |____/ \___|_| |_|\__|_|_| |_|\___|_|
[/bold cyan]
[bold magenta]           >> Model Context Protocol (MCP) Dynamic Security Scanner & Linter <<[/bold magenta]
[dim cyan]                        v0.1.0 • Built for AI Agents & Tool Security[/dim cyan]
"""


def print_banner():
    console.print(BANNER)


def print_target_info(target: str, transport: str, total_tools: int):
    grid = Table.grid(expand=True, padding=(0, 2))
    grid.add_column(justify="left", style="bold cyan")
    grid.add_column(justify="left", style="white")

    grid.add_row("[+] Target:", f"[bold green]{target}[/]")
    grid.add_row("[+] Transport:", f"[yellow]{transport.upper()}[/]")
    grid.add_row("[+] Discovered Tools:", f"[bold magenta]{total_tools} tools registered[/]")

    panel = Panel(
        grid,
        title="[bold bright_white][*] Scan Initialization[/]",
        border_style="cyan",
        padding=(1, 2),
    )
    console.print(panel)


def print_tools_table(tools: List[ToolDefinition]):
    table = Table(
        title="[bold cyan][*] Discovered MCP Tool Interfaces[/]",
        border_style="bright_blue",
        header_style="bold magenta",
        show_lines=True,
    )
    table.add_column("#", style="dim", width=4, justify="center")
    table.add_column("Tool Name", style="bold cyan", width=22)
    table.add_column("Parameters", style="yellow", width=26)
    table.add_column("Description", style="white")

    for idx, tool in enumerate(tools, 1):
        params = list(tool.input_schema.get("properties", {}).keys())
        params_str = ", ".join(params) if params else "[dim italic]none[/]"
        desc = tool.description or "[dim italic]No description provided[/]"
        if len(desc) > 80:
            desc = desc[:77] + "..."
        table.add_row(str(idx), tool.name, params_str, desc)

    console.print(table)


def print_findings_summary(summary: ScanSummary):
    console.print("\n")

    score = summary.security_score
    if score >= 90:
        score_color = "bold green"
        verdict = "[+] EXCELLENT (Hardened)"
    elif score >= 70:
        score_color = "bold yellow"
        verdict = "[!] MODERATE (Action Needed)"
    elif score >= 40:
        score_color = "bold orange3"
        verdict = "[!] HIGH RISK (Vulnerabilities Found)"
    else:
        score_color = "bold red"
        verdict = "[!] CRITICAL RISK (Immediate Remediation Required)"

    cards = [
        Panel(
            f"[{score_color}]{score}/100[/]\n[dim]{verdict}[/dim]",
            title="[bold]Security Score[/]",
            border_style=score_color.split()[-1],
            width=36,
        ),
        Panel(
            f"[bold red]Critical: {summary.critical_count}[/]\n"
            f"[bold orange3]High:     {summary.high_count}[/]\n"
            f"[bold yellow]Medium:   {summary.medium_count}[/]\n"
            f"[bold cyan]Low:      {summary.low_count}[/]",
            title="[bold]Severity Breakdown[/]",
            border_style="magenta",
            width=30,
        ),
        Panel(
            f"[white]Target:[/] [green]{summary.target[:20]}[/]\n"
            f"[white]Tools Scanned:[/] [magenta]{len(summary.scanned_tools)}[/]\n"
            f"[white]Total Findings:[/] [bold red]{len(summary.findings)}[/]\n"
            f"[white]Scan Duration:[/] [cyan]{summary.duration_seconds:.2f}s[/]",
            title="[bold]Scan Telemetry[/]",
            border_style="blue",
            width=34,
        ),
    ]

    console.print(Columns(cards, equal=False))


def print_detailed_findings(findings: List[Finding]):
    if not findings:
        console.print(
            Panel(
                "[bold green][+] No security vulnerabilities detected in the target MCP server! Clean scan.[/]",
                border_style="green",
            )
        )
        return

    console.print("\n[bold magenta]=================== DETAILED SECURITY FINDINGS ===================[/bold magenta]\n")

    for idx, f in enumerate(findings, 1):
        content = Text()
        content.append(f"• Tool: ", style="bold cyan")
        content.append(f"{f.tool_name}\n", style="bold white")

        if f.parameter:
            content.append(f"• Vulnerable Parameter: ", style="bold cyan")
            content.append(f"{f.parameter}\n", style="bold yellow")

        content.append(f"• Category: ", style="bold cyan")
        content.append(f"{f.category.value}\n", style="magenta")

        content.append(f"• CWE Reference: ", style="bold cyan")
        content.append(f"{f.cwe_id}\n\n", style="dim")

        content.append(f"• Description:\n  {f.description}\n\n", style="white")

        if f.payload:
            content.append(f"• Injected Payload:\n  ", style="bold red")
            content.append(f"{f.payload}\n\n", style="bold yellow")

        if f.response_snippet:
            content.append(f"• Evidence / Server Response:\n  ", style="bold green")
            content.append(f"{f.response_snippet[:200]}\n\n", style="italic dim")

        content.append(f"[Remediation Guidance]\n  {f.remediation}", style="bold bright_green")

        border_color = "red" if f.severity in (Severity.CRITICAL, Severity.HIGH) else "yellow" if f.severity == Severity.MEDIUM else "cyan"

        panel = Panel(
            content,
            title=f"{f.severity.badge} [bold bright_white]Finding #{idx}: {f.title}[/]",
            border_style=border_color,
            padding=(1, 2),
        )
        console.print(panel)
