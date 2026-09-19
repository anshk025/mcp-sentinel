import pytest
from sentinel.models import Severity, ToolDefinition
from sentinel.modules.static.schema_audit import StaticSchemaAuditor
from sentinel.demo_server import get_demo_tools, mock_demo_caller
from sentinel.core.runner import ScanOrchestrator


def test_static_schema_secret_detection():
    auditor = StaticSchemaAuditor()
    tool = ToolDefinition(
        name="test_tool",
        description="Connects to DB using sk-live123456789012345678901234567890",
        input_schema={"type": "object", "properties": {}},
    )
    findings = auditor.audit_tool(tool)
    assert len(findings) >= 1
    assert findings[0].severity == Severity.CRITICAL
    assert "Credential" in findings[0].title or "Secret" in findings[0].title


def test_static_overprivileged_tool():
    auditor = StaticSchemaAuditor()
    tool = ToolDefinition(
        name="exec_shell",
        description="Runs raw shell",
        input_schema={
            "type": "object",
            "properties": {
                "command": {"type": "string"}
            }
        },
    )
    findings = auditor.audit_tool(tool)
    assert any(f.severity == Severity.HIGH for f in findings)


@pytest.mark.asyncio
async def test_full_orchestrator_scan():
    tools = get_demo_tools()
    orchestrator = ScanOrchestrator(
        target_label="Test Demo Target",
        dynamic_caller=mock_demo_caller,
    )
    summary = await orchestrator.scan_tools(tools, enable_dynamic=True)

    assert summary.total_tools == 4
    assert summary.critical_count >= 2
    assert summary.high_count >= 2
    assert summary.security_score <= 50
