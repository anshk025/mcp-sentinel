import asyncio
import json
import os
import shutil
import sys
from typing import Any, Dict, List, Optional
from pydantic import BaseModel

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from sentinel.models import ToolDefinition


class MCPClientAdapter:
    """Universal adapter to interact with MCP servers across transports (stdio / sse)."""

    def __init__(self, command: Optional[str] = None, args: Optional[List[str]] = None, env: Optional[Dict[str, str]] = None, sse_url: Optional[str] = None):
        self.command = command
        self.args = args or []
        self.env = {**os.environ, **(env or {})}
        self.sse_url = sse_url
        self._session: Optional[ClientSession] = None
        self._exit_stack = None

    async def connect_and_list_tools(self) -> List[ToolDefinition]:
        """Connects via stdio and extracts registered tool definitions."""
        if not self.command:
            raise ValueError("No command specified for stdio transport")

        server_params = StdioServerParameters(
            command=self.command,
            args=self.args,
            env=self.env,
        )

        tools: List[ToolDefinition] = []

        async with stdio_client(server_params) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                response = await session.list_tools()

                for tool in response.tools:
                    tools.append(
                        ToolDefinition(
                            name=tool.name,
                            description=tool.description or "",
                            input_schema=tool.inputSchema if hasattr(tool, "inputSchema") and tool.inputSchema else (tool.input_schema if hasattr(tool, "input_schema") and tool.input_schema else {}),
                        )
                    )

        return tools

    async def call_tool_stdio(self, tool_name: str, arguments: Dict[str, Any], timeout: float = 10.0) -> Any:
        """Executes a single tool call against stdio target and returns the raw response."""
        if not self.command:
            raise ValueError("No command specified for stdio transport")

        server_params = StdioServerParameters(
            command=self.command,
            args=self.args,
            env=self.env,
        )

        async with stdio_client(server_params) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                try:
                    result = await asyncio.wait_for(
                        session.call_tool(tool_name, arguments=arguments),
                        timeout=timeout,
                    )
                    return result
                except asyncio.TimeoutError:
                    return {"error": "Tool call timed out"}
                except Exception as e:
                    return {"error": str(e)}
