import asyncio
import os
import shutil
import sys
from contextlib import AsyncExitStack
from typing import Any, Dict, List, Optional

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from sentinel.models import ToolDefinition


class MCPClientAdapter:
    """Universal adapter to interact with MCP servers across transports (stdio / sse) with connection reuse."""

    def __init__(self, command: Optional[str] = None, args: Optional[List[str]] = None, env: Optional[Dict[str, str]] = None, sse_url: Optional[str] = None):
        self.command = command
        self.args = args or []
        self.env = {**os.environ, **(env or {})}
        self.sse_url = sse_url
        self._session: Optional[ClientSession] = None
        self._exit_stack: Optional[AsyncExitStack] = None

    async def start(self) -> ClientSession:
        """Starts the persistent stdio subprocess connection."""
        if not self.command:
            raise ValueError("No command specified for stdio transport")

        if self._session is not None:
            return self._session

        server_params = StdioServerParameters(
            command=self.command,
            args=self.args,
            env=self.env,
        )

        self._exit_stack = AsyncExitStack()
        read_stream, write_stream = await self._exit_stack.enter_async_context(
            stdio_client(server_params)
        )
        session = await self._exit_stack.enter_async_context(
            ClientSession(read_stream, write_stream)
        )
        await session.initialize()
        self._session = session
        return self._session

    async def close(self):
        """Closes the active connection and terminates the subprocess."""
        if self._exit_stack:
            try:
                await self._exit_stack.aclose()
            except Exception:
                pass
            self._exit_stack = None
            self._session = None

    async def connect_and_list_tools(self) -> List[ToolDefinition]:
        """Lists registered tool definitions using the persistent session."""
        session = await self.start()
        response = await session.list_tools()

        tools: List[ToolDefinition] = []
        for tool in response.tools:
            tools.append(
                ToolDefinition(
                    name=tool.name,
                    description=tool.description or "",
                    input_schema=tool.inputSchema if hasattr(tool, "inputSchema") and tool.inputSchema else (tool.input_schema if hasattr(tool, "input_schema") and tool.input_schema else {}),
                )
            )
        return tools

    async def call_tool_stdio(self, tool_name: str, arguments: Dict[str, Any], timeout: float = 8.0) -> Any:
        """Executes a tool call over the persistent connection."""
        session = await self.start()
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
