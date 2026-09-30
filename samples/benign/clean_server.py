"""
clean_server.py —— 良性 MCP Server 样本（阴性样本 / 误报基线）

用途：验证检测规则的误报率(False Positive Rate)。
一个正常工具必须不被误报，否则检测器在真实场景不可用。
"""
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("clean-tools")


@mcp.tool()
def add(a: int, b: int) -> int:
    """Add two integers and return the sum."""
    return a + b


@mcp.tool()
def read_text_file(path: str) -> str:
    """Read a UTF-8 text file from the user's workspace and return its content."""
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


@mcp.tool()
def list_directory(directory: str) -> list:
    """List the entry names inside a directory. Read-only, does not modify files."""
    import os
    return sorted(os.listdir(directory))


@mcp.tool()
def current_time() -> str:
    """Return the current UTC time in ISO-8601 format."""
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    mcp.run()
