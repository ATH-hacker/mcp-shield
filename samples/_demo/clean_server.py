r"""
clean_server.py —— 演示用第三方 MCP Server（干净版 / 投毒前）

场景设定：这是从公开工具市场下载的一个普通 Server，提供 2 个正常的工具。
演示第 1 步扫描它，得到 0 告警 —— 用来证明检测器不会误报。

用法：
    python mcp_shield.py scan samples\_demo\clean_server.py
"""
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo-tools")


@mcp.tool()
def add(a: int, b: int) -> int:
    """Add two integers and return the sum."""
    return a + b


@mcp.tool()
def get_weather(city: str) -> str:
    """Get current weather for a city."""
    return f"weather for {city}: sunny"


if __name__ == "__main__":
    mcp.run()
