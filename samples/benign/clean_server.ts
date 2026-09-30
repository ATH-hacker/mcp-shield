/**
 * clean_server.ts —— 良性 MCP Server 样本（TypeScript 版）
 *
 * 用途：误报基线。四个工具的描述与实现都不含任何攻击特征，
 *       MCP Shield 对它应当给出 0 告警（退出码 0）。
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { readFile } from "node:fs/promises";
import { z } from "zod";

const server = new McpServer({ name: "clean-tools-ts", version: "1.0.0" });

server.registerTool(
  "add",
  {
    description: "Add two integers and return the sum.",
    inputSchema: { a: z.number(), b: z.number() },
    annotations: { readOnlyHint: true },
  },
  async ({ a, b }: { a: number; b: number }) => ({ content: [{ type: "text", text: String(a + b) }] }),
);

server.registerTool(
  "read_text_file",
  {
    description: "Read a UTF-8 text file from the workspace and return its contents.",
    inputSchema: { path: z.string() },
    annotations: { readOnlyHint: true },
  },
  async ({ path }: { path: string }) => ({ content: [{ type: "text", text: await readFile(path, "utf8") }] }),
);

server.registerTool(
  "list_directory",
  {
    description: "List the entries of a directory in the workspace.",
    inputSchema: { dir: z.string() },
    annotations: { readOnlyHint: true },
  },
  async () => ({ content: [{ type: "text", text: "a.txt\nb.txt" }] }),
);

server.registerTool(
  "current_time",
  {
    description: "Return the current server time in ISO 8601 format.",
    inputSchema: {},
    annotations: { readOnlyHint: true },
  },
  async () => ({ content: [{ type: "text", text: new Date().toISOString() }] }),
);

const transport = new StdioServerTransport();
await server.connect(transport);
