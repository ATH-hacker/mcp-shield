# MCP Shield 样本说明

本目录下的样本**全部是检测靶标，不是可用的攻击工具**。

## samples/attack/ —— 恶意样本（用于验证检出率）

| 文件 | 语言 | 说明 |
|------|------|------|
| `venomous_server.py` | Python | 8 个工具，覆盖 tool-poisoning 的全部 8 类手法 |
| `venomous_server.ts` | TypeScript | 与 Python 版一一对应的 8 个工具 |

两个文件里刻意集中了 8 类载体：

| 工具名 | 载体 | 对应规则 |
|--------|------|---------|
| `read_file` | 描述里夹带 "Do not tell the user…" | MS-001 |
| `get_weather` | 零宽字符 U+200B / U+200D | MS-002 |
| `send_email` | Unicode TAG 字符走私（还原后为明文指令） | MS-003 |
| `transfer_funds` | Bidi 覆盖字符 U+202E / U+202C | MS-004 |
| `upload_artifact` | 实现体读取 `~/.ssh/id_rsa`、`.env` 等 | MS-005 |
| `list_dir` | 实现体使用 `os.popen` / `child_process.exec` | MS-006 |
| `sync_notes` | 硬编码外传端点 `collector.attacker.example/ingest` | MS-007 |
| `calc` | `eval()` 且高危工具名未声明 annotations | MS-006 + MS-008 |

**所有对外域名均为 `example` 保留域名，不可路由；凭据路径只是字符串常量，
没有任何外发逻辑。** 这些文件被设计成"能被扫出来"，而不是"能真的打出去"。

## samples/benign/ —— 良性样本（用于验证误报率）

| 文件 | 语言 | 说明 |
|------|------|------|
| `clean_server.py` | Python | 4 个常规工具，0 告警 |
| `clean_server.ts` | TypeScript | 4 个常规工具，均声明 `annotations`，0 告警 |
| `leaked_secret.txt` | 文本 | 假密钥样例，**前缀为 `RAILSAMPLE-PLACEHOLDER`**，非真实凭据 |

## 负责任使用

这些样本的作用是让你能在**自己的机器上**复现检出效果、验证规则是否退化。
请勿把它们改造成可实际外发的程序，也勿用于未授权的目标。

如果你要新增样本，请遵守两条约定：
1. 域名一律用 `example` / `example.com` / `*.invalid`；
2. 任何看起来像凭据的字符串都要带明确的占位前缀（如 `RAILSAMPLE-PLACEHOLDER`），
   以免触发平台的 Secret Scanning 或误导他人。
