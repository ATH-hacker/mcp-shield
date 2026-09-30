# 更新日志

本项目遵循 [语义化版本](https://semver.org/lang/zh-CN/)，
格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)。

## [0.1.0] - 2026-09-30

首个公开版本。定位：面向 MCP / Agent 工具链的投毒检测与运行时防护网关。

### 新增

- **静态扫描（Python）** `scanner.py` —— 基于 `ast` 精确关联「工具名 → 描述 → 实现体」，
  零第三方依赖。
- **静态扫描（TS/JS）** `tsjs_scanner.py` —— 文本层状态机，覆盖 `registerTool` /
  `server.tool` / `setRequestHandler(ListTools)` 三种注册形态，与 Python 侧共用
  同一套告警码（MS-001..MS-008）。
- **8 条检测规则**：MS-001 描述隐瞒指令 / MS-002 零宽字符 / MS-003 Unicode TAG 走私 /
  MS-004 Bidi 覆盖 / MS-005 敏感凭据路径 / MS-006 危险执行原语 /
  MS-007 硬编码外传端点 / MS-008 未声明 annotations。全部映射 OWASP LLM Top 10。
- **双模态检测**：同时识别**真实不可见码点**与**字面转义序列**（`\u200b` 等）。
  这是 v0.1.0 开发中的真实教训 —— 首版对转义形态全部漏报。
- **Unicode TAG 可逆还原**：`chr(cp - 0xE0000)` 还原攻击者夹带的明文指令。
- **运行层取证** `probe_client.py` —— 零依赖 MCP stdio 客户端，真的拉起 Server
  抓 `tools/list`，逐码点解剖并向 JSONL 落盘原始报文。
- **统一 CLI** `mcp_shield.py` —— `scan` / `probe` / `config` 三个子命令。
- **SARIF 2.1.0 输出**，含 `partialFingerprints`，可接 GitHub Code Scanning。
- **semgrep 规则集** `rules/mcp-python.yaml`（8 条）、`rules/mcp-typescript.yaml`（7 条），
  与本实现语义一一对应。
- **恶意/良性样本集** `samples/` —— 8 个恶意工具 + 4 个良性工具，Python 与 TS 双语各一套。
- **测试** `tests/test_scanner.py` —— 21 个 unittest 用例，含「零第三方依赖」的
  AST 静态断言与 CLI 契约断言。
- **发布前自检** `verify_release.py` —— 25 项端到端检查，重新计算所有对外声明的数字。
- **本地可视化控制台** `scripts/ui_server.py` + `ui/console.html` ——
  三栏对照「人眼所见 / 线上报文 / 模型读到的东西」，含五页签与运行层取证实录。
- **CI** `.github/workflows/tests.yml` —— Linux + Windows，Python 3.10/3.11/3.12 矩阵。

### 实测结果

| 样本 | 语言 | 工具数 | 告警 | ERROR/WARNING |
|------|------|-------:|-----:|--------------:|
| `samples/attack/venomous_server.py` | Python | 8 | 17 | 11 / 6 |
| `samples/attack/venomous_server.ts` | TypeScript | 8 | 14 | — |
| `samples/benign/clean_server.py` | Python | 4 | 0 | 0 / 0 |
| `samples/benign/clean_server.ts` | TypeScript | 4 | 0 | 0 / 0 |

运行层取证：8 个工具中 3 个（`get_weather` / `send_email` / `transfer_funds`）
携带不可见字符，与静态层独立得出的结论一致。

### 已知局限

- TS/JS 为文本层近似，非完整语法分析。
- 运行时动态拼接的载荷静态层不可见。
- 样本集规模有限（8 恶意 + 4 良性），属设计验证而非统计评测。
- 针对 MCP 规范 `2024-11-05` 编写。

见 [SECURITY.md](SECURITY.md) 的「已知的能力边界」。

### 说明

本项目不做「首个 / 唯一 / 业界领先」类宣称。同机实测表明，用 Semgrep 1.178.0 +
本项目自写的同一套规则也能得到 17 条命中 / 0 误报；差异在于规则颗粒度与运行层能力，
而非「只有我们能做」。详见 README 的「明确不声称的事」。
