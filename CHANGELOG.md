# 更新日志

本项目遵循 [语义化版本](https://semver.org/lang/zh-CN/)，
格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)。

## [0.2.0] - 2026-10-02

### 新增

- **策略裁决层（BLOCK / WARN / PASS）** —— 把告警按「工具」聚合成三级处置建议：
  `scanner.policy_verdicts()` / `scanner.policy_summary()`。同时进入三处输出：
  控制台报告的「策略裁决」块、JSON 的 `policy` 段（含 `block_on` / `warn_on` /
  `summary` / `verdicts`）、SARIF 每条 result 的 `properties.mcpShieldVerdict`。
- CLI 新增 `--block-on` / `--warn-on`（严重度或规则号，逗号分隔），可把某几条规则
  单列为硬阻断，例如 `--block-on MS-003` 只拦「描述走私 TAG」。
- `mcp_shield.py config` 现在同时打印策略默认值；`config --json` 输出结构从裸规则表
  改为 `{"rules": ..., "policy": {...}}`。

### 修复

- **文档声称的三级裁决层在代码里不存在。** v0.1.0 的 README 与作品报告都把
  BLOCK / WARN / PASS 写成「系统的裁决层」，并描述成「命中 ERROR 即不返回给模型、
  要求重新授权」——但全树搜索显示该字段只出现在 Web 控制台展示层
  （`scripts/ui_server.py`），`scan --json` 与 SARIF 里都没有，CLI 里更没有一个
  地方算过它。这是典型的「文档写了、代码没做」：最容易在对照代码时被当场抓住。
  现在两个方向都改了：**裁决真的算出来了**，并且**删掉了所有「运行时拦截」
  的描述** —— MCP Shield 不在 Agent 的调用路径上，它给的是处置建议，
  由集成方接到 CI 门禁、准入检查或工单流。
- **`--out` 文档口径**：`build_release.py` 打印的下一步仍在硬编码 `v0.1.0`，改为读
  `version.__version__`；`probe_client.py` 的 `clientInfo.version` 也从字面量改为读
  同一来源。

### 说明

三级裁决有一条底线：**只要命中过任何一条规则，最低也是 WARN。**
`PASS` 的含义严格限定为「这个工具完全没有命中任何规则」，
绝不用来表示「我们没看懂」—— 这与 v0.1.0 修掉的「扫不动被当成干净」是同一类错误的
另一个入口：一个「有 6 条 ERROR 却写着 PASS」的工具会误导使用者。

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
- **测试** `tests/test_scanner.py` —— 30 个 unittest 用例，含「零第三方依赖」的
  AST 静态断言、CLI 契约断言，以及「扫不动 ≠ 干净」的退出码断言。
- **发布前自检** `verify_release.py` —— 35 项端到端检查，重新计算所有对外声明的数字。
- **本地可视化控制台** `scripts/ui_server.py` + `ui/console.html` ——
  三栏对照「人眼所见 / 线上报文 / 模型读到的东西」，含五页签与运行层取证实录。
- **CI** `.github/workflows/tests.yml` —— Linux + Windows，Python 3.10/3.11/3.12 矩阵。

### 修复

发布前做了一轮「专挑没跑过的路径」的破坏性自检，抓到并修掉 5 个真实缺陷
（前 4 个在那轮自检里露头，第 5 个在随后打包时才露头）：

- **`probe --out` 直接崩溃**（`OSError: [WinError 193] %1 不是有效的 Win32 应用程序`）。
  根因：`run_forensics()` 里保留了一份「只替换 `python`/`python3`/`py`」的旧判断，
  而 `_pin_interpreter()` 后来补上了「裸 `.py` 脚本自动补解释器」的分支 ——
  于是 `probe samples/attack/venomous_server.py --out x.jsonl` 会拿 `.py` 文件
  直接去 `CreateProcess`。修法：统一走 `_pin_interpreter()`。
  教训：同一件事只能有一处实现。
- **`probe_client.py --out` 写在 Server 命令之后会被静默吞掉**（`nargs=REMAINDER`
  把后续所有参数都收进 `server` 列表），用户看到「明明指定了路径却没落盘」。
  修法：`--out` 默认改为 `None`，并兜底捡回末位以 `.jsonl` 结尾的参数，
  同时在未指定时明确打印默认落盘路径。
- **「扫不动」被当成「干净」**：语法解析失败的文件只往 stderr 打个提示就返回退出码
  `0`，攻击者只要交一个解析不了的文件，CI 就会绿着放过它。修法：新增退出码 `2`
  （扫描未完成），报告头显式打印 `解析失败: N 个文件 —— 这些文件的内容【未被检查】`。
  目标不存在、语言过滤后无目标同样返回 `2`。
- **`tsjs_scanner.py --version` 触发 `NameError`**：用到了 `__version__` 却没 import。
- **打包工具把自己的占位符也替换掉了**：`build_release.py` 的 `_replace_placeholder()`
  用 `os.walk` 遍历全部文件，把工具自身第 29 行的 `PLACEHOLDER` 常量一起替换成了用户名 ——
  于是发给别人的构建脚本里写死了一个账号，再跑 `--user X` 还会退化成「把上一个用户名
  换成 X」。修法：跳过自身文件，并在注释里写明原因。

同时清掉了 `tests/` 里 3 处未关闭文件的 `ResourceWarning`（改为 `with open(...)`）。

### 测试与 CI 的一处诚实化

运行层用例要真的拉起样本 Server，而样本 Server 依赖官方 MCP SDK ——
它不是扫描器的依赖，只是**被测对象**的依赖。原来的 `test` 作业在「不装任何第三方包」
的环境里跑，于是这 2 个用例直接报 `ModuleNotFoundError: No module named 'mcp'` 失败。
现在拆成两件事：

- 扫描相关用例继续在**什么都没装**的环境里跑（这才是「零第三方依赖」的证明）；
- 运行层 2 个用例在没有 `mcp` 时**显式 skipped 并写明原因**，不静默通过；
- CI 新增 `runlayer` 作业，装上 `mcp<2` 专门跑运行层与 35 项端到端自检。

两边都不含糊：既不假装测过，也不让零依赖的证明被污染。

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
