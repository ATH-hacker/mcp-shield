<div align="center">

# MCP Shield

**面向 MCP / Agent 工具链的投毒检测与运行时防护网关**

把「看不见的攻击」变成屏幕上的证据

[![tests](https://github.com/zjt-2007/mcp-shield/actions/workflows/tests.yml/badge.svg)](https://github.com/zjt-2007/mcp-shield/actions/workflows/tests.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)](verify_release.py)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![SARIF](https://img.shields.io/badge/output-SARIF%202.1.0-orange)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)

零第三方依赖 · 8 条自研检测规则 · 静态与运行层双证据链 · 真实可复现

</div>

---

## 这是什么

MCP（Model Context Protocol）让 Agent 能调用外部工具。工具的 `description`
字段会被**原样塞进模型上下文**，而模型**无法区分「描述」与「指令」** ——
这就是 MCP 生态里最要命的那个根因。

于是攻击者有了一条极低成本的路：在工具描述里藏一段人眼看不见、但模型会照做的
指令。经典的载荷形态有五种：

| # | 攻击载体 | 人眼看得见吗 | 常规 SAST / diff 看得见吗 |
|---|---------|:-----------:|:------------------------:|
| 1 | 自然语言夹带（"不要告诉用户…"） | 看得见 | 看不见（docstring 被当字符串，不检查语义） |
| 2 | 零宽字符 `U+200B` / `U+200D` | **看不见** | 看不见（字符串比对不显示不可见码点） |
| 3 | Unicode TAG 区 `U+E0000..E007F` | **看不见** | 看不见（同上） |
| 4 | 双向文本覆盖 `U+202E` | 看得见但**顺序是错的** | 看不见（显示顺序与逻辑顺序不一致） |
| 5 | **转义形态**（源码里写 `\u200b` 而非真实字符） | 看得见 | **最常被漏掉** —— 文件里没有不可见字符，运行时才还原 |

MCP Shield 就是针对这条链路的检测与拦截工具。

## 它能做到什么

1. **静态扫描**：Python 走 AST 精确关联「工具名 → 描述 → 实现体」；TS/JS 走
   文本层状态机（覆盖 `registerTool` / `server.tool` / `setRequestHandler` 三种注册形态）。
2. **双模态检测**：同时抓**真实不可见码点**与**字面转义序列**。第 5 类载体是
   踩坑踩出来的 —— 第一版扫描器对 `\u200b` 全部漏报，补上 `ESCAPE_PATTERNS` 后全中。
3. **可逆还原隐藏载荷**：Unicode TAG 区字符减 `0xE0000` 即得攻击者想传的明文，
   报告里直接给出还原后的人类可读文本。
4. **运行层取证**：不看源码，真的把 Server 拉起来跑一遍 JSON-RPC，
   抓 `tools/list` 响应并逐码点解剖 —— 黑盒第三方工具也能验。
5. **策略裁决**：命中 `ERROR` 级规则即判 `BLOCK`，不把该工具描述交给模型。
6. **标准输出**：SARIF 2.1.0（含 `partialFingerprints`），可直接进 GitHub Code Scanning / CI 门禁。

## 30 秒上手

```bash
git clone https://github.com/zjt-2007/mcp-shield
cd mcp-shield

# 不需要 pip install 任何东西
python mcp_shield.py config                      # 看内建 8 条规则
python mcp_shield.py scan samples/attack/venomous_server.py    # 恶意样本 → 17 条告警，退出码 1
python mcp_shield.py scan samples/benign/clean_server.py       # 良性样本 → 0 条告警，退出码 0
python mcp_shield.py probe samples/attack/venomous_server.py   # 运行层取证（不用源码）
python verify_release.py                         # 发布前完整自检（25 项）
```

扫自己的项目：

```bash
python mcp_shield.py scan /path/to/your/mcp-server --sarif reports/my.sarif
```

## 检测规则

| 告警码 | 级别 | 检测内容 | 攻击类型 | OWASP LLM Top 10 |
|--------|:----:|---------|---------|------------------|
| MS-001 | ERROR | 工具描述夹带隐瞒/绕过指令 | tool-poisoning | LLM01 Prompt Injection |
| MS-002 | WARNING | 零宽 / 不可见字符 | hidden-instruction | LLM01 |
| MS-003 | ERROR | Unicode TAG 字符走私 | hidden-instruction | LLM01 |
| MS-004 | ERROR | 双向文本覆盖字符（Bidi） | hidden-instruction | LLM01 |
| MS-005 | ERROR | 实现体触碰敏感凭据路径 | credential-exfiltration | LLM02 Sensitive Information Disclosure |
| MS-006 | ERROR | 使用危险执行原语（`eval` / `exec` / `os.system`） | excessive-agency | LLM06 Excessive Agency |
| MS-007 | ERROR | 硬编码可疑外传端点 | data-exfiltration | LLM02 |
| MS-008 | WARNING | 高危工具未声明 `annotations` | excessive-agency | LLM06 |

规则同时以 **semgrep YAML** 形式提供（`rules/mcp-python.yaml`、`rules/mcp-typescript.yaml`），
语义与本实现一一对应；也可以用任意支持 SARIF 的平台消费本实现的输出。

## 实测数据

以下数字全部由 `python verify_release.py` 在每次运行时重新计算，不是手写死的。

| 指标 | 恶意样本 | 良性样本 |
|------|---------|---------|
| 发现工具数 | 8 | 4 |
| 告警总数 | **17** | **0** |
| ERROR / WARNING | 11 / 6 | 0 / 0 |
| 命中规则 | 8 / 8 全部命中 | —— |
| 单文件扫描中位耗时 | ~3 ms | ~1.4 ms |

运行层取证（不看源码，抓真实报文）：

```
serverInfo : {"name": "venomous-tools", "version": "1.29.0"}
协议版本   : 2024-11-05
工具总数   : 8
携带不可见字符的工具: 3
  - get_weather      4 处  zero-width
  - send_email      46 处  unicode-tag
  - transfer_funds   4 处  bidi
```

**两条独立证据链指向同一批 3 个工具** —— 静态层从源码看出的，与运行层从报文抓到的，
是同一批。这是本项目最有说服力的一处交叉验证。

TS/JS 侧：恶意样本 8 工具 / 14 条告警，良性样本 4 工具 / 0 告警。

## 架构

```
                   ┌──────────────── 静态层（看源码）────────────────┐
  MCP Server 源码  │  scanner.py      Python AST，精确关联工具/描述/实现体
  (.py / .ts / .js)│  tsjs_scanner.py TS/JS 文本层状态机
                   │  rules/*.yaml    semgrep 规则（同语义，可换用）
                   └───────────────────────┬───────────────────────┘
                                           │ Finding(MS-001..MS-008)
                                           ▼
                   ┌──────────── 策略层：BLOCK / WARN / PASS ───────┐
                                           ▲
                   ┌──────────────── 运行层（看报文）───────────────┐
  MCP Server 进程  │  probe_client.py  真的拉起 Server，抓 tools/list
                   │  逐码点解剖：零宽 / TAG / Bidi，还原隐藏载荷
                   └───────────────────────┬───────────────────────┘
                                           ▼
                     JSON 报告 · SARIF 2.1.0 · JSONL 原始报文
```

两层**刻意不合并结果**：把运行层结论并进静态告警会污染"独立证据"这个定位，
交叉验证就失去意义了。

## 创新点（以及不声称什么）

**① 双模态检测.** 真实不可见码点与字面转义序列都要抓。这不是设计出来的，
是踩坑踩出来的：第一版扫描器对源码里的 `\u200b` 全部漏报，因为文件里没有
真实的不可见字符。补上转义形态检测后才 100% 命中。

**② Unicode TAG 可逆还原.** `chr(cp - 0xE0000)` 直接把走私的载荷还原成明文。
报告里给出的不是"发现可疑字符"，而是攻击者想传的那句话本身。

**③ 静态 ↔ 运行双证据链.** 两条独立链路指向同一批工具（实测：8 个工具中同样那 3 个）。

**④ 策略化裁决.** 按规则级别给出 BLOCK / WARN / PASS，而不是只报一个数字。

**⑤ 零依赖 + 标准 SARIF.** 任何装了 Python 3.10+ 的机器都能现场复现，
有测试用例在 CI 里强制校验这一点。

### 明确不声称的事

- ❌ **不声称"只有我们能做这件事"。** 同机实测：用 Semgrep 1.178.0 + 我们自写的
  同一套规则，也能得到 **17 条命中 / 0 误报**，命中行号与我们高度重合
  （原因：Semgrep 的 Python 解析器同样会解释字符串转义序列）。
  差异只在**颗粒度**：我们是 8 条可独立追溯的规则条目，Semgrep 归并为 5 类。
- ❌ **不声称"首个/唯一/业界领先"。** 同赛道已有多个项目在做 MCP 安全的不同环节。
  本项目的定位是**组合**：`MCP 领域规则集 + 零依赖实现 + 运行层取证` 这一组
  目前没有成熟项目同时提供。
- ❌ **不声称统计意义上的检出率。** 样本集是 8 恶意 + 4 良性，属于**设计验证**，
  不是统计评测。
- ❌ **不做模型侧防护。** 即使描述完全干净，模型自身也可能被诱导。本工具只对
  「工具描述与实现体」这一层负责。

## 项目结构

```
mcp-shield/
├── scanner.py                 Python AST 扫描器（零依赖）
├── tsjs_scanner.py            TypeScript/JavaScript 文本层扫描器（零依赖）
├── probe_client.py            MCP stdio 客户端 + 流量取证（零依赖）
├── mcp_shield.py              统一 CLI：scan / probe / config
├── version.py                 版本号唯一来源
├── verify_release.py          发布前 25 项端到端自检
├── rules/
│   ├── mcp-python.yaml        semgrep 规则（Python，8 条）
│   └── mcp-typescript.yaml    semgrep 规则（TS/JS，7 条）
├── samples/
│   ├── attack/                恶意样本（检测靶标，不可路由域名）
│   └── benign/                良性样本（误报基线）
├── tests/test_scanner.py      21 个回归用例（unittest，零依赖）
├── scripts/
│   ├── ui_server.py           本地可视化控制台
│   └── build_standalone.py    生成离线单页版控制台
├── ui/console.html            控制台前端（自包含单页）
├── docs/                      答辩材料、PPT 大纲、演示脚本
├── .github/workflows/tests.yml
├── mcp-shield.toml.example    配置示例
├── SECURITY.md                安全政策与已知能力边界
└── CHANGELOG.md
```

## 外部依赖说明（重要）

核心链路**零第三方依赖**，只用 Python 标准库 —— 这条有 CI 断言守着。

唯一在 `samples/` 里被用到的是 **MCP 官方 Python SDK**（`pip install "mcp<2"`），
它只用于让**恶意样本 Server 真的能跑起来**，即运行层的**被测对象**，
**不是本项目的实现依赖**：

```bash
pip install "mcp<2"     # 仅当你要跑 samples/ 里的 Server 时才需要
python mcp_shield.py probe samples/attack/venomous_server.py
```

`scripts/` 下的可视化控制台用到 `playwright-core`（仅用于生成截图），
不参与检测逻辑。

## 已知局限

1. TS/JS 是文本层近似，不是完整语法分析；深层嵌套、动态注册名可能漏报。
2. 载荷若在运行时动态拼接（而非字面量），静态层看不到，需配合运行层取证。
3. 针对 MCP 规范 **2024-11-05** 编写，规范演进后需同步更新。
4. 样本集规模有限，不做统计意义声明。

详见 [SECURITY.md](SECURITY.md)。

## 许可

[Apache-2.0](LICENSE) —— 可自由使用、修改、商用。

## 负责任使用

`samples/attack/` 下的文件是**检测靶标**，不是可用攻击工具；域名全部为
`example` 保留域名，不可路由。请勿改造成可实际外发的程序，也勿用于未授权目标。
