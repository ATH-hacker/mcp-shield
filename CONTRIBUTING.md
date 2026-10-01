# 贡献指南

感谢你有兴趣改进 MCP Shield。这个项目最欢迎的是**检测能力**方面的贡献。

## 环境要求

- Python **3.10+**（用到 `X | Y` 类型注解与 `sys.stdlib_module_names`）
- 不需要 `pip install` 任何东西即可运行核心功能

```bash
git clone https://github.com/zjt20070101/mcp-shield
cd mcp-shield
python -m unittest discover -s tests -v      # 30 个用例应全绿（缺 MCP SDK 时 skip 2 个运行层用例）
python verify_release.py                     # 35 项自检应全通过
```

## 硬性约定

提交 PR 前请确认：

1. **核心模块零第三方依赖。** `scanner.py` / `tsjs_scanner.py` / `probe_client.py` /
   `mcp_shield.py` 只能 import 标准库。`tests/test_scanner.py::TestZeroDependency`
   会失败并指名道姓告诉你违规的模块名。
2. **新增规则必须两套实现都加。** Python 侧加进 `scanner.py`，TS/JS 侧加进
   `tsjs_scanner.py`，同时更新 `rules/*.yaml`。两侧告警码语义必须一致。
3. **不要改对外声明的数字而不改测试。** 告警总数、ERROR/WARNING 分布这类数字
   同时写在 `tests/test_scanner.py`、`verify_release.py` 和 `README.md` 里。
   规则一改就会红 —— 这是故意的，请同步更新三处。
4. **样本必须使用保留域名。** 新增攻击样本时，域名一律用
   `example` / `example.com` / `*.invalid`；任何像凭据的字符串都要带明确占位前缀
   （如 `RAILSAMPLE-PLACEHOLDER`）。`verify_release.py` 会扫描并拦下违规。
5. **不要写「首个 / 唯一 / 业界领先」。** 见 README「明确不声称的事」。

## 最欢迎的贡献类型

### 1. 绕过样本（最有价值）

如果你发现某种手法能骗过当前检测，请开 Issue，标题以 `[detection-gap]` 开头，
附上最小复现片段。对检测工具来说，被绕过的样本比赞美有价值得多。

### 2. 新的攻击载体

MCP 工具投毒的形态还在演化。已知但尚未覆盖的方向包括：

- 描述里的同形字 / 混合脚本欺骗（homoglyph）
- 通过 `inputSchema` 的字段描述夹带指令（当前只扫工具级 description）
- 多轮 Rug Pull：同一工具先干净、后投毒（需要运行层时间序列比对）
- 通过工具返回值投毒（当前只覆盖工具定义）

### 3. 规则精度

误报和漏报同样值得修。如果你有真实世界的 MCP Server 代码，跑一遍
`python mcp_shield.py scan <你的目录>` 并把误报贴出来，非常有帮助。

## 代码风格

- 缩进 4 空格，行长建议 100 字符内
- 类型注解能加就加（本项目大量使用 `from __future__ import annotations`）
- **注释解释「为什么」，不解释「是什么」。** 这个项目里所有非平凡的取舍
  （为什么用括号栈、为什么 MS-008 要看整个对象、为什么两套扫描器不合并结果）
  都写在注释里，请保持这个习惯。
- 中文注释是这个项目的既定风格，请继续使用。

## 提交信息

用简短的祈使句，说明**改了什么**与**为什么**：

```
修复 MS-008 对裸键 name 的误判

RE_TOOL_NAME_KEYS 的可选引号组后面直接跟冒号，导致 `name:` 这种
不带引号的键永远失配。改为显式匹配两种情况。
```

## 许可

提交贡献即表示你同意以 [Apache-2.0](LICENSE) 许可发布你的贡献。
