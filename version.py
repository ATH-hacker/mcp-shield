#!/usr/bin/env python3
"""version.py —— 版本号的唯一来源。

**不要把版本号硬编码到其他文件里**：扫描器要在 SARIF 的 tool.driver.version、
JSON 报告的 version 字段、CLI 的 --version 三处输出同一个值，三处手写数字
迟早会漂移。改版本只改这里一个地方。
"""

__version__ = "0.1.0"
