# reports/

扫描产物目录。这里**刻意不提交**具体报告文件 —— 它们随时可重新生成，
且内容会随规则演进变化。生成方式：

```bash
python scanner.py samples/attack/venomous_server.py \
    --json reports/scan_attack.json --sarif reports/scan_attack.sarif
python mcp_shield.py probe samples/attack/venomous_server.py \
    --out reports/traffic_attack.jsonl
```
