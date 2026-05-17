# BeaconFlow 统一 triage 入口真实测试

## 测试题目：ISCC2026 re-手忙脚乱

### 基本信息

- **目标文件**：`D:\CTF\ISCC2026\guo\re-手忙脚乱\attachment-62.exe`
- **文件类型**：PE x64（自动检测）
- **测试命令**：
  ```powershell
  python -m beaconflow.cli triage --target "D:\CTF\ISCC2026\guo\re-手忙脚乱\attachment-62.exe" --output-dir "D:\project\test4\triage_auto_test" --stdin "AAAA" --timeout 180
  ```

### 输出结果

```json
{
  "status": "ok",
  "target": "D:\\CTF\\ISCC2026\\guo\\re-手忙脚乱\\attachment-62.exe",
  "artifacts": {
    "metadata": "D:\\project\\test4\\triage_auto_test\\metadata.json",
    "drcov": "D:\\project\\test4\\triage_auto_test\\drcov.attachment-62.exe.20728.0000.proc.log",
    "coverage": "D:\\project\\test4\\triage_auto_test\\coverage_report.json",
    "flow": "D:\\project\\test4\\triage_auto_test\\flow_report.json",
    "decision_points": "D:\\project\\test4\\triage_auto_test\\decision_points.json",
    "roles": "D:\\project\\test4\\triage_auto_test\\roles.json"
  },
  "errors": [],
  "next_steps": [
    "用 inspect-function 深入可疑函数",
    "用 trace-compare / trace-values 获取运行时比较值",
    "用 suggest-hook 生成 Frida hook 模板",
    "用 export-annotations 标注回 IDA/Ghidra"
  ]
}
```

### 自动检测过程

1. **文件类型检测**：读取文件头 magic bytes
   - 前 2 字节 = `MZ` → 识别为 PE 文件
   - 自动分发到 `triage-native` 工作流

2. **Ghidra metadata 导出**：148 个函数

3. **drcov 覆盖率采集**：使用 DynamoRIO 运行目标程序

4. **覆盖率分析**：统计覆盖的函数和基本块

5. **执行流分析**：恢复执行流

6. **决策点检测**：识别 cmp+jcc 等决策点

7. **角色检测**：识别 validator/input_handler 等角色

### 后续分析命令

```powershell
# 查看可疑函数
python -m beaconflow.cli inspect-function --metadata D:\project\test4\triage_auto_test\metadata.json --name check_flag

# 推荐 Frida hook
python -m beaconflow.cli suggest-hook --decision-points D:\project\test4\triage_auto_test\decision_points.json --roles D:\project\test4\triage_auto_test\roles.json

# 推荐 angr 求解
python -m beaconflow.cli suggest-angr --roles D:\project\test4\triage_auto_test\roles.json

# 推荐 GDB 断点
python -m beaconflow.cli suggest-debug --decision-points D:\project\test4\triage_auto_test\decision_points.json --debugger gdb --output bp.gdb

# 运行时追踪
python -m beaconflow.cli trace-calls --target "D:\CTF\ISCC2026\guo\re-手忙脚乱\attachment-62.exe" --stdin "AAAA"

# 生成 HTML 报告
python -m beaconflow.cli to-html --input D:\project\test4\triage_auto_test\coverage_report.json --input-format json --output D:\project\test4\triage_auto_test\coverage_report.html
```

---

## 文件类型自动检测支持

| 文件类型 | 检测方式 | 分发工作流 |
| --- | --- | --- |
| PE (.exe) | MZ magic | triage-native |
| ELF x86/x64 | 0x7fELF + e_machine | triage-native |
| ELF LoongArch/ARM/MIPS/RISC-V | 0x7fELF + e_machine | triage-qemu |
| WASM (.wasm) | \0asm magic | triage-wasm |
| Python (.pyc) | 后缀 + magic number | triage-pyc |
| APK (.apk) | 后缀 | 提示使用 import-jadx-summary |
| .so/.dll/.pyd | 内部 magic | triage-native |
| 未知格式 | - | 错误 + next_actions |
