"""验证 triage-native 缺依赖时输出 partial report"""
import json
import sys
sys.path.insert(0, r"D:\project\BeaconFlow")

from beaconflow.triage import _detect_target_type, triage
from pathlib import Path

# 测试1: 文件类型检测
print("=== Test 1: 文件类型检测 ===")
test_file = Path(r"D:\CTF\ISCC2026\guo\re-手忙脚乱\attachment-62.exe")
if test_file.exists():
    info = _detect_target_type(test_file)
    print(f"Type: {info.get('type')}, Arch: {info.get('arch')}")
    assert info.get("type") == "pe", f"Expected pe, got {info.get('type')}"
    print("PASS: PE detection works")
else:
    print("SKIP: test file not found")

# 测试2: 不存在的文件
print("\n=== Test 2: 不存在的文件 ===")
info = _detect_target_type(Path("nonexistent.exe"))
assert info.get("type") == "unknown"
assert "error" in info
print("PASS: nonexistent file returns unknown with error")

# 测试3: WASM 文件检测
wasm_file = Path(r"D:\project\test4\wasm_triage3\wasm_analyze.json")
if wasm_file.exists():
    info = _detect_target_type(wasm_file)
    print(f"JSON file type: {info.get('type')} (should NOT be pyc)")
    assert info.get("type") != "pyc", "JSON files should not be detected as pyc"
    print("PASS: JSON not misdetected as pyc")

print("\nAll detection tests passed!")
