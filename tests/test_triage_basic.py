"""Verify triage detection and partial report behavior."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

from beaconflow.triage import _detect_target_type, triage


class TestDetectTargetType(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def _write(self, name: str, data: bytes) -> Path:
        p = Path(self.tmpdir) / name
        p.write_bytes(data)
        return p

    def test_nonexistent_file_returns_unknown(self):
        info = _detect_target_type(Path("nonexistent_file_12345.exe"))
        self.assertEqual(info.get("type"), "unknown")
        self.assertIn("error", info)

    def test_pe_detection(self):
        p = self._write("test.exe", b"MZ" + b"\x00" * 126)
        info = _detect_target_type(p)
        self.assertEqual(info.get("type"), "pe")

    def test_elf_detection(self):
        p = self._write("test.elf", b"\x7fELF" + b"\x00" * 60)
        info = _detect_target_type(p)
        self.assertEqual(info.get("type"), "elf")

    def test_wasm_detection(self):
        p = self._write("test.wasm", b"\x00asm" + b"\x01\x00\x00\x00")
        info = _detect_target_type(p)
        self.assertEqual(info.get("type"), "wasm")

    def test_json_not_misdetected_as_pyc(self):
        p = self._write("test.json", b'{"key": "value"}')
        info = _detect_target_type(p)
        self.assertNotEqual(info.get("type"), "pyc")

    def test_apk_detection(self):
        p = self._write("test.apk", b"PK" + b"\x00" * 100)
        info = _detect_target_type(p)
        self.assertEqual(info.get("type"), "apk")


class TestTriagePartialReport(unittest.TestCase):
    def test_triage_nonexistent_returns_error(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            result = triage(
                target_path=Path(tmpdir) / "nonexistent_12345.exe",
                output_dir=tmpdir,
            )
            self.assertIn(result.get("status"), ("error", "partial"))


if __name__ == "__main__":
    unittest.main()
