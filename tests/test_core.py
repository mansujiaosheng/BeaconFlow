from __future__ import annotations

import json
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from beaconflow.analysis import deflatten_flow, diff_flow, rank_input_branches
from beaconflow.analysis.ai_digest import compact_report, infer_report_kind
from beaconflow.address_range import detect_executable_address_range
from beaconflow.cli import _mutated_inputs, _parse_mutate_positions, _seed_from_mutate_format
from beaconflow.coverage import load_address_log, load_drcov
from beaconflow.mcp.server import TOOLS
from beaconflow.models import BasicBlock, CoverageBlock, CoverageData, Function, ProgramMetadata


def _metadata() -> ProgramMetadata:
    blocks = (
        BasicBlock(0x1000, 0x1004, (0x1010, 0x1020)),
        BasicBlock(0x1010, 0x1014, (0x1030,)),
        BasicBlock(0x1020, 0x1024, (0x1030,)),
        BasicBlock(0x1030, 0x1034, ()),
    )
    return ProgramMetadata(
        input_path="target.exe",
        image_base=0,
        functions=(Function("check", 0x1000, 0x1040, blocks),),
    )


def _coverage(addresses: list[int]) -> CoverageData:
    return CoverageData(
        modules={},
        blocks=[CoverageBlock(module_id=0, offset=address, size=4, absolute_start=address) for address in addresses],
    )


def _loop_metadata() -> ProgramMetadata:
    blocks = (
        BasicBlock(0x1000, 0x1004, (0x1010,)),
        BasicBlock(0x1010, 0x1014, (0x1000, 0x1020)),
        BasicBlock(0x1020, 0x1024, ()),
    )
    return ProgramMetadata(
        input_path="loop.exe",
        image_base=0,
        functions=(Function("loop", 0x1000, 0x1030, blocks),),
    )


class ParserTests(unittest.TestCase):
    def test_elf_executable_load_range_detection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "target.elf"
            ident = b"\x7fELF" + bytes([2, 1, 1]) + b"\x00" * 9
            header = struct.pack(
                "<16sHHIQQQIHHHHHH",
                ident,
                2,
                0x3e,
                1,
                0x401000,
                0x40,
                0,
                0,
                0x40,
                0x38,
                2,
                0,
                0,
                0,
            )
            exec_load = struct.pack("<IIQQQQQQ", 1, 5, 0x1000, 0x401000, 0x401000, 0x200, 0x300, 0x1000)
            data_load = struct.pack("<IIQQQQQQ", 1, 6, 0x2000, 0x404000, 0x404000, 0x100, 0x100, 0x1000)
            path.write_bytes(header + exec_load + data_load)

            result = detect_executable_address_range(path)
            self.assertEqual(result["status"], "ok")
            self.assertEqual(result["address_min"], "0x401000")
            self.assertEqual(result["address_max"], "0x401300")

    def test_qemu_address_log_parser_supports_common_formats(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "qemu.log"
            path.write_text(
                "\n".join(
                    [
                        "0x00001000:  addi.d $sp,$sp,-16",
                        "Trace 0: 0x00001010 [000/0001010/0x1010/0]",
                        "----------------",
                        "[00000000/00001020/00000000/00000000]",
                    ]
                ),
                encoding="utf-8",
            )
            coverage = load_address_log(path, min_address=0x1000, max_address=0x1030)
            self.assertEqual([block.absolute_start for block in coverage.blocks], [0x1000, 0x1010, 0x1020])
            self.assertEqual(coverage.trace_mode, "exec,nochain")
            self.assertEqual(coverage.hit_count_precision, "exact")

    def test_qemu_in_asm_hit_counts_are_marked_translation_log(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "in_asm.log"
            path.write_text("0x00001000: addi.d $sp,$sp,-16\n0x00001010: ret\n", encoding="utf-8")
            coverage = load_address_log(path)
            self.assertEqual(coverage.trace_mode, "in_asm")
            self.assertEqual(coverage.hit_count_precision, "translation-log")

    def test_drcov_parser_reads_v5_module_and_bb_table(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.drcov"
            header = (
                "DRCOV VERSION: 5\n"
                "DRCOV FLAVOR: drcov\n"
                "Module Table: version 5, count 1\n"
                "Columns: id, containing_id, start, end, entry, offset, preferred_base, path\n"
                "0, 0, 4096, 8192, 0, 0, 0, target.exe\n"
                "BB Table: 2 bbs\n"
            ).encode("utf-8")
            payload = struct.pack("<IHH", 0x10, 4, 0) + struct.pack("<IHH", 0x20, 8, 0)
            path.write_bytes(header + payload)
            coverage = load_drcov(path)
            self.assertEqual(coverage.modules[0].name, "target.exe")
            self.assertEqual([(b.offset, b.size, b.absolute_start) for b in coverage.blocks], [(0x10, 4, 0x1010), (0x20, 8, 0x1020)])


class AnalysisTests(unittest.TestCase):
    def test_flow_diff_reports_only_right_branch(self) -> None:
        metadata = _metadata()
        bad = _coverage([0x1000, 0x1010, 0x1030])
        good = _coverage([0x1000, 0x1020, 0x1030])
        result = diff_flow(metadata, bad, good)
        self.assertEqual(result["ai_digest"]["task"], "flow_diff")
        self.assertTrue(result["ai_digest"]["top_findings"])
        right_blocks = result["ai_report"]["user_only_right_blocks"]
        self.assertIn({"function": "check", "block_start": "0x1020"}, right_blocks)

    def test_branch_rank_prioritizes_input_dependent_source(self) -> None:
        metadata = _metadata()
        bad = _coverage([0x1000, 0x1010, 0x1030])
        better = _coverage([0x1000, 0x1010, 0x1030, 0x1010])
        good = _coverage([0x1000, 0x1020, 0x1030])
        result = rank_input_branches(metadata, [bad, better, good], labels=["bad", "better", "good"], roles=["bad", "better", "good"])
        self.assertGreater(result["summary"]["ranked_branch_points"], 0)
        self.assertEqual(result["ai_digest"]["task"], "branch_rank")
        self.assertEqual(result["ai_digest"]["recommended_actions"][0]["kind"], "open_disassembly")
        self.assertEqual(result["ranked_branches"][0]["block"], "check:0x1000")
        self.assertGreaterEqual(result["ranked_branches"][0]["new_successors_vs_baseline"], 1)
        confidence = result["report_confidence"]
        self.assertIn(confidence["level"], {"high", "medium", "low"})
        self.assertIsInstance(confidence["score"], int)
        self.assertTrue(confidence["recommendation"])

    def test_strict_dispatcher_mode_does_not_remove_hot_loop(self) -> None:
        metadata = _loop_metadata()
        coverage = _coverage(([0x1000, 0x1010] * 10) + [0x1020])
        strict = deflatten_flow(metadata, coverage, dispatcher_mode="strict")
        aggressive = deflatten_flow(metadata, coverage, dispatcher_mode="aggressive")
        self.assertEqual(strict["summary"]["dispatcher_blocks"], 0)
        self.assertGreaterEqual(aggressive["summary"]["dispatcher_blocks"], 1)
        self.assertTrue(any(item["warnings"] for item in aggressive["dispatcher_candidates"]))

    def test_deflatten_warns_when_qemu_in_asm_counts_are_used(self) -> None:
        metadata = _loop_metadata()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "in_asm.log"
            path.write_text("\n".join(["0x00001000: nop", "0x00001010: nop", "0x00001020: ret"]), encoding="utf-8")
            coverage = load_address_log(path)
            result = deflatten_flow(metadata, coverage)
            self.assertEqual(result["summary"]["hit_count_precision"], "translation-log")
            self.assertEqual(result["data_quality"]["hit_count_precision"], "translation-log")
            self.assertTrue(any("exec,nochain" in warning for warning in result["warnings"]))
            self.assertEqual(result["ai_digest"]["recommended_actions"][0]["kind"], "recollect_trace")

    def test_ai_summary_compacts_existing_report(self) -> None:
        metadata = _metadata()
        result = rank_input_branches(
            metadata,
            [_coverage([0x1000, 0x1010, 0x1030]), _coverage([0x1000, 0x1020, 0x1030])],
            labels=["bad", "good"],
            roles=["bad", "good"],
        )
        self.assertEqual(infer_report_kind(result), "branch_rank")
        compact = compact_report("branch_rank", result, max_findings=1)
        self.assertEqual(len(compact["ai_digest"]["top_findings"]), 1)
        self.assertNotIn("ranked_branches", compact)


class QemuExploreInputTests(unittest.TestCase):
    def test_mutate_format_generates_seed_and_byte_flips(self) -> None:
        self.assertEqual(_seed_from_mutate_format("flag{%4x}"), "flag{0000}")
        args = type(
            "Args",
            (),
            {
                "mutate_format": "flag{%2x}",
                "mutate_seed": None,
                "mutate_alphabet": "01",
                "mutate_limit": 5,
                "strategy": "byte-flip",
            },
        )()
        cases = _mutated_inputs(args)
        self.assertEqual(cases[0], "flag{00}")
        self.assertIn("flag{10}", cases)
        self.assertLessEqual(len(cases), 5)

    def test_mutate_format_can_be_repeated_for_multiple_prefixes(self) -> None:
        args = type(
            "Args",
            (),
            {
                "mutate_format": ["flag{%1x}", "ctf{%1x}"],
                "mutate_seed": None,
                "mutate_alphabet": "01",
                "mutate_limit": 2,
                "strategy": "byte-flip",
            },
        )()
        cases = _mutated_inputs(args)
        self.assertIn("flag{0}", cases)
        self.assertIn("ctf{0}", cases)

    def test_mutate_template_is_not_ctf_specific(self) -> None:
        self.assertEqual(_seed_from_mutate_format("token=%4x&mode=%2s"), "token=0000&mode=AA")
        args = type(
            "Args",
            (),
            {
                "mutate_format": ["token=%2x"],
                "mutate_seed": None,
                "mutate_alphabet": "01",
                "mutate_positions": None,
                "mutate_limit": 4,
                "strategy": "byte-flip",
            },
        )()
        self.assertIn("token=10", _mutated_inputs(args))

    def test_mutate_positions_selects_custom_seed_offsets(self) -> None:
        self.assertEqual(_parse_mutate_positions("1,3-4,6:8", 10), [1, 3, 4, 6, 7])
        args = type(
            "Args",
            (),
            {
                "mutate_format": ["ignored"],
                "mutate_seed": "login=admin",
                "mutate_alphabet": "xz",
                "mutate_positions": "6:11",
                "mutate_limit": 4,
                "strategy": "byte-flip",
            },
        )()
        cases = _mutated_inputs(args)
        self.assertEqual(cases[0], "login=admin")
        self.assertIn("login=xdmin", cases)


class McpTests(unittest.TestCase):
    def test_tools_list_contains_analysis_entry_points(self) -> None:
        for name in ["analyze_flow", "diff_flow", "qemu_explore", "branch_rank", "recover_state_transitions", "ai_summary"]:
            self.assertIn(name, TOOLS)
            self.assertIn("inputSchema", TOOLS[name])

    def test_qemu_explore_schema_exposes_auto_address_range(self) -> None:
        props = TOOLS["qemu_explore"]["inputSchema"]["properties"]
        self.assertIn("auto_address_range", props)
        self.assertEqual(props["auto_address_range"]["default"], True)


class CliTests(unittest.TestCase):
    def test_cli_help_lists_quickstart_and_qemu_commands(self) -> None:
        completed = subprocess.run(
            [sys.executable, "-m", "beaconflow.cli", "--help"],
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertIn("quickstart-qemu", completed.stdout)
        self.assertIn("qemu-explore", completed.stdout)


if __name__ == "__main__":
    raise SystemExit(unittest.main())
