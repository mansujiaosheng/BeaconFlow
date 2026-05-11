from __future__ import annotations

import json
import struct
import tempfile
import unittest
from pathlib import Path

from beaconflow.analysis import diff_flow, rank_input_branches
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


class ParserTests(unittest.TestCase):
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
        right_blocks = result["ai_report"]["user_only_right_blocks"]
        self.assertIn({"function": "check", "block_start": "0x1020"}, right_blocks)

    def test_branch_rank_prioritizes_input_dependent_source(self) -> None:
        metadata = _metadata()
        bad = _coverage([0x1000, 0x1010, 0x1030])
        better = _coverage([0x1000, 0x1010, 0x1030, 0x1010])
        good = _coverage([0x1000, 0x1020, 0x1030])
        result = rank_input_branches(metadata, [bad, better, good], labels=["bad", "better", "good"], roles=["bad", "better", "good"])
        self.assertGreater(result["summary"]["ranked_branch_points"], 0)
        self.assertEqual(result["ranked_branches"][0]["block"], "check:0x1000")
        self.assertGreaterEqual(result["ranked_branches"][0]["new_successors_vs_baseline"], 1)


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
        for name in ["analyze_flow", "diff_flow", "qemu_explore", "branch_rank", "recover_state_transitions"]:
            self.assertIn(name, TOOLS)
            self.assertIn("inputSchema", TOOLS[name])


if __name__ == "__main__":
    raise SystemExit(unittest.main())
