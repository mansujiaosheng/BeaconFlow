"""
WASM 二进制解析器 - 纯 Python 实现。

从 WASM 文件中提取函数、基本块、指令和导出信息，
转换为 BeaconFlow 兼容的 metadata JSON 格式。

WASM 二进制格式参考: https://webassembly.github.io/spec/core/binary/
"""

from __future__ import annotations

import json
import struct
from pathlib import Path
from typing import Any

WASM_MAGIC = b"\x00asm"
WASM_VERSION = 1

SECTION_TYPE = 1
SECTION_IMPORT = 2
SECTION_FUNCTION = 3
SECTION_TABLE = 4
SECTION_MEMORY = 5
SECTION_GLOBAL = 6
SECTION_EXPORT = 7
SECTION_START = 8
SECTION_ELEMENT = 9
SECTION_CODE = 10
SECTION_DATA = 11
SECTION_DATACOUNT = 12

# WASM 指令操作码
OP_UNREACHABLE = 0x00
OP_NOP = 0x01
OP_BLOCK = 0x02
OP_LOOP = 0x03
OP_IF = 0x04
OP_ELSE = 0x05
OP_END = 0x0B
OP_BR = 0x0C
OP_BR_IF = 0x0D
OP_BR_TABLE = 0x0E
OP_RETURN = 0x0F
OP_CALL = 0x10
OP_CALL_INDIRECT = 0x11
OP_DROP = 0x1A
OP_SELECT = 0x1B
OP_LOCAL_GET = 0x20
OP_LOCAL_SET = 0x21
OP_LOCAL_TEE = 0x22
OP_GLOBAL_GET = 0x23
OP_GLOBAL_SET = 0x24

# 加载/存储操作码
OP_I32_LOAD = 0x28
OP_I64_LOAD = 0x29
OP_F32_LOAD = 0x2A
OP_F64_LOAD = 0x2B
OP_I32_LOAD8_S = 0x2C
OP_I32_LOAD8_U = 0x2D
OP_I32_LOAD16_S = 0x2E
OP_I32_LOAD16_U = 0x2F
OP_I64_LOAD8_S = 0x30
OP_I64_LOAD8_U = 0x31
OP_I64_LOAD16_S = 0x32
OP_I64_LOAD16_U = 0x33
OP_I64_LOAD32_S = 0x34
OP_I64_LOAD32_U = 0x35
OP_I32_STORE = 0x36
OP_I64_STORE = 0x37
OP_F32_STORE = 0x38
OP_F64_STORE = 0x39
OP_I32_STORE8 = 0x3A
OP_I32_STORE16 = 0x3B
OP_I64_STORE8 = 0x3C
OP_I64_STORE16 = 0x3D
OP_I64_STORE32 = 0x3E
OP_MEMORY_SIZE = 0x3F
OP_MEMORY_GROW = 0x40

# 常量操作码
OP_I32_CONST = 0x41
OP_I64_CONST = 0x42
OP_F32_CONST = 0x43
OP_F64_CONST = 0x44

# 比较操作码
OP_I32_EQZ = 0x45
OP_I32_EQ = 0x46
OP_I32_NE = 0x47
OP_I32_LT_S = 0x48
OP_I32_LT_U = 0x49
OP_I32_GT_S = 0x4A
OP_I32_GT_U = 0x4B
OP_I32_LE_S = 0x4C
OP_I32_LE_U = 0x4D
OP_I32_GE_S = 0x4E
OP_I32_GE_U = 0x4F
OP_I64_EQZ = 0x50
OP_I64_EQ = 0x51
OP_I64_NE = 0x52
OP_I64_LT_S = 0x53
OP_I64_LT_U = 0x54
OP_I64_GT_S = 0x55
OP_I64_GT_U = 0x56
OP_I64_LE_S = 0x57
OP_I64_LE_U = 0x58
OP_I64_GE_S = 0x59
OP_I64_GE_U = 0x5A

# 算术操作码
OP_I32_CLZ = 0x67
OP_I32_CTZ = 0x68
OP_I32_POPCNT = 0x69
OP_I32_ADD = 0x6A
OP_I32_SUB = 0x6B
OP_I32_MUL = 0x6C
OP_I32_DIV_S = 0x6D
OP_I32_DIV_U = 0x6E
OP_I32_REM_S = 0x6F
OP_I32_REM_U = 0x70
OP_I32_AND = 0x71
OP_I32_OR = 0x72
OP_I32_XOR = 0x73
OP_I32_SHL = 0x74
OP_I32_SHR_S = 0x75
OP_I32_SHR_U = 0x76
OP_I32_ROTL = 0x77
OP_I32_ROTR = 0x78
OP_I64_ADD = 0x7C
OP_I64_SUB = 0x7D
OP_I64_MUL = 0x7E
OP_I64_DIV_S = 0x7F
OP_I64_DIV_U = 0x80
OP_I64_REM_S = 0x81
OP_I64_REM_U = 0x82
OP_I64_AND = 0x83
OP_I64_OR = 0x84
OP_I64_XOR = 0x85
OP_I64_SHL = 0x86
OP_I64_SHR_S = 0x87
OP_I64_SHR_U = 0x88
OP_I64_ROTL = 0x89
OP_I64_ROTR = 0x8A

# WASM 操作码助记符映射
OPCODE_NAMES: dict[int, str] = {
    0x00: "unreachable", 0x01: "nop", 0x02: "block", 0x03: "loop",
    0x04: "if", 0x05: "else", 0x0B: "end", 0x0C: "br", 0x0D: "br_if",
    0x0E: "br_table", 0x0F: "return", 0x10: "call", 0x11: "call_indirect",
    0x1A: "drop", 0x1B: "select",
    0x20: "local.get", 0x21: "local.set", 0x22: "local.tee",
    0x23: "global.get", 0x24: "global.set",
    0x28: "i32.load", 0x29: "i64.load", 0x2A: "f32.load", 0x2B: "f64.load",
    0x2C: "i32.load8_s", 0x2D: "i32.load8_u", 0x2E: "i32.load16_s", 0x2F: "i32.load16_u",
    0x30: "i64.load8_s", 0x31: "i64.load8_u", 0x32: "i64.load16_s", 0x33: "i64.load16_u",
    0x34: "i64.load32_s", 0x35: "i64.load32_u",
    0x36: "i32.store", 0x37: "i64.store", 0x38: "f32.store", 0x39: "f64.store",
    0x3A: "i32.store8", 0x3B: "i32.store16",
    0x3C: "i64.store8", 0x3D: "i64.store16", 0x3E: "i64.store32",
    0x3F: "memory.size", 0x40: "memory.grow",
    0x41: "i32.const", 0x42: "i64.const", 0x43: "f32.const", 0x44: "f64.const",
    0x45: "i32.eqz", 0x46: "i32.eq", 0x47: "i32.ne",
    0x48: "i32.lt_s", 0x49: "i32.lt_u", 0x4A: "i32.gt_s", 0x4B: "i32.gt_u",
    0x4C: "i32.le_s", 0x4D: "i32.le_u", 0x4E: "i32.ge_s", 0x4F: "i32.ge_u",
    0x50: "i64.eqz", 0x51: "i64.eq", 0x52: "i64.ne",
    0x53: "i64.lt_s", 0x54: "i64.lt_u", 0x55: "i64.gt_s", 0x56: "i64.gt_u",
    0x57: "i64.le_s", 0x58: "i64.le_u", 0x59: "i64.ge_s", 0x5A: "i64.ge_u",
    0x67: "i32.clz", 0x68: "i32.ctz", 0x69: "i32.popcnt",
    0x6A: "i32.add", 0x6B: "i32.sub", 0x6C: "i32.mul",
    0x6D: "i32.div_s", 0x6E: "i32.div_u", 0x6F: "i32.rem_s", 0x70: "i32.rem_u",
    0x71: "i32.and", 0x72: "i32.or", 0x73: "i32.xor",
    0x74: "i32.shl", 0x75: "i32.shr_s", 0x76: "i32.shr_u",
    0x77: "i32.rotl", 0x78: "i32.rotr",
    0x7C: "i64.add", 0x7D: "i64.sub", 0x7E: "i64.mul",
    0x7F: "i64.div_s", 0x80: "i64.div_u", 0x81: "i64.rem_s", 0x82: "i64.rem_u",
    0x83: "i64.and", 0x84: "i64.or", 0x85: "i64.xor",
    0x86: "i64.shl", 0x87: "i64.shr_s", 0x88: "i64.shr_u",
    0x89: "i64.rotl", 0x8A: "i64.rotr",
}

# 比较类操作码（用于决策点检测）
COMPARE_OPS = {
    0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A,
}

# 算术/位运算操作码
ARITH_OPS = {
    0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73,
    0x74, 0x75, 0x76, 0x77, 0x78, 0x7C, 0x7D, 0x7E, 0x7F, 0x80,
    0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A,
}

# 分支类操作码
BRANCH_OPS = {0x0C, 0x0D, 0x0E}

# 常量类操作码
CONST_OPS = {0x41, 0x42, 0x43, 0x44}

# 需要 immediate 操作数的操作码
IMMEDIATE_OPS = {
    0x0C: "br_label",       # br labelidx
    0x0D: "br_label",       # br_if labelidx
    0x10: "func_idx",       # call funcidx
    0x11: "type_idx",       # call_indirect typeidx
    0x20: "local_idx",      # local.get localidx
    0x21: "local_idx",      # local.set localidx
    0x22: "local_idx",      # local.tee localidx
    0x23: "global_idx",     # global.get globalidx
    0x24: "global_idx",     # global.set globalidx
    0x41: "i32_value",      # i32.const s32
    0x42: "i64_value",      # i64.const s64
    0x43: "f32_value",      # f32.const f32
    0x44: "f64_value",      # f64.const f64
}

# 内存操作码（需要 memarg: align + offset）
MEMORY_OPS = {
    0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
    0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E,
}


class WasmReader:
    """WASM 二进制读取器。"""

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def read_byte(self) -> int:
        b = self.data[self.pos]
        self.pos += 1
        return b

    def read_bytes(self, n: int) -> bytes:
        result = self.data[self.pos:self.pos + n]
        self.pos += n
        return result

    def read_u32(self) -> int:
        result = struct.unpack_from("<I", self.data, self.pos)[0]
        self.pos += 4
        return result

    def read_leb128_unsigned(self) -> int:
        result = 0
        shift = 0
        while True:
            b = self.read_byte()
            result |= (b & 0x7F) << shift
            shift += 7
            if not (b & 0x80):
                break
        return result

    def read_leb128_signed(self, bits: int = 32) -> int:
        result = 0
        shift = 0
        while True:
            b = self.read_byte()
            result |= (b & 0x7F) << shift
            shift += 7
            if not (b & 0x80):
                if b & 0x40:
                    result |= -(1 << shift)
                break
        return result

    def read_name(self) -> str:
        length = self.read_leb128_unsigned()
        return self.read_bytes(length).decode("utf-8")

    def at_end(self) -> bool:
        return self.pos >= len(self.data)


class WasmInstruction:
    __slots__ = ("offset", "opcode", "name", "operands", "immediate")

    def __init__(self, offset: int, opcode: int, name: str, operands: list[str] | None = None, immediate: Any = None):
        self.offset = offset
        self.opcode = opcode
        self.name = name
        self.operands = operands or []
        self.immediate = immediate

    def to_text(self) -> str:
        parts = [self.name]
        if self.operands:
            parts.append(" ".join(str(o) for o in self.operands))
        return " ".join(parts)

    def is_compare(self) -> bool:
        return self.opcode in COMPARE_OPS

    def is_branch(self) -> bool:
        return self.opcode in BRANCH_OPS

    def is_const(self) -> bool:
        return self.opcode in CONST_OPS

    def is_arith(self) -> bool:
        return self.opcode in ARITH_OPS

    def is_call(self) -> bool:
        return self.opcode in (0x10, 0x11)


class WasmFunction:
    __slots__ = ("index", "name", "type_index", "locals", "instructions", "start_offset", "end_offset")

    def __init__(self, index: int, name: str, type_index: int):
        self.index = index
        self.name = name
        self.type_index = type_index
        self.locals: list[str] = []
        self.instructions: list[WasmInstruction] = []
        self.start_offset = 0
        self.end_offset = 0


class WasmModule:
    """WASM 模块解析器。"""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.type_section: list[dict] = []
        self.import_count = 0
        self.import_names: list[str] = []
        self.function_type_indices: list[int] = []
        self.export_map: dict[str, tuple[int, str]] = {}
        self.functions: list[WasmFunction] = []
        self.data_section_offsets: list[int] = []
        self._parse()

    def _parse(self):
        data = self.path.read_bytes()
        reader = WasmReader(data)

        magic = reader.read_bytes(4)
        if magic != WASM_MAGIC:
            raise ValueError(f"不是有效的 WASM 文件: magic={magic!r}")
        version = reader.read_u32()
        if version != WASM_VERSION:
            raise ValueError(f"不支持的 WASM 版本: {version}")

        while not reader.at_end():
            section_id = reader.read_byte()
            section_size = reader.read_leb128_unsigned()
            section_start = reader.pos
            section_data = reader.read_bytes(section_size)

            if section_id == SECTION_TYPE:
                self._parse_type_section(section_data)
            elif section_id == SECTION_IMPORT:
                self._parse_import_section(section_data)
            elif section_id == SECTION_FUNCTION:
                self._parse_function_section(section_data)
            elif section_id == SECTION_EXPORT:
                self._parse_export_section(section_data)
            elif section_id == SECTION_CODE:
                self._parse_code_section(section_data)
            elif section_id == SECTION_DATA:
                self._parse_data_section(section_data)

    def _parse_type_section(self, data: bytes):
        reader = WasmReader(data)
        count = reader.read_leb128_unsigned()
        for _ in range(count):
            form = reader.read_byte()
            if form != 0x60:
                continue
            param_count = reader.read_leb128_unsigned()
            params = []
            for _ in range(param_count):
                params.append(self._read_valtype(reader))
            result_count = reader.read_leb128_unsigned()
            results = []
            for _ in range(result_count):
                results.append(self._read_valtype(reader))
            self.type_section.append({"params": params, "results": results})

    def _read_valtype(self, reader: WasmReader) -> str:
        vt = reader.read_byte()
        return {0x7F: "i32", 0x7E: "i64", 0x7D: "f32", 0x7C: "f64"}.get(vt, f"unknown({vt})")

    def _parse_import_section(self, data: bytes):
        reader = WasmReader(data)
        count = reader.read_leb128_unsigned()
        for _ in range(count):
            module_name = reader.read_name()
            field_name = reader.read_name()
            kind = reader.read_byte()
            if kind == 0:
                reader.read_leb128_unsigned()
                self.import_count += 1
                self.import_names.append(f"{module_name}.{field_name}")
            elif kind == 1:
                reader.read_byte()
                reader.read_leb128_unsigned()
                reader.read_leb128_unsigned()
            elif kind == 2:
                limit_flag = reader.read_byte()
                reader.read_leb128_unsigned()
                if limit_flag & 1:
                    reader.read_leb128_unsigned()
            elif kind == 3:
                reader.read_leb128_unsigned()
                reader.read_byte()

    def _parse_function_section(self, data: bytes):
        reader = WasmReader(data)
        count = reader.read_leb128_unsigned()
        for _ in range(count):
            self.function_type_indices.append(reader.read_leb128_unsigned())

    def _parse_export_section(self, data: bytes):
        reader = WasmReader(data)
        count = reader.read_leb128_unsigned()
        for _ in range(count):
            name = reader.read_name()
            kind = reader.read_byte()
            index = reader.read_leb128_unsigned()
            kind_name = {0: "func", 1: "table", 2: "memory", 3: "global"}.get(kind, "unknown")
            self.export_map[name] = (index, kind_name)

    def _parse_code_section(self, data: bytes):
        reader = WasmReader(data)
        count = reader.read_leb128_unsigned()
        for func_idx in range(count):
            body_size = reader.read_leb128_unsigned()
            body_start = reader.pos
            body_data = reader.read_bytes(body_size)

            global_func_idx = self.import_count + func_idx
            type_idx = self.function_type_indices[func_idx] if func_idx < len(self.function_type_indices) else 0

            name = self._get_func_name(global_func_idx)
            func = WasmFunction(global_func_idx, name, type_idx)
            func.start_offset = body_start

            body_reader = WasmReader(body_data)
            local_count = body_reader.read_leb128_unsigned()
            for _ in range(local_count):
                n = body_reader.read_leb128_unsigned()
                vt = self._read_valtype(body_reader)
                for _ in range(n):
                    func.locals.append(vt)

            func.instructions = self._parse_instructions(body_reader)
            func.end_offset = body_start + body_size
            self.functions.append(func)

    def _parse_instructions(self, reader: WasmReader) -> list[WasmInstruction]:
        instructions: list[WasmInstruction] = []
        while not reader.at_end():
            offset = reader.pos
            opcode = reader.read_byte()
            name = OPCODE_NAMES.get(opcode, f"op_{opcode:02x}")

            operands: list[str] = []
            immediate = None

            if opcode in (0x02, 0x03, 0x04):
                block_type = reader.read_byte()
                if block_type != 0x40:
                    bt_name = {0x7F: "i32", 0x7E: "i64", 0x7D: "f32", 0x7C: "f64"}.get(block_type, f"type_{block_type}")
                    operands.append(bt_name)

            elif opcode == 0x0E:
                count = reader.read_leb128_unsigned()
                labels = [str(reader.read_leb128_unsigned()) for _ in range(count)]
                default = reader.read_leb128_unsigned()
                operands.append(f"[{','.join(labels)}] default={default}")
                immediate = {"labels": labels, "default": default}

            elif opcode in (0x0C, 0x0D):
                label = reader.read_leb128_unsigned()
                operands.append(str(label))
                immediate = label

            elif opcode == 0x10:
                func_idx = reader.read_leb128_unsigned()
                called_name = self._get_func_name(func_idx)
                operands.append(called_name)
                immediate = func_idx

            elif opcode == 0x11:
                type_idx = reader.read_leb128_unsigned()
                reader.read_byte()
                operands.append(f"type_{type_idx}")
                immediate = type_idx

            elif opcode in (0x20, 0x21, 0x22):
                idx = reader.read_leb128_unsigned()
                operands.append(str(idx))
                immediate = idx

            elif opcode in (0x23, 0x24):
                idx = reader.read_leb128_unsigned()
                operands.append(str(idx))
                immediate = idx

            elif opcode == 0x41:
                val = reader.read_leb128_signed(32)
                operands.append(f"0x{val & 0xFFFFFFFF:x}" if val < 0 or val > 9 else str(val))
                immediate = val

            elif opcode == 0x42:
                val = reader.read_leb128_signed(64)
                operands.append(f"0x{val & 0xFFFFFFFFFFFFFFFF:x}" if val < 0 or val > 9 else str(val))
                immediate = val

            elif opcode == 0x43:
                val = struct.unpack_from("<f", reader.read_bytes(4))[0]
                operands.append(str(val))
                immediate = val

            elif opcode == 0x44:
                val = struct.unpack_from("<d", reader.read_bytes(8))[0]
                operands.append(str(val))
                immediate = val

            elif opcode in MEMORY_OPS:
                align = reader.read_leb128_unsigned()
                mem_offset = reader.read_leb128_unsigned()
                operands.append(f"offset={mem_offset}")
                immediate = {"align": align, "offset": mem_offset}

            elif opcode in (0x3F, 0x40):
                reader.read_byte()

            instructions.append(WasmInstruction(offset, opcode, name, operands, immediate))

        return instructions

    def _parse_data_section(self, data: bytes):
        reader = WasmReader(data)
        count = reader.read_leb128_unsigned()
        for _ in range(count):
            flags = reader.read_leb128_unsigned()
            if flags == 0:
                self._skip_init_expr(reader)
            elif flags == 1:
                reader.read_leb128_unsigned()
                self._skip_init_expr(reader)
            elif flags == 2:
                reader.read_leb128_unsigned()
                self._skip_init_expr(reader)
            size = reader.read_leb128_unsigned()
            reader.read_bytes(size)

    def _skip_init_expr(self, reader: WasmReader):
        while not reader.at_end():
            opcode = reader.read_byte()
            if opcode == 0x0B:
                break
            elif opcode == 0x41:
                reader.read_leb128_signed(32)
            elif opcode == 0x42:
                reader.read_leb128_signed(64)
            elif opcode == 0x43:
                reader.read_bytes(4)
            elif opcode == 0x44:
                reader.read_bytes(8)
            elif opcode == 0x23:
                reader.read_leb128_unsigned()

    def _get_func_name(self, global_idx: int) -> str:
        for name, (idx, kind) in self.export_map.items():
            if kind == "func" and idx == global_idx:
                return name
        if global_idx < self.import_count:
            if global_idx < len(self.import_names):
                return self.import_names[global_idx]
            return f"import_{global_idx}"
        local_idx = global_idx - self.import_count
        return f"f{local_idx}"


def _split_basic_blocks(func: WasmFunction) -> list[dict[str, Any]]:
    """将函数指令分割为基本块。"""
    if not func.instructions:
        return []

    leaders: set[int] = {0}

    for i, insn in enumerate(func.instructions):
        if insn.opcode in (0x02, 0x03, 0x04):
            leaders.add(i)
        if insn.opcode in (0x0C, 0x0D, 0x0E, 0x0F):
            if i + 1 < len(func.instructions):
                leaders.add(i + 1)
        if insn.opcode == 0x05:
            leaders.add(i)
        if i > 0 and func.instructions[i - 1].opcode in (0x0C, 0x0D, 0x0E):
            leaders.add(i)

    sorted_leaders = sorted(leaders)
    blocks: list[dict[str, Any]] = []

    for block_idx, start in enumerate(sorted_leaders):
        end = sorted_leaders[block_idx + 1] if block_idx + 1 < len(sorted_leaders) else len(func.instructions)

        block_insns = func.instructions[start:end]
        if not block_insns:
            continue

        succs: list[str] = []
        last_insn = block_insns[-1]

        if last_insn.opcode == 0x0F:
            pass
        elif last_insn.opcode == 0x0E:
            if last_insn.immediate and isinstance(last_insn.immediate, dict):
                n_labels = len(last_insn.immediate["labels"])
                for label_idx in range(n_labels + 1):
                    target_block_idx = block_idx + label_idx + 1
                    if target_block_idx < len(sorted_leaders):
                        target_offset = func.start_offset + sorted_leaders[target_block_idx]
                        succs.append(f"0x{target_offset:x}")
        elif last_insn.opcode in (0x0C, 0x0D):
            pass
        elif last_insn.opcode != 0x0B:
            if block_idx + 1 < len(sorted_leaders):
                next_offset = func.start_offset + sorted_leaders[block_idx + 1]
                succs.append(f"0x{next_offset:x}")

        instructions_text = [insn.to_text() for insn in block_insns]
        calls = [insn.operands[0] for insn in block_insns if insn.is_call() and insn.operands]
        constants = []
        for insn in block_insns:
            if insn.is_const() and insn.immediate is not None:
                val = insn.immediate
                if isinstance(val, int) and 0 < abs(val) < 0x100000 and val not in constants:
                    constants.append(val)

        block_addr = f"0x{func.start_offset + start:x}"
        block_end_addr = f"0x{func.start_offset + end:x}"

        context: dict[str, Any] = {}
        if instructions_text:
            context["instructions"] = instructions_text
        if calls:
            context["calls"] = list(dict.fromkeys(calls))
        if constants:
            context["constants"] = [f"0x{c:x}" for c in constants[:20]]

        blocks.append({
            "start": block_addr,
            "end": block_end_addr,
            "succs": succs,
            "context": context,
        })

    return blocks


def wasm_to_metadata(wasm_path: str | Path, output_path: str | Path | None = None) -> dict[str, Any]:
    """将 WASM 文件转换为 BeaconFlow 兼容的 metadata JSON。

    参数:
        wasm_path: WASM 文件路径
        output_path: 输出 JSON 路径（可选）
    """
    module = WasmModule(wasm_path)

    functions_data = []
    for func in module.functions:
        blocks = _split_basic_blocks(func)
        func_addr = f"0x{func.start_offset:x}"
        func_end = f"0x{func.end_offset:x}"

        functions_data.append({
            "name": func.name,
            "start": func_addr,
            "end": func_end,
            "blocks": blocks,
        })

    metadata = {
        "input_path": str(module.path),
        "image_base": "0x0",
        "format": "wasm",
        "functions": functions_data,
    }

    if output_path:
        output_path = Path(output_path)
        output_path.write_text(json.dumps(metadata, indent=2, ensure_ascii=False), encoding="utf-8")

    return {
        "output_path": str(output_path) if output_path else None,
        "format": "wasm",
        "functions": len(functions_data),
        "basic_blocks": sum(len(f["blocks"]) for f in functions_data),
        "exports": len([k for k, v in module.export_map.items() if v[1] == "func"]),
        "imports": module.import_count,
    }
