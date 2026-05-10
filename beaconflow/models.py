from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import PurePath
from typing import Any


def normalize_path_name(path: str) -> str:
    return PurePath(path.replace("\\", "/")).name.lower()


def parse_int(value: int | str) -> int:
    if isinstance(value, int):
        return value
    return int(value, 16) if value.lower().startswith("0x") else int(value)


def hex_addr(value: int) -> str:
    return f"0x{value:x}"


@dataclass(frozen=True)
class BasicBlock:
    start: int
    end: int
    succs: tuple[int, ...] = ()

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "BasicBlock":
        return cls(
            start=parse_int(data["start"]),
            end=parse_int(data["end"]),
            succs=tuple(parse_int(x) for x in data.get("succs", ())),
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "start": hex_addr(self.start),
            "end": hex_addr(self.end),
            "succs": [hex_addr(x) for x in self.succs],
        }


@dataclass(frozen=True)
class Function:
    name: str
    start: int
    end: int
    blocks: tuple[BasicBlock, ...] = ()

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "Function":
        return cls(
            name=data.get("name") or hex_addr(parse_int(data["start"])),
            start=parse_int(data["start"]),
            end=parse_int(data["end"]),
            blocks=tuple(BasicBlock.from_json(x) for x in data.get("blocks", ())),
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "start": hex_addr(self.start),
            "end": hex_addr(self.end),
            "blocks": [x.to_json() for x in self.blocks],
        }


@dataclass(frozen=True)
class ProgramMetadata:
    input_path: str
    image_base: int
    functions: tuple[Function, ...] = ()

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "ProgramMetadata":
        return cls(
            input_path=data.get("input_path", ""),
            image_base=parse_int(data.get("image_base", 0)),
            functions=tuple(Function.from_json(x) for x in data.get("functions", ())),
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "input_path": self.input_path,
            "image_base": hex_addr(self.image_base),
            "functions": [x.to_json() for x in self.functions],
        }


@dataclass(frozen=True)
class DrcovModule:
    module_id: int
    start: int
    end: int
    path: str
    base: int = 0
    seg_offset: int = 0
    preferred_base: int = 0

    @property
    def name(self) -> str:
        return normalize_path_name(self.path)


@dataclass(frozen=True)
class CoverageBlock:
    module_id: int
    offset: int
    size: int
    absolute_start: int | None = None

    @property
    def absolute_end(self) -> int | None:
        if self.absolute_start is None:
            return None
        return self.absolute_start + self.size


@dataclass
class CoverageData:
    modules: dict[int, DrcovModule] = field(default_factory=dict)
    blocks: list[CoverageBlock] = field(default_factory=list)

