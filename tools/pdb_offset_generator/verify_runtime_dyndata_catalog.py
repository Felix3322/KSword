#!/usr/bin/env python3
"""Verify that the checked-in runtime DbgHelp catalog mirrors the publisher.

The runtime resolver cannot import Python in a packaged build, so its compact
macro catalog is checked in. This guard fails when FIELD_MAP, type-size,
callback, global aliases, or shared numeric IDs drift without a C++ update.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

import ksword_pdb_profile_generator as generator
import ksword_profile_release_sync as release_sync


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CATALOG = (
    ROOT
    / "Ksword5.1"
    / "Ksword5.1"
    / "ArkDriverClient"
    / "ArkRuntimeDynDataCatalog.inc"
)
DEFAULT_RUNTIME_SOURCE = (
    ROOT
    / "Ksword5.1"
    / "Ksword5.1"
    / "ArkDriverClient"
    / "ArkRuntimeDynData.cpp"
)

FIELD_RE = re.compile(
    r'^KSW_RUNTIME_FIELD\((\d+)U,\s*"([^"]+)",\s*"([^"]+)",\s*"([^"]+)"\)$'
)
TYPE_SIZE_RE = re.compile(
    r'^KSW_RUNTIME_TYPE_SIZE\((\d+)U,\s*"([^"]+)",\s*"([^"]+)"\)$'
)
GLOBAL_RE = re.compile(
    r'^KSW_RUNTIME_GLOBAL\((\d+)U,\s*"([^"]+)",\s*"([^"]+)",\s*(true|false)\)$'
)
CALLBACK_FIELD_RE = re.compile(
    r'^KSW_RUNTIME_CALLBACK_FIELD\((\d+)U,\s*"([^"]+)",\s*"([^"]+)",\s*"([^"]+)"\)$'
)
V4_GROUP_COUNT_RE = re.compile(
    r"case\s+(KSW_DYN_V4_CAPABILITY_GROUP_[A-Z0-9_]+):\s*"
    r"group\.requiredItemCount\s*=\s*(\d+)U;\s*"
    r"group\.optionalItemCount\s*=\s*(\d+)U;",
    re.MULTILINE,
)


def expected_lines() -> set[str]:
    lines: set[str] = set()
    for name, (type_name, member_name) in generator.FIELD_MAP.items():
        lines.add(
            f'KSW_RUNTIME_FIELD({release_sync.KNOWN_FIELD_IDS[name]}U, '
            f'"{name}", "{type_name}", "{member_name}")'
        )
    for name, type_name in generator.TYPE_SIZE_MAP.items():
        lines.add(
            f'KSW_RUNTIME_TYPE_SIZE({release_sync.KNOWN_FIELD_IDS[name]}U, '
            f'"{name}", "{type_name}")'
        )
    for name in generator.CALLBACK_GLOBAL_RVA_NAMES:
        aliases = generator.GLOBAL_RVA_SYMBOL_ALIASES.get(name, (name,))
        lines.add(
            f'KSW_RUNTIME_GLOBAL({release_sync.CALLBACK_GLOBAL_RVA_FIELD_IDS[name]}U, '
            f'"{name}", "{"|".join(aliases)}", true)'
        )
    for name in generator.KERNEL_GLOBAL_RVA_NAMES:
        lines.add(
            f'KSW_RUNTIME_GLOBAL({release_sync.KERNEL_GLOBAL_RVA_FIELD_IDS[name]}U, '
            f'"{name}", "{name}", false)'
        )
    for name, (type_name, member_name) in generator.CALLBACK_STRUCT_FIELD_MAP.items():
        canonical = release_sync.CALLBACK_NAME_ALIASES.get(name, name)
        lines.add(
            f'KSW_RUNTIME_CALLBACK_FIELD('
            f'{release_sync.CALLBACK_STRUCT_OFFSET_FIELD_IDS[canonical]}U, '
            f'"{name}", "{type_name}", "{member_name}")'
        )
    return lines


def catalog_lines(path: Path) -> set[str]:
    lines: set[str] = set()
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if any(
            pattern.fullmatch(line)
            for pattern in (FIELD_RE, TYPE_SIZE_RE, GLOBAL_RE, CALLBACK_FIELD_RE)
        ):
            if line in lines:
                raise ValueError(f"duplicate runtime catalog entry: {line}")
            lines.add(line)
    return lines


def runtime_v4_group_counts(path: Path) -> dict[str, tuple[int, int]]:
    source = path.read_text(encoding="utf-8")
    return {
        macro_name: (int(required), int(optional))
        for macro_name, required, optional in V4_GROUP_COUNT_RE.findall(source)
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
    parser.add_argument(
        "--runtime-source",
        type=Path,
        default=DEFAULT_RUNTIME_SOURCE,
    )
    args = parser.parse_args()

    expected = expected_lines()
    actual = catalog_lines(args.catalog)
    missing = sorted(expected - actual)
    unexpected = sorted(actual - expected)
    if missing or unexpected:
        if missing:
            print("missing:")
            print("\n".join(missing))
        if unexpected:
            print("unexpected:")
            print("\n".join(unexpected))
        return 1

    expected_v4_counts = {
        "KSW_DYN_V4_CAPABILITY_GROUP_TIMER_DPC":
            release_sync.V4_FIXED_CAPABILITY_GROUP_COUNTS[
                release_sync.V4_TIMER_GROUP_ID
            ],
        "KSW_DYN_V4_CAPABILITY_GROUP_FLTMGR_MINIFILTER":
            release_sync.V4_FIXED_CAPABILITY_GROUP_COUNTS[
                release_sync.V4_FLTMGR_MINIFILTER_GROUP_ID
            ],
        "KSW_DYN_V4_CAPABILITY_GROUP_CI_KERNEL_HASH":
            release_sync.V4_FIXED_CAPABILITY_GROUP_COUNTS[
                release_sync.V4_CI_KERNEL_HASH_GROUP_ID
            ],
        "KSW_DYN_V4_CAPABILITY_GROUP_WORK_QUEUE":
            release_sync.V4_FIXED_CAPABILITY_GROUP_COUNTS[
                release_sync.V4_WORK_QUEUE_GROUP_ID
            ],
    }
    actual_v4_counts = runtime_v4_group_counts(
        args.runtime_source
    )
    if actual_v4_counts != expected_v4_counts:
        print(f"v4 group count mismatch: expected={expected_v4_counts}")
        print(f"v4 group count mismatch: actual={actual_v4_counts}")
        return 1

    print(
        "runtime DynData catalog OK: "
        f"{len(generator.FIELD_MAP)} fields, "
        f"{len(generator.TYPE_SIZE_MAP)} type sizes, "
        f"{len(generator.CALLBACK_GLOBAL_RVA_NAMES) + len(generator.KERNEL_GLOBAL_RVA_NAMES)} globals, "
        f"{len(generator.CALLBACK_STRUCT_FIELD_MAP)} callback members, "
        f"{len(expected_v4_counts)} fixed v4 group contracts"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
