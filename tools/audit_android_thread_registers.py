#!/usr/bin/env python
"""Fail closed on project object code that writes Android-owned thread registers."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import subprocess
import sys

INSTRUCTION = re.compile(r"^\s*[0-9a-f]+:\s+[0-9a-f]+\s+([a-z0-9.]+)\s*(.*?)\s*$", re.I)
REGISTER_18 = re.compile(r"\b[wx]18\b", re.I)
X18_WRITEBACK_BASE = re.compile(r"\[[^\]]*\b[wx]18\b[^\]]*\](?:!|\s*,\s*#)", re.I)
STATUS_STORE_MNEMONICS = {"stxr", "stlxr", "stxp", "stlxp"}
READ_ONLY_X18_MNEMONICS = (
    "st",
    "cmp",
    "cmn",
    "tst",
    "cbz",
    "cbnz",
    "tbz",
    "tbnz",
    "br",
    "blr",
    "ret",
)


def audit_instruction(line: str) -> str | None:
    match = INSTRUCTION.match(line)
    if match is None:
        return None
    mnemonic = match.group(1).lower()
    operands = match.group(2).lower()

    if mnemonic == "msr" and ("tpidr_el0" in operands or "tpidrro_el0" in operands):
        return "write to Android-owned thread-pointer register"
    if not REGISTER_18.search(operands):
        return None

    fields = [field.strip() for field in operands.split(",")]
    if mnemonic in STATUS_STORE_MNEMONICS and fields and fields[0] in {"x18", "w18"}:
        return "exclusive-store status result writes Android platform register x18"
    if X18_WRITEBACK_BASE.search(operands):
        return "writeback addressing updates Android platform register x18"

    if mnemonic == "mov":
        if len(fields) == 2 and fields[0] not in {"x18", "w18"} and fields[1] in {"x18", "w18"}:
            return None
    if mnemonic.startswith(READ_ONLY_X18_MNEMONICS):
        return None
    return "instruction may write Android platform register x18"


def disassemble(objdump: Path, object_file: Path) -> str:
    return subprocess.check_output(
        [str(objdump), "-d", str(object_file)],
        text=True,
        errors="replace",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--objdump", type=Path, required=True)
    parser.add_argument("--object-root", type=Path, action="append", required=True)
    args = parser.parse_args()

    if not args.objdump.is_file():
        raise SystemExit(f"missing llvm-objdump: {args.objdump}")

    objects: list[Path] = []
    for root in args.object_root:
        if not root.is_dir():
            raise SystemExit(f"missing object root: {root}")
        objects.extend(sorted(root.rglob("*.o")))
    objects = sorted(set(objects))
    if not objects:
        raise SystemExit("no project object files found")

    violations: list[str] = []
    instruction_count = 0
    x18_read_count = 0
    tpidr_read_count = 0
    for object_file in objects:
        for line in disassemble(args.objdump, object_file).splitlines():
            match = INSTRUCTION.match(line)
            if match is None:
                continue
            instruction_count += 1
            mnemonic = match.group(1).lower()
            operands = match.group(2).lower()
            if REGISTER_18.search(operands):
                x18_read_count += 1
            if mnemonic == "mrs" and ("tpidr_el0" in operands or "tpidrro_el0" in operands):
                tpidr_read_count += 1
            violation = audit_instruction(line)
            if violation is not None:
                violations.append(f"{object_file}: {line.strip()}: {violation}")

    if violations:
        print("thread-register audit FAIL", file=sys.stderr)
        for violation in violations:
            print(violation, file=sys.stderr)
        return 1

    print(
        "thread-register audit PASS "
        f"objects={len(objects)} instructions={instruction_count} "
        f"x18_reads={x18_read_count} tpidr_reads={tpidr_read_count} "
        "x18_writes=0 tpidr_writes=0"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
