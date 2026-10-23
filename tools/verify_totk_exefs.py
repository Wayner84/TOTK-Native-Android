#!/usr/bin/env python3
"""Privately extract and exact-match the owner's TOTK 1.0.0/1.4.3 ExeFS.

Game-derived output stays below --private-root, which must be Git-ignored. The
committable report contains metadata and pass/fail state, never keys or module
hashes. Existing extraction directories are verified and never overwritten.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def extract_or_verify(
    *, label: str, source: Path, keys: Path, output: Path, expected_path: Path,
    extractor: Path, update: bool,
) -> dict:
    expected_doc = json.loads(expected_path.read_text(encoding="utf-8"))
    expected = expected_doc["exefs_sha256"]
    if not output.exists():
        output.parent.mkdir(parents=True, exist_ok=True)
        command = [sys.executable, str(extractor), str(source), "--keys", str(keys), "--output", str(output)]
        if update:
            command.append("--update")
        subprocess.run(command, check=True)
    if not output.is_dir():
        raise ValueError(f"not an ExeFS directory: {output}")
    actual_paths = {path.name: path for path in output.iterdir() if path.is_file()}
    if set(actual_paths) != set(expected):
        raise ValueError(f"{label}: ExeFS names differ: {sorted(actual_paths)}")
    mismatches = [name for name, digest in expected.items() if file_sha256(actual_paths[name]) != digest]
    if mismatches:
        raise ValueError(f"{label}: exact hash mismatch: {', '.join(sorted(mismatches))}")
    return {
        "label": label,
        "display_version": expected_doc["display_version"],
        "internal_version": expected_doc["version"],
        "source_name": source.name,
        "source_bytes": source.stat().st_size,
        "container": source.suffix.lower().lstrip("."),
        "exefs_files": sorted(actual_paths),
        "exefs_total_bytes": sum(path.stat().st_size for path in actual_paths.values()),
        "exact_manifest_match": True,
        "integrity": "Pinned extractor verified NCA/FS headers, ExeFS hash table and every ExeFS data block; exact module SHA-256 values matched the pinned version manifest.",
        "private_output": str(output.resolve()),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True, type=Path)
    parser.add_argument("--update", required=True, type=Path)
    parser.add_argument("--keys", required=True, type=Path)
    parser.add_argument("--private-root", type=Path, default=Path("private/extracted"))
    parser.add_argument("--report", type=Path, default=Path("logs/exefs-verification.json"))
    args = parser.parse_args()
    for name, path in (("base", args.base), ("update", args.update), ("keys", args.keys)):
        if not path.is_file():
            raise SystemExit(f"missing {name}: {path}")

    project = Path(__file__).resolve().parent.parent
    upstream = project / "third_party/MacNativeGames/games/totk"
    extractor = upstream / "scripts/extract_exefs.py"
    rows = [
        extract_or_verify(
            label="base", source=args.base.resolve(), keys=args.keys.resolve(),
            output=(project / args.private_root / "v0/exefs").resolve(),
            expected_path=upstream / "assets/expected-v1.0.0.json", extractor=extractor, update=False,
        ),
        extract_or_verify(
            label="update", source=args.update.resolve(), keys=args.keys.resolve(),
            output=(project / args.private_root / "v143/exefs").resolve(),
            expected_path=upstream / "assets/expected-v1.4.3.json", extractor=extractor, update=True,
        ),
    ]
    report = {
        "format": 1,
        "status": "pass",
        "scope": "owner-supplied TOTK base and update ExeFS identity",
        "key_values_recorded": False,
        "results": rows,
    }
    destination = (project / args.report).resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes((json.dumps(report, indent=2) + "\n").encode("utf-8"))
    print(f"PASS: exact TOTK 1.0.0 base and 1.4.3 update ExeFS match; report: {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
