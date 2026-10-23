import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from tools.verify_totk_exefs import extract_or_verify


class VerifyTotkExeFsTests(unittest.TestCase):
    def fixture(self):
        temp = tempfile.TemporaryDirectory()
        root = Path(temp.name)
        output = root / "exefs"
        output.mkdir()
        payloads = {"main": b"main", "sdk": b"sdk"}
        for name, payload in payloads.items():
            (output / name).write_bytes(payload)
        expected = {
            "display_version": "test",
            "version": 1,
            "exefs_sha256": {name: hashlib.sha256(payload).hexdigest() for name, payload in payloads.items()},
        }
        manifest = root / "expected.json"
        manifest.write_text(json.dumps(expected), encoding="utf-8")
        return temp, root, output, manifest

    def test_existing_exact_exefs_passes_without_extractor(self):
        temp, root, output, manifest = self.fixture()
        self.addCleanup(temp.cleanup)
        source = root / "game.xci"
        source.write_bytes(b"container")
        result = extract_or_verify(
            label="base", source=source, keys=root / "unused.keys", output=output,
            expected_path=manifest, extractor=root / "not-run.py", update=False,
        )
        self.assertTrue(result["exact_manifest_match"])
        self.assertEqual(result["exefs_files"], ["main", "sdk"])

    def test_hash_mismatch_fails_closed(self):
        temp, root, output, manifest = self.fixture()
        self.addCleanup(temp.cleanup)
        (output / "main").write_bytes(b"changed")
        source = root / "game.xci"
        source.write_bytes(b"container")
        with self.assertRaisesRegex(ValueError, "exact hash mismatch"):
            extract_or_verify(
                label="base", source=source, keys=root / "unused.keys", output=output,
                expected_path=manifest, extractor=root / "not-run.py", update=False,
            )


if __name__ == "__main__":
    unittest.main()
