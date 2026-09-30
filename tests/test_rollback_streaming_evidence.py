"""Rollback evidence must fit in memory even when the catalog does not."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from tests.test_rhel9_rollback import ROOT, _load_module


class StreamingRollbackEvidenceTests(unittest.TestCase):
    def test_catalog_larger_than_address_space_can_be_hashed(self):
        # A whole-file read of the real sparse file cannot fit in this process.
        # No mocked file reads: both evidence paths must produce the right hash.
        program = """
import json, resource, sys
from pathlib import Path
from tests.test_rhel9_rollback import _load_module
module = _load_module()
resource.setrlimit(resource.RLIMIT_AS, (96 * 1024**2, 96 * 1024**2))
root = Path(sys.argv[1])
if sys.argv[2] == 'file':
    row = module.SystemRollbackHost._file_evidence(root / 'catalog.db', Path('catalog.db'))
    print(json.dumps({'sha256': row.sha256, 'size': row.size}))
else:
    print(json.dumps(module._checksum_rows(root)))
"""
        with tempfile.TemporaryDirectory(prefix="lto-streaming-") as temporary:
            root = Path(temporary)
            size = 128 * 1024**2
            with (root / "catalog.db").open("wb") as stream:
                stream.truncate(size)
            expected = hashlib.sha256()
            for _ in range(128):
                expected.update(bytes(1024**2))
            for mode in ("file", "checksums"):
                with self.subTest(mode=mode):
                    result = subprocess.run(
                        [sys.executable, "-c", program, str(root), mode],
                        cwd=ROOT, capture_output=True, text=True, timeout=20,
                        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    value = json.loads(result.stdout)
                    self.assertEqual(value, {
                        "sha256": expected.hexdigest(), "size": size,
                    } if mode == "file" else [f"{expected.hexdigest()}  catalog.db"])

    def test_empty_and_multi_chunk_evidence_preserves_metadata_and_checksums(self):
        module = _load_module()
        with tempfile.TemporaryDirectory(prefix="lto-streaming-") as temporary:
            root = Path(temporary)
            for content in (b"", b"abc", b"x" * (2 * 1024**2 + 17)):
                with self.subTest(size=len(content)):
                    path = root / "catalog.db"
                    path.write_bytes(content)
                    path.chmod(0o640)
                    before = path.stat()
                    row = module.SystemRollbackHost._file_evidence(path, Path("catalog.db"))
                    self.assertEqual(row.sha256, hashlib.sha256(content).hexdigest())
                    self.assertEqual((row.size, row.mode, row.uid, row.gid),
                                     (len(content), 0o640, before.st_uid, before.st_gid))
                    self.assertEqual(module._checksum_rows(root),
                                     [f"{hashlib.sha256(content).hexdigest()}  catalog.db"])
                    self.assertEqual(path.stat().st_mtime_ns, before.st_mtime_ns)
                    self.assertEqual(path.stat().st_ctime_ns, before.st_ctime_ns)
