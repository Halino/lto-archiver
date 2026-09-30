"""Final immutable-release admission binds one exact draft and asset set."""

from __future__ import annotations

import runpy
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VERIFIER = ROOT / "packaging/rpm/verify-public-release.py"
NAMES = (
    "ATTESTATION.json",
    "FINAL-RPM-SHA256SUMS",
    "FINAL-RPM-SHA256SUMS.asc",
    "RPM-PUBLIC-KEY.asc",
    "lto-archiver-0.11.30-155.el9.noarch.rpm",
    "lto-archiver-0.11.30-155.el9.src.rpm",
    "lto-archiver-python-runtime-0.11.27-3.el9.src.rpm",
    "lto-archiver-python-runtime-0.11.27-3.el9.x86_64.rpm",
)
# Independently calculated from sorted ASCII names + NUL + 64 literal 'a' bytes + LF.
ASSET_DIGEST = "0fe6ea8019f1aa0992ffce647ad48369161d1f52479f541c03fd3bc3ed294f2d"


class FinalProofTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.verifier = runpy.run_path(str(VERIFIER))

    def identity(self) -> dict[str, object]:
        return {
            "repo": "owner/lto-archiver-rhel9",
            "tag": "v0.11.30",
            "commit": "c" * 40,
            "draft_id": 17,
            "manifest_sha256": "b" * 64,
            "asset_set_sha256": ASSET_DIGEST,
            "run_id": 23,
        }

    def proof(self, checked_at: int = 1_800_000_000) -> dict[str, object]:
        return self.verifier["make_final_proof"](**self.identity(), checked_at=checked_at)

    def test_exact_bound_proof_passes_at_120_seconds(self) -> None:
        proof = self.proof()
        self.assertEqual(set(self.identity()) | {"checked_at"}, set(proof))
        self.verifier["validate_final_proof"](proof, self.identity(), 1_800_000_120)

    def test_proof_rejects_wrong_repo_draft_or_asset_digest(self) -> None:
        validate = self.verifier["validate_final_proof"]
        error = self.verifier["PublicReleaseError"]
        for key, value in (
            ("repo", "other/lto-archiver-rhel9"),
            ("draft_id", 18),
            ("asset_set_sha256", "d" * 64),
        ):
            with self.subTest(key=key):
                changed = self.proof()
                changed[key] = value
                with self.assertRaises(error):
                    validate(changed, self.identity(), 1_800_000_001)
        for malformed in ({"extra": "x"}, {"draft_id": True}, {"run_id": 0}):
            with self.subTest(malformed=malformed):
                with self.assertRaises(error):
                    validate(self.proof() | malformed, self.identity(), 1_800_000_001)

    def test_proof_rejects_future_or_121_second_timestamp(self) -> None:
        validate = self.verifier["validate_final_proof"]
        error = self.verifier["PublicReleaseError"]
        for now in (1_799_999_999, 1_800_000_121):
            with self.subTest(now=now), self.assertRaises(error):
                validate(self.proof(), self.identity(), now)

    def test_asset_set_rejects_same_name_changed_byte(self) -> None:
        digest = self.verifier["asset_set_sha256"]
        error = self.verifier["PublicReleaseError"]
        files = {name: "a" * 64 for name in NAMES}
        self.assertEqual(ASSET_DIGEST, digest(files))
        changed = files | {NAMES[0]: "b" * 64}
        self.assertNotEqual(ASSET_DIGEST, digest(changed))
        with self.assertRaises(error):
            digest({name: value for name, value in files.items() if name != NAMES[0]})
        with self.assertRaises(error):
            digest(files | {"extra.rpm": "a" * 64})
        with self.assertRaises(error):
            digest({name.replace("0.11.30-155", "0.11.29-155"): value
                    for name, value in files.items()})


if __name__ == "__main__":
    unittest.main()
