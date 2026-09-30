"""Historical release142/runtime3/driver21 closure invariants.

Release142 was signed but refused before installation; predecessor141 remains
installed. Current transition behavior is covered by test_release144_transition.
The recorded release142 qualification evidence remains in its release notes.
"""

from __future__ import annotations

import hashlib
import unittest
from pathlib import Path

from tests import test_rhel9_rollback_predecessor_profile as profile_tests

ROOT = Path(__file__).resolve().parents[1]
DRIVER21_VERIFY_POLICY_SHA256 = (
    "39c26ec18c7d8eadaad0c9b1b3d89fc133e5f60fb63f94ed427dbb8839fbadb0"
)


class Release142HistoricalClosureTests(unittest.TestCase):
    setUp = profile_tests.RollbackPredecessorProfileTests.setUp
    source_contract = profile_tests.RollbackPredecessorProfileTests.source_contract
    full_gate = profile_tests.RollbackPredecessorProfileTests.full_gate

    def test_driver21_verification_policy_bytes_are_unchanged(self):
        raw = (ROOT / "packaging/rpm/driver-rpm-verify-policy.json").read_bytes()
        self.assertEqual(DRIVER21_VERIFY_POLICY_SHA256, hashlib.sha256(raw).hexdigest())

    def test_release142_predecessor141_schema40_driver21_remains_valid(self):
        self.assertTrue(self.full_gate(141, 40, driver_release=21, reader="inactive"))


if __name__ == "__main__":
    unittest.main()
