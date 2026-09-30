"""Historical release136/runtime3/driver21 closure invariants.

Current release-transition behavior is covered by test_release144_transition.
This module retains immutable predecessor facts relevant after application140.
"""

from __future__ import annotations

import hashlib
import unittest

from tests import test_rhel9_rollback_predecessor_profile as profile_tests
from tests.test_release135_transition import canonical


DRIVER21_VERIFY_POLICY = (
    "39c26ec18c7d8eadaad0c9b1b3d89fc133e5f60fb63f94ed427dbb8839fbadb0"
)


class Release136HistoricalClosureTests(unittest.TestCase):
    setUp = profile_tests.RollbackPredecessorProfileTests.setUp
    source_contract = profile_tests.RollbackPredecessorProfileTests.source_contract
    full_gate = profile_tests.RollbackPredecessorProfileTests.full_gate

    def test_driver21_policy_digest_remains_the_predecessor_authority(self):
        policy = {
            "command": ["/usr/bin/rpm", "-V", "lto-ltfs"],
            "package_nevra": "lto-ltfs-0.1.0-21.el9.x86_64",
            "permitted_rows": ["S.5....T.  c /etc/lto-ltfs/device.json"],
            "schema": 1,
            "stderr": "",
            "success_exit_codes": [1],
        }

        self.assertEqual(
            DRIVER21_VERIFY_POLICY,
            hashlib.sha256(canonical(policy)).hexdigest(),
        )

    def test_release136_schema40_driver21_remains_a_valid_historical_profile(self):
        self.assertTrue(
            self.full_gate(136, 40, driver_release=21, reader="inactive")
        )


if __name__ == "__main__":
    unittest.main()
