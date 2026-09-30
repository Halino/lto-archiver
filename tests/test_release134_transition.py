"""Historical release134/runtime3/driver20 closure invariants.

Current release-transition behavior is covered by test_release135_transition.
This module retains immutable predecessor facts relevant after application135.
"""

from __future__ import annotations

import hashlib
import json
import unittest

from tests import test_rhel9_rollback_predecessor_profile as profile_tests


DRIVER20_VERIFY_POLICY = "e7e02f82d64b566c733f3fbaf1bb923b48f2c07932d3265d45ca280e08d67ade"


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


class Release134HistoricalClosureTests(unittest.TestCase):
    setUp = profile_tests.RollbackPredecessorProfileTests.setUp
    source_contract = profile_tests.RollbackPredecessorProfileTests.source_contract
    full_gate = profile_tests.RollbackPredecessorProfileTests.full_gate

    def test_driver20_policy_digest_remains_the_predecessor_authority(self):
        policy = {
            "command": ["/usr/bin/rpm", "-V", "lto-ltfs"],
            "package_nevra": "lto-ltfs-0.1.0-20.el9.x86_64",
            "permitted_rows": ["S.5....T.  c /etc/lto-ltfs/device.json"],
            "schema": 1,
            "stderr": "",
            "success_exit_codes": [1],
        }
        digest = hashlib.sha256(canonical(policy)).hexdigest()
        self.assertEqual(DRIVER20_VERIFY_POLICY, digest)

    def test_release134_schema40_driver20_remains_a_valid_historical_profile(self):
        self.assertTrue(
            self.full_gate(134, 40, driver_release=20, reader="inactive")
        )


if __name__ == "__main__":
    unittest.main()
