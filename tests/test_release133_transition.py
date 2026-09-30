"""Historical release133/runtime3/driver19 closure invariants.

Current release-transition behavior is covered by test_release135_transition.
This module retains immutable predecessor facts relevant after application134.
"""

from __future__ import annotations

import hashlib
import json
import unittest

from tests import test_rhel9_rollback_predecessor_profile as profile_tests


DRIVER19_VERIFY_POLICY = "1047fb218b397967999172e7ca3d8cf423b0012fb2bb2dd2ef519bd1da2fc818"


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


class Release133HistoricalClosureTests(unittest.TestCase):
    setUp = profile_tests.RollbackPredecessorProfileTests.setUp
    source_contract = profile_tests.RollbackPredecessorProfileTests.source_contract
    full_gate = profile_tests.RollbackPredecessorProfileTests.full_gate

    def test_driver19_policy_digest_remains_the_predecessor_authority(self):
        policy = {
            "command": ["/usr/bin/rpm", "-V", "lto-ltfs"],
            "package_nevra": "lto-ltfs-0.1.0-19.el9.x86_64",
            "permitted_rows": ["S.5....T.  c /etc/lto-ltfs/device.json"],
            "schema": 1,
            "stderr": "",
            "success_exit_codes": [1],
        }
        digest = hashlib.sha256(canonical(policy)).hexdigest()
        self.assertEqual(DRIVER19_VERIFY_POLICY, digest)

    def test_release133_schema40_driver19_remains_a_valid_historical_profile(self):
        self.assertTrue(
            self.full_gate(133, 40, driver_release=19, reader="inactive")
        )


if __name__ == "__main__":
    unittest.main()
