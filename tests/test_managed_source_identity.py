"""Legacy NFS pins must survive only a provable anonymous-device renumbering."""
import hashlib
import json
import os
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from ltobackup import managed_sources


def legacy_pin(root, device, inode):
    raw = json.dumps({'canonical_root': str(root), 'device': device, 'inode': inode},
                     sort_keys=True, separators=(',', ':')).encode()
    return hashlib.sha256(raw).hexdigest()


class NfsRootIdentityTests(unittest.TestCase):
    def setUp(self):
        self.root = Path('/mnt/lto-archiver/sources/anime')
        self.old = {
            'kind': 'managed_share', 'share_id': 'anime', 'resource_revision': 3,
            'config_revision': 2, 'credential_generation': 0,
            'mount_identity_sha256': 'a' * 64, 'read_only': True,
            'filesystem_type': 'nfs4', 'source_sha256': 'b' * 64,
            'admitted_endpoints_sha256': 'c' * 64, 'relative_subpath': '',
            'source_identity_sha256': '02393970e01c35bd43c734dc4ce4fccc7c6d0e34c99806c2b98773f06c3eaa9b',
        }
        self.current = {**self.old, 'source_identity_sha256': legacy_pin(self.root, 53, 26)}

    def matches(self, old=None, current=None, *, device=53, inode=26, root=None):
        root = self.root if root is None else root
        if current is None:
            current = {**self.current, 'source_identity_sha256': legacy_pin(root, device, inode)}
        with patch.object(Path, 'stat', return_value=SimpleNamespace(st_dev=device, st_ino=inode)):
            return managed_sources._matches_renumbered_nfs_root(
                self.old if old is None else old,
                current,
                root,
            )

    def test_server_fixture_proves_only_device_changed(self):
        self.assertEqual(self.old['source_identity_sha256'], legacy_pin(self.root, 54, 26))
        self.assertTrue(self.matches())

    def test_changed_inode_path_or_nonanonymous_device_is_rejected(self):
        for args in ({'inode': 27}, {'root': self.root / 'replacement'},
                     {'device': os.makedev(8, 1)}):
            with self.subTest(args=args):
                self.assertFalse(self.matches(**args))

    def test_every_other_frozen_field_remains_exact(self):
        changes = {'share_id': 'film', 'resource_revision': 4, 'config_revision': 3,
                   'credential_generation': 1, 'mount_identity_sha256': 'd' * 64,
                   'read_only': False, 'filesystem_type': 'nfs',
                   'source_sha256': 'e' * 64, 'admitted_endpoints_sha256': 'f' * 64,
                   'relative_subpath': 'media'}
        for field, value in changes.items():
            with self.subTest(field=field):
                self.assertFalse(self.matches(current={**self.current, field: value}))

    def test_subdirectories_and_other_filesystems_do_not_gain_compatibility(self):
        for field, value in (('relative_subpath', 'media'), ('filesystem_type', 'cifs'),
                             ('filesystem_type', 'ext4')):
            with self.subTest(field=field, value=value):
                self.assertFalse(self.matches(old={**self.old, field: value},
                                              current={**self.current, field: value}))

    def test_out_of_bound_historical_device_is_not_accepted(self):
        old = {**self.old, 'source_identity_sha256': legacy_pin(self.root, os.makedev(0, 4096), 26)}
        self.assertFalse(self.matches(old=old))

    def test_cached_success_does_not_admit_changed_inode_or_evidence(self):
        self.assertTrue(self.matches())
        self.assertFalse(self.matches(inode=29))
        self.assertFalse(self.matches(current={**self.current, 'source_sha256': 'f' * 64}))

    def test_changed_snapshot_between_observation_and_proof_is_rejected(self):
        stale = {**self.current, 'source_identity_sha256': legacy_pin(self.root, 52, 26)}
        self.assertFalse(self.matches(current=stale))


if __name__ == '__main__':
    unittest.main()
