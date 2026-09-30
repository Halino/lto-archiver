import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ltobackup.errors import ValidationError
from ltobackup.linux_settings import LinuxPaths, LinuxSettings, load_linux_settings


class LinuxSettingsTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.root = Path(self.tempdir.name)

    def test_for_root_uses_fixed_subdirectories(self):
        paths = LinuxPaths.for_root(Path("/tmp/state"), Path("/tmp/run/daemon.sock"))
        self.assertEqual(Path("/tmp/state/catalog.db"), paths.catalog_file)
        self.assertEqual(Path("/tmp/state/backups"), paths.backup_dir)
        self.assertEqual(Path("/tmp/state/migrations"), paths.migration_dir)
        self.assertEqual(Path("/tmp/state"), paths.state_dir)
        self.assertEqual(Path("/tmp/run/daemon.sock"), paths.socket_path)

    def test_from_settings_uses_configured_root_and_socket(self):
        settings = valid_settings()
        paths = LinuxPaths.from_settings(settings)
        self.assertEqual(settings.state_dir, paths.state_dir)
        self.assertEqual(settings.socket_path, paths.socket_path)
        self.assertEqual(settings.state_dir / "catalog.db", paths.catalog_file)

    def test_every_configured_path_must_be_absolute(self):
        for field, value in (
            ("state_dir", Path("state")),
            ("socket_path", Path("run/daemon.sock")),
            ("tape_device_path", Path("dev/tape/by-id/drive")),
            ("scsi_device_path", Path("dev/lto-archiver-scsi-drive")),
            ("mount_path", Path("relative")),
            ("managed_source_mount_root", Path("relative-managed-source")),
            ("source_roots", (Path("relative-source"),)),
            ("restore_roots", (Path("relative-restore"),)),
        ):
            with (
                self.subTest(field=field, value=value),
                self.assertRaises(ValidationError),
            ):
                valid_settings(**{field: value}).validate()

    def test_fixed_managed_source_mount_root_is_distinct_from_other_roots(self):
        self.assertEqual(
            Path("/mnt/lto-archiver/sources"),
            valid_settings().managed_source_mount_root,
        )
        cases = (
            {"state_dir": Path("/mnt/lto-archiver/sources/state")},
            {"mount_path": Path("/mnt/lto-archiver/sources/tape")},
            {"source_roots": (Path("/mnt/lto-archiver/sources/source"),)},
            {"restore_roots": (Path("/mnt/lto-archiver/sources/restore"),)},
        )
        for overrides in cases:
            with (
                self.subTest(overrides=overrides),
                self.assertRaisesRegex(ValidationError, "overlap"),
            ):
                valid_settings(**overrides).validate()

    def test_managed_source_mount_root_is_the_fixed_packaged_security_boundary(self):
        with self.assertRaisesRegex(
            ValidationError, "managed_source_mount_root must be the packaged path"
        ):
            valid_settings(
                managed_source_mount_root=Path("/opt/lto-archiver/sources")
            ).validate()

    def test_loader_parses_the_closed_share_endpoint_host_settings(self):
        config = write_valid_toml(self.root / "shares.toml")
        loaded = load_linux_settings(config)
        self.assertEqual(
            Path("/mnt/lto-archiver/sources"), loaded.managed_source_mount_root
        )
        self.assertEqual(
            ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "fe80::/10"),
            loaded.share_endpoint_cidrs,
        )
        self.assertEqual((".lan", ".local"), loaded.share_endpoint_dns_suffixes)

    def test_state_socket_mount_source_and_restore_overlap_is_bidirectionally_rejected(
        self,
    ):
        cases = (
            {"socket_path": Path("/var/lib/lto-archiver/daemon.sock")},
            {"mount_path": Path("/var/lib/lto-archiver/tape")},
            {"state_dir": Path("/mnt/lto-archiver/tape/state")},
            {"source_roots": (Path("/var/lib/lto-archiver/source"),)},
            {"source_roots": (Path("/var/lib"),)},
            {"source_roots": (Path("/mnt/lto-archiver/tape/source"),)},
            {
                "mount_path": Path("/srv/private"),
                "source_roots": (Path("/srv/private/film"),),
            },
            {
                "mount_path": Path("/srv/restore"),
                "restore_roots": (Path("/srv/restore/job"),),
            },
            {"restore_roots": (Path("/var/lib/lto-archiver/restore"),)},
            {"restore_roots": (Path("/var/lib"),)},
            {
                "source_roots": (Path("/srv/media"),),
                "restore_roots": (Path("/srv/media/restored"),),
            },
            {
                "source_roots": (Path("/srv/media/source"),),
                "restore_roots": (Path("/srv/media"),),
            },
        )
        for overrides in cases:
            with (
                self.subTest(overrides=overrides),
                self.assertRaisesRegex(ValidationError, "overlap"),
            ):
                valid_settings(**overrides).validate()

    def test_rejects_transient_or_non_tape_device_identifiers(self):
        for field, value in (
            ("tape_device_path", Path("/dev/st0")),
            ("scsi_device_path", Path("/dev/sg0")),
            ("tape_device_path", Path("/dev/disk/by-id/not-a-tape")),
            ("tape_device_path", Path("/dev/tape/by-id/rewinding-drive")),
            ("scsi_device_path", Path("/dev/disk/by-id/scsi-drive")),
            (
                "scsi_device_path",
                Path("/dev/lto-archiver/by-id/generic-drive"),
            ),
            (
                "scsi_device_path",
                Path("/dev/lto-archiver/by-id/scsi-drive"),
            ),
            ("scsi_device_path", Path("/dev/lto-archiver-scsi-")),
            ("scsi_device_path", Path("/dev/nested/lto-archiver-scsi-drive")),
        ):
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(ValidationError, "stable.*alias"),
            ):
                valid_settings(**{field: value}).validate()

    def test_accepts_tape_by_id_symlink_to_transient_node(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tape_namespace = root / "tape" / "by-id"
            tape_namespace.mkdir(parents=True)
            (root / "st0").touch()
            configured = tape_namespace / "lto-drive-nst"
            configured.symlink_to(root / "st0")
            with patch("ltobackup.linux_settings._TAPE_ID_NAMESPACE", tape_namespace):
                valid_settings(tape_device_path=configured).validate()

    def test_accepts_flat_scsi_alias_symlink_to_transient_node(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "sg0").touch()
            configured = root / "lto-archiver-scsi-generic"
            configured.symlink_to(root / "sg0")
            with patch("ltobackup.linux_settings._SCSI_DEVICE_ROOT", root):
                valid_settings(scsi_device_path=configured).validate()

    def test_rejects_invalid_socket_group(self):
        for value in ("", "-lto-web", "lto web", "lto/web", "x" * 33):
            with (
                self.subTest(value=value),
                self.assertRaisesRegex(ValidationError, "socket_group"),
            ):
                valid_settings(socket_group=value).validate()

    def test_loader_rejects_unknown_keys_including_credential_shaped_keys(self):
        for extra, rejected in (
            ('smb_password = "must-not-be-accepted"', "smb_password"),
            ('[undeclared]\nvalue = "no"', "undeclared"),
        ):
            config = write_valid_toml(self.root / f"{rejected}.toml")
            config.write_text(config.read_text() + "\n" + extra + "\n")
            with (
                self.subTest(rejected=rejected),
                self.assertRaisesRegex(ValidationError, f"unknown.*{rejected}"),
            ):
                load_linux_settings(config)

    def test_loader_accepts_declared_toml_data(self):
        config = write_valid_toml(self.root / "config.toml")
        loaded = load_linux_settings(config)
        self.assertIsInstance(loaded, LinuxSettings)
        self.assertEqual(Path("/srv/media"), loaded.source_roots[0])

    def test_buffer_size_outside_closed_range_is_rejected(self):
        for value in (0, 1024 * 1024 - 1, 64 * 1024 * 1024 + 1):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                valid_settings(buffer_bytes=value).validate()

    def test_safe_summary_redacts_sensitive_paths_and_never_serializes_secrets(self):
        settings = valid_settings(
            source_roots=(Path("/srv/private/film"),),
            restore_roots=(Path("/srv/private/restore"),),
        )
        rendered = json.dumps(settings.safe_summary(), sort_keys=True)
        sensitive = (
            settings.state_dir,
            settings.socket_path,
            settings.tape_device_path,
            settings.scsi_device_path,
            settings.mount_path,
            *settings.source_roots,
            *settings.restore_roots,
        )
        for value in sensitive:
            with self.subTest(value=value):
                self.assertNotIn(str(value), rendered)
        self.assertEqual(1, settings.safe_summary()["source_root_count"])
        self.assertEqual(1, settings.safe_summary()["restore_root_count"])
        self.assertEqual(
            {
                "source_root_count",
                "restore_root_count",
                "buffer_bytes",
                "socket_group",
                "stable_tape_id_configured",
                "stable_scsi_id_configured",
            },
            set(settings.safe_summary()),
        )


def valid_settings(**overrides):
    values = {
        "state_dir": Path("/var/lib/lto-archiver"),
        "socket_path": Path("/run/lto-archiver/daemon.sock"),
        "socket_group": "lto-web",
        "tape_device_path": Path("/dev/tape/by-id/configure-drive-nst"),
        "scsi_device_path": Path("/dev/lto-archiver-scsi-configure-drive"),
        "mount_path": Path("/mnt/lto-archiver/tape"),
        "managed_source_mount_root": Path("/mnt/lto-archiver/sources"),
        "source_roots": (Path("/srv/media"),),
        "restore_roots": (Path("/srv/restore"),),
        "share_endpoint_cidrs": (
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "fc00::/7",
            "fe80::/10",
        ),
        "share_endpoint_dns_suffixes": (".lan", ".local"),
        "buffer_bytes": 8 * 1024 * 1024,
    }
    values.update(overrides)
    return LinuxSettings(**values)


def write_valid_toml(path: Path) -> Path:
    path.write_text(
        """state_dir = \"/var/lib/lto-archiver\"
socket_path = \"/run/lto-archiver/daemon.sock\"
socket_group = \"lto-web\"
tape_device_path = \"/dev/tape/by-id/configure-drive-nst\"
scsi_device_path = \"/dev/lto-archiver-scsi-configure-drive\"
mount_path = \"/mnt/lto-archiver/tape\"
managed_source_mount_root = \"/mnt/lto-archiver/sources\"
source_roots = [\"/srv/media\"]
restore_roots = [\"/srv/restore\"]
share_endpoint_cidrs = [\"10.0.0.0/8\", \"172.16.0.0/12\", \"192.168.0.0/16\", \"fc00::/7\", \"fe80::/10\"]
share_endpoint_dns_suffixes = [\".lan\", \".local\"]
buffer_bytes = 8388608
""",
        encoding="utf-8",
    )
    return path
