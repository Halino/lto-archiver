"""Protected rollback sources must follow the recorded predecessor profile."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
import tempfile
import unittest
from contextlib import ExitStack, closing
from datetime import UTC, datetime
from pathlib import Path
from unittest import mock

from tests.test_rhel9_live_verifier import _load_module


class RollbackPredecessorProfileTests(unittest.TestCase):
    def setUp(self):
        self.module = _load_module()
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.bundle = Path(temporary.name)
        self.recovery = self.bundle / "release-recovery"
        self.recovery.mkdir(mode=0o700)
        self.recovery.chmod(0o700)
        # Only ownership expectations are adapted to the unprivileged runner.
        # File validation, copying, hashing and SQLite inspection remain real.
        for name, value in (("_ROOT_UID", os.getuid()), ("_ROOT_GID", os.getgid())):
            patch = mock.patch.object(self.module, name, value)
            patch.start()
            self.addCleanup(patch.stop)

    def source_contract(self, app_release: int, schema: int, *, driver_release: int = 16):
        path = self.recovery / (
            f"20260906T120000000000Z-abcdef123456-p-v{schema}-0123456789abcdef.sqlite3"
        )
        with closing(sqlite3.connect(path)) as connection, connection:
            connection.execute("CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT)")
            connection.execute(
                "INSERT INTO metadata VALUES('schema_version', ?)", (str(schema),)
            )
        path.chmod(0o600)
        original = path.read_bytes()
        return (
            path,
            original,
            {
                "schema": 2,
                "installed_nevras": {
                    "lto-archiver": f"lto-archiver-0.11.27-{app_release}.el9.noarch",
                    "lto-archiver-python-runtime": (
                        "lto-archiver-python-runtime-0.11.27-3.el9.x86_64"
                    ),
                    "lto-ltfs": f"lto-ltfs-0.1.0-{driver_release}.el9.x86_64",
                },
                "protected_backup_relative_path": path.relative_to(
                    self.bundle
                ).as_posix(),
                "protected_backup_sha256": hashlib.sha256(original).hexdigest(),
                "source_catalog_schema": schema,
                "source_catalog_sha256": hashlib.sha256(original).hexdigest(),
            },
        )

    def assert_source_admitted(self, app_release: int, schema: int):
        path, original, contract = self.source_contract(app_release, schema)
        observation = self.module.SystemLiveHost._database(
            path, catalog=True, catalog_schema=str(schema), protected_catalog=True
        )
        self.assertTrue(observation.integrity_ok)
        self.assertTrue(observation.foreign_keys_ok)
        self.assertTrue(observation.schema_ok)
        self.assertTrue(
            self.module._legacy_protected_source_ok(self.bundle, contract),
            f"valid app{app_release}/schema{schema} protected source was rejected",
        )
        self.assertEqual(original, path.read_bytes())

    def test_historical101_schema35_protected_source_remains_valid(self):
        self.assert_source_admitted(101, 35)

    def test_current129_schema40_protected_source_is_valid(self):
        self.assert_source_admitted(129, 40)

    def test_historical_release132_accepts_exact131_driver17_protected_source(self):
        path, original, contract = self.source_contract(131, 40, driver_release=17)
        self.assertTrue(self.module._legacy_protected_source_ok(self.bundle, contract))
        for application, driver, schema in ((131, 18, 40), (132, 17, 40), (131, 17, 35)):
            changed = {**contract, "source_catalog_schema": schema,
                       "installed_nevras": {**contract["installed_nevras"],
                           "lto-archiver": f"lto-archiver-0.11.27-{application}.el9.noarch",
                           "lto-ltfs": f"lto-ltfs-0.1.0-{driver}.el9.x86_64"}}
            with self.subTest(application=application, driver=driver, schema=schema):
                self.assertFalse(self.module._legacy_protected_source_ok(self.bundle, changed))
        self.assertEqual(original, path.read_bytes())

    def test_release133_accepts_exact132_driver18_protected_source(self):
        path, original, contract = self.source_contract(132, 40, driver_release=18)
        self.assertTrue(self.module._legacy_protected_source_ok(self.bundle, contract))
        for application, driver, schema in (
            (132, 19, 40), (133, 18, 40), (136, 18, 40), (132, 18, 35),
        ):
            changed = {**contract, "source_catalog_schema": schema,
                       "installed_nevras": {**contract["installed_nevras"],
                           "lto-archiver": f"lto-archiver-0.11.27-{application}.el9.noarch",
                           "lto-ltfs": f"lto-ltfs-0.1.0-{driver}.el9.x86_64"}}
            with self.subTest(application=application, driver=driver, schema=schema):
                self.assertFalse(self.module._legacy_protected_source_ok(self.bundle, changed))
        self.assertEqual(original, path.read_bytes())

    def test_release134_accepts_exact133_driver19_protected_source(self):
        path, original, contract = self.source_contract(133, 40, driver_release=19)
        self.assertTrue(self.module._legacy_protected_source_ok(self.bundle, contract))
        for application, driver, schema in (
            (133, 20, 40), (134, 19, 40), (136, 19, 40), (133, 19, 35),
        ):
            changed = {**contract, "source_catalog_schema": schema,
                       "installed_nevras": {**contract["installed_nevras"],
                           "lto-archiver": f"lto-archiver-0.11.27-{application}.el9.noarch",
                           "lto-ltfs": f"lto-ltfs-0.1.0-{driver}.el9.x86_64"}}
            with self.subTest(application=application, driver=driver, schema=schema):
                self.assertFalse(self.module._legacy_protected_source_ok(self.bundle, changed))
        self.assertEqual(original, path.read_bytes())

    def test_historical134_driver20_protected_source_remains_valid(self):
        path, original, contract = self.source_contract(134, 40, driver_release=20)
        self.assertTrue(self.module._legacy_protected_source_ok(self.bundle, contract))
        for application, driver, schema in (
            (134, 21, 40), (135, 20, 40), (136, 20, 40), (134, 20, 35),
        ):
            changed = {**contract, "source_catalog_schema": schema,
                       "installed_nevras": {**contract["installed_nevras"],
                           "lto-archiver": f"lto-archiver-0.11.27-{application}.el9.noarch",
                           "lto-ltfs": f"lto-ltfs-0.1.0-{driver}.el9.x86_64"}}
            with self.subTest(application=application, driver=driver, schema=schema):
                self.assertFalse(self.module._legacy_protected_source_ok(self.bundle, changed))
        self.assertEqual(original, path.read_bytes())

    def test_release136_accepts_exact135_driver21_protected_source(self):
        path, original, contract = self.source_contract(135, 40, driver_release=21)
        self.assertTrue(self.module._legacy_protected_source_ok(self.bundle, contract))
        for application, driver, schema in (
            (135, 20, 40), (136, 20, 40), (134, 21, 40), (135, 21, 35),
        ):
            changed = {**contract, "source_catalog_schema": schema,
                       "installed_nevras": {**contract["installed_nevras"],
                           "lto-archiver": f"lto-archiver-0.11.27-{application}.el9.noarch",
                           "lto-ltfs": f"lto-ltfs-0.1.0-{driver}.el9.x86_64"}}
            with self.subTest(application=application, driver=driver, schema=schema):
                self.assertFalse(self.module._legacy_protected_source_ok(self.bundle, changed))
        self.assertEqual(original, path.read_bytes())

    def test_release131_accepts_exact130_driver17_schema40_protected_source(self):
        path, original, contract = self.source_contract(130, 40, driver_release=17)
        self.assertTrue(self.module._legacy_protected_source_ok(self.bundle, contract))
        for application, driver, schema in ((129, 17, 40), (130, 16, 40),
                                            (132, 17, 40), (130, 17, 35)):
            changed = {**contract, "source_catalog_schema": schema,
                       "installed_nevras": {**contract["installed_nevras"],
                           "lto-archiver": f"lto-archiver-0.11.27-{application}.el9.noarch",
                           "lto-ltfs": f"lto-ltfs-0.1.0-{driver}.el9.x86_64"}}
            with self.subTest(application=application, driver=driver, schema=schema):
                self.assertFalse(self.module._legacy_protected_source_ok(self.bundle, changed))
        self.assertEqual(original, path.read_bytes())

    def test_historical_protected_source_digest_mismatch_is_rejected(self):
        path, original, contract = self.source_contract(101, 35)
        contract["protected_backup_sha256"] = "0" * 64
        self.assertFalse(self.module._legacy_protected_source_ok(self.bundle, contract))
        self.assertEqual(original, path.read_bytes())

    def test_schema40_filename_does_not_authorize_schema35_database(self):
        path, original, contract = self.source_contract(129, 40)
        with closing(sqlite3.connect(path)) as connection, connection:
            connection.execute("UPDATE metadata SET value='35'")
        changed = path.read_bytes()
        self.assertNotEqual(original, changed)
        contract["protected_backup_sha256"] = hashlib.sha256(changed).hexdigest()
        self.assertFalse(self.module._legacy_protected_source_ok(self.bundle, contract))
        self.assertEqual(changed, path.read_bytes())

    def test_crossed_and_unknown_predecessor_profiles_are_rejected(self):
        path, original, contract = self.source_contract(129, 40)
        for package, nevra in (
            ("lto-archiver", "lto-archiver-0.11.27-101.el9.noarch"),
            ("lto-archiver", "lto-archiver-0.11.27-127.el9.noarch"),
            ("lto-archiver", "lto-archiver-0.11.27-130.el9.noarch"),
            (
                "lto-archiver-python-runtime",
                "lto-archiver-python-runtime-0.11.27-4.el9.x86_64",
            ),
            ("lto-ltfs", "lto-ltfs-0.1.0-17.el9.x86_64"),
        ):
            changed = {
                **contract,
                "installed_nevras": {
                    **contract["installed_nevras"],
                    package: nevra,
                },
            }
            with self.subTest(nevra=nevra):
                self.assertFalse(
                    self.module._legacy_protected_source_ok(self.bundle, changed)
                )
        for schema in (35, 41, "40", 40.0, True):
            with self.subTest(schema=schema):
                self.assertFalse(
                    self.module._legacy_protected_source_ok(
                        self.bundle, {**contract, "source_catalog_schema": schema}
                    )
                )
        self.assertEqual(original, path.read_bytes())

    def test_historical_backup_does_not_authorize_current_app_with_schema35(self):
        _path, _original, contract = self.source_contract(101, 35)
        contract["installed_nevras"]["lto-archiver"] = (
            "lto-archiver-0.11.27-129.el9.noarch"
        )
        self.assertFalse(self.module._legacy_protected_source_ok(self.bundle, contract))

    def full_gate(
        self,
        app=129,
        schema=40,
        *,
        driver_release=16,
        restoration="2020-01-02T00:00:00Z",
        reader="active",
        socket_active=True,
        reader_boundary=True,
        new_journal_error=False,
    ):
        _path, _original, contract = self.source_contract(app, schema, driver_release=driver_release)
        contracts = self.bundle / "contracts"
        contracts.mkdir()
        tools = self.bundle / "tools"
        tools.mkdir()
        policy = (
            Path(__file__).resolve().parents[1]
            / "packaging/deployment/rpm-verify-policy.json"
        )
        (tools / "rpm-verify-policy.json").write_bytes(policy.read_bytes())
        nevras = contract["installed_nevras"]
        rpm_rows = {name: "" for name in nevras}
        rpm_rows["lto-ltfs"] = "S.5....T.  c /etc/lto-ltfs/device.json\n"
        enablement = {
            unit: "enabled" if unit.endswith((".socket", "web.service")) else "static"
            for unit in self.module.REQUIRED_ACTIVE_UNITS
        }
        rich = [
            f'rule family="ipv4" source address="{source}" port port="8443" protocol="tcp" accept'
            for source in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
        ]
        contract.update(
            captured_at="2020-01-01T00:00:00Z",
            custom_web_unit_sha256="ABSENT",
            driver_authority={},
            firewall_observation_sha256="b" * 64,
            firewall_policy={
                "schema": 1,
                "zone": "public",
                **{
                    f"{key}_{scope}": rich if key == "rich_rules" else []
                    for key in ("rich_rules", "ports", "services")
                    for scope in ("runtime", "permanent")
                },
            },
            unit_enablement=enablement,
            predecessor_web_probe={
                "url": "https://example.invalid:8443/login",
                "ca_certificate": "/private/ca.crt",
            },
            installed_package_state={
                "schema": 1,
                "packages": {
                    name: {
                        "nevra": nevra,
                        "installed_file_metadata_sha256": hashlib.sha256(
                            f"metadata-{name}\n".encode()
                        ).hexdigest(),
                        "rpm_verify_exit": 1 if rpm_rows[name] else 0,
                        "rpm_verify_stdout_sha256": hashlib.sha256(
                            rpm_rows[name].encode()
                        ).hexdigest(),
                        "rpm_verify_rows": rpm_rows[name].splitlines(),
                    }
                    for name, nevra in nevras.items()
                },
            },
        )
        contract_path = contracts / "old-live-contract.json"
        contract_path.write_bytes(self.module._canonical_bytes(contract))
        (self.bundle / "rollback-SHA256SUMS").write_text(
            "".join(
                sorted(
                    f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(self.bundle).as_posix()}\n"
                    for path in self.bundle.rglob("*")
                    if path.is_file()
                )
            )
        )

        def runner(argv, accepted=(0,)):
            command = tuple(map(str, argv))
            code, output = 0, ""
            if command[0] == "/usr/bin/rpm":
                package = command[-1]
                if "--qf" in command:
                    output = nevras[package]
                elif "--dump" in command:
                    output = f"metadata-{package}\n"
                else:
                    self.assertIn("-V", command)
                    output = rpm_rows[package]
                    code = 1 if output else 0
            elif command[0] == "/usr/bin/systemctl":
                if "is-enabled" in command:
                    output = enablement[command[-1]]
                elif "is-active" in command:
                    output = (
                        reader
                        if command[-1] == "lto-archiver-log-reader.service"
                        else "active"
                    )
                    if (
                        command[-1] == "lto-archiver-log-reader.socket"
                        and not socket_active
                    ):
                        output = "inactive"
                    code = 0 if output == "active" else 3
                else:
                    self.assertIn("--failed", command)
            elif command[0] == "/usr/bin/firewall-cmd":
                output = (
                    "\n".join(sorted(rich)) if "--list-rich-rules" in command else ""
                )
            elif command[0] == "/usr/bin/journalctl":
                since = next(item for item in command if item.startswith("--since=@"))
                restoration_epoch = int(datetime(2020, 1, 2, tzinfo=UTC).timestamp())
                # Candidate failure is before restoration; a second failure is after it.
                if int(since.split("@", 1)[1]) < restoration_epoch or new_journal_error:
                    output = json.dumps(
                        {
                            "_SYSTEMD_UNIT": "lto-archiver-command-broker.service",
                            "PRIORITY": "3",
                            "MESSAGE_ID": "a" * 32,
                        }
                    )
                if app == 101 and not new_journal_error:
                    output = ""
            else:
                raise AssertionError(command)
            return subprocess.CompletedProcess(command, code, output, "")

        def daemon_get(_host, endpoint):
            if endpoint == "/api/v1/status":
                return {
                    "api_version": 1,
                    "accepting_mutations": True,
                    "job": {"state": "paused"},
                    "operation": None,
                    "admission_blocker": None,
                    "critical_recovery": None,
                }
            if endpoint == "/api/v1/health":
                return {"api_version": 1, "status": "ok"}
            return []

        def databases(_host, *, catalog_schema, protected_backup_required):
            self.assertEqual(str(schema), catalog_schema)
            self.assertFalse(protected_backup_required)
            return {
                name: self.module.DatabaseObservation(True, True, True)
                for name in self.module.REQUIRED_DATABASES
            }

        with ExitStack() as stack:
            for name, replacement in (
                ("_run", staticmethod(runner)),
                ("_require_root_tool", staticmethod(lambda _path: None)),
                ("_daemon_get", daemon_get),
                ("_databases", databases),
                ("_log_reader_boundary_ok", lambda _host: reader_boundary),
                (
                    "_inventory",
                    lambda *_args: self.module.InventoryObservation(
                        0, 0, 0, "d" * 64, True, True
                    ),
                ),
            ):
                stack.enter_context(
                    mock.patch.object(self.module.SystemLiveHost, name, replacement)
                )
            stack.enter_context(
                mock.patch.object(
                    self.module, "_legacy_https_login_ok", return_value=True
                )
            )
            if restoration is None:
                return self.module._legacy_rollback_gate(contract_path, self.bundle)
            return self.module._legacy_rollback_gate(
                contract_path, self.bundle, restoration_started_at=restoration
            )

    def test_full_historical101_gate_preserves_original_interval(self):
        self.assertTrue(self.full_gate(101, 35, restoration=None))

    def test_full_current129_gate_excludes_prior_candidate_error(self):
        self.assertTrue(self.full_gate())

    def test_full_current130_driver17_rollback_health_gate(self):
        self.assertTrue(self.full_gate(130, 40, driver_release=17, reader="inactive"))

    def test_full_current131_driver17_rollback_health_gate(self):
        self.assertTrue(self.full_gate(131, 40, driver_release=17, reader="inactive"))

    def test_full_current132_driver18_rollback_health_gate(self):
        self.assertTrue(self.full_gate(132, 40, driver_release=18, reader="inactive"))

    def test_full_current129_gate_rejects_new_restoration_error(self):
        self.assertFalse(self.full_gate(new_journal_error=True))

    def test_full_current129_gate_requires_restoration_timestamp(self):
        self.assertFalse(self.full_gate(restoration=None))

    def test_full_current129_gate_accepts_only_healthy_on_demand_reader(self):
        self.assertTrue(self.full_gate(reader="inactive"))

    def test_full_current129_gate_rejects_failed_reader(self):
        self.assertFalse(self.full_gate(reader="failed"))

    def test_full_current129_gate_rejects_inactive_reader_socket(self):
        self.assertFalse(self.full_gate(reader="inactive", socket_active=False))

    def test_full_current129_gate_rejects_invalid_reader_boundary(self):
        self.assertFalse(self.full_gate(reader="inactive", reader_boundary=False))

    def test_full_current129_gate_rejects_timestamp_before_capture(self):
        self.assertFalse(self.full_gate(restoration="2019-12-31T23:59:59Z"))

    def test_full_current129_gate_rejects_future_timestamp(self):
        self.assertFalse(self.full_gate(restoration="2999-01-01T00:00:00Z"))


if __name__ == "__main__":
    unittest.main()
