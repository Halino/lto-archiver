from __future__ import annotations

import dataclasses
import hashlib
import importlib.util
import inspect
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from ltobackup.catalog import Catalog
from ltobackup.daemon.backups import BackupManager
from tests.fixtures import build_frozen_job_fixture

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "packaging" / "scripts" / "verify-deployment-rhel9.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("verify_deployment_rhel9", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load deployment verifier")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


class FakeLiveHost:
    def __init__(self, module, observation) -> None:
        self.module = module
        self.observation = observation
        self.observe_calls = 0
        self.mutation_calls: list[str] = []

    def observe(self, request):
        self.observe_calls += 1
        return self.observation

    def mount(self, *_args):
        self.mutation_calls.append("mount")
        raise AssertionError("live verifier attempted a mutation")

    format = mount
    unmount = mount
    scan = mount
    broker_command = mount
    media_probe = mount


class Rhel9LiveVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = _load_module()
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.rpm_policy = self.root / "rpm-policy.json"
        self.journal_policy = self.root / "journal-policy.json"
        self.driver_contract = self.root / "driver-input.json"
        self.rpm_policy.write_text(
            json.dumps(
                {
                    "packages": {
                        "lto-archiver": {
                            "allowed_config_paths": {
                                "/etc/lto-archiver/config.toml": ["5", "S", "T"],
                                "/etc/lto-archiver/web.toml": ["5", "S", "T"],
                            }
                        },
                        "lto-archiver-python-runtime": {"allowed_config_paths": {}},
                    },
                    "schema": 1,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n",
            encoding="utf-8",
        )
        self.journal_policy.write_text(
            '{"allowlist":[],"schema":1}\n', encoding="utf-8"
        )
        contract = {
            "installed_file_metadata_sha256": "1" * 64,
            "package_nevra": "lto-ltfs-0.1.0-21.el9.x86_64",
            "rpm_header_sha256": "2" * 64,
            "rpm_payload_sha256": "3" * 64,
            "rpm_public_key_sha256": "4" * 64,
            "rpm_raw_sha256": "5" * 64,
            "rpm_signing_policy_sha256": "6" * 64,
            "rpm_verify_policy_sha256": (
                "39c26ec18c7d8eadaad0c9b1b3d89fc133e5f60fb63f94ed427dbb8839fbadb0"
            ),
            "schema": 1,
            "source_provenance_evidence_sha256": "8" * 64,
            "source_provenance_status": "local-build-identity-only",
        }
        self.driver_bytes = (
            json.dumps(contract, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        self.driver_contract.write_bytes(self.driver_bytes)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _request(self):
        return self.module.VerifyDeploymentRequest(
            expected_nevras={
                "lto-archiver": "lto-archiver-0.11.27-144.el9.noarch",
                "lto-archiver-python-runtime": (
                    "lto-archiver-python-runtime-0.11.27-3.el9.x86_64"
                ),
                "lto-ltfs": "lto-ltfs-0.1.0-21.el9.x86_64",
            },
            rpm_verify_policy=self.rpm_policy,
            journal_policy=self.journal_policy,
            driver_input_contract=self.driver_contract,
            expected_driver_input_sha256=_sha(self.driver_bytes),
            maintenance_started_at="2026-08-29T05:00:00Z",
            artifact_manifest_sha256="a" * 64,
            rollback_manifest_sha256="b" * 64,
        )

    def _observation(self, **changes):
        m = self.module
        observation = m.LiveObservation(
            installed_nevras=self._request().expected_nevras,
            app_runtime_signatures_ok=True,
            driver_contract_ok=True,
            driver_installed_equivalent=True,
            units={
                name: m.UnitObservation(
                    enablement=(
                        "enabled"
                        if name in m.REQUIRED_ENABLED_UNITS
                        else (
                            "static"
                            if name in m.REQUIRED_STATIC_UNITS
                            else "disabled"
                        )
                    ),
                    active=True,
                )
                for name in m.REQUIRED_ACTIVE_UNITS
            },
            failed_unit_count=0,
            daemon=m.DaemonObservation(
                health_ok=True,
                api_v1=True,
                idle=True,
                accepting_mutations=True,
                admission_blocker_count=0,
                critical_recovery_count=0,
            ),
            https_ok=True,
            databases={
                name: m.DatabaseObservation(True, True, True)
                for name in m.REQUIRED_DATABASES
            },
            inventory=m.InventoryObservation(
                library_count=2,
                share_count=1,
                mount_count=1,
                digest="c" * 64,
                reconciled=True,
                no_unmanaged_test_mount=True,
            ),
            firewall=m.FirewallObservation(
                listener_exact=True,
                lan_only=True,
                source_rules=m.REQUIRED_FIREWALL_RULES,
                broad_port_open=False,
                broad_service_open=False,
            ),
            rpm_verify={
                "lto-archiver": (),
                "lto-archiver-python-runtime": (),
            },
            driver_rpm_verify_ok=True,
            priority_journal_events=(),
        )
        return dataclasses.replace(observation, **changes)

    def _verify(self, observation=None):
        host = FakeLiveHost(self.module, observation or self._observation())
        report = self.module.verify_deployment(self._request(), host)
        return report, host

    def test_green_report_requires_exact_nevras_all_units_https_daemon_status_and_databases(self):
        report, host = self._verify()

        self.assertEqual("green", report.status)
        self.assertTrue(report.package_identity_ok)
        self.assertTrue(report.units_ok)
        self.assertTrue(report.daemon_ok)
        self.assertTrue(report.https_ok)
        self.assertTrue(report.databases_ok)
        self.assertEqual(1, host.observe_calls)

    def test_release144_live_gate_requires_current_application_and_driver21(self):
        policy = json.loads((ROOT / "packaging/rpm/driver-rpm-verify-policy.json").read_text())
        policy["package_nevra"] = "lto-ltfs-0.1.0-21.el9.x86_64"
        driver = json.loads(self.driver_bytes)
        driver.update(package_nevra=policy["package_nevra"],
                      rpm_verify_policy_sha256=_sha(self.module._canonical_bytes(policy)))
        self.driver_bytes = self.module._canonical_bytes(driver)
        self.driver_contract.write_bytes(self.driver_bytes)
        current = {**self._request().expected_nevras,
                   "lto-archiver": "lto-archiver-0.11.27-144.el9.noarch",
                   "lto-ltfs": "lto-ltfs-0.1.0-21.el9.x86_64"}
        request = dataclasses.replace(self._request(), expected_nevras=current)
        host = FakeLiveHost(self.module, self._observation(installed_nevras=current))
        self.assertEqual("green", self.module.verify_deployment(request, host).status)
        self.assertEqual([], host.mutation_calls)
        for application, driver in ((143, 21), (141, 21), (144, 20), (141, 20)):
            changed = {**current,
                       "lto-archiver": f"lto-archiver-0.11.27-{application}.el9.noarch",
                       "lto-ltfs": f"lto-ltfs-0.1.0-{driver}.el9.x86_64"}
            host = FakeLiveHost(self.module, self._observation(installed_nevras=changed))
            with self.subTest(application=application, driver=driver):
                self.assertEqual("failed", self.module.verify_deployment(request, host).status)

    def test_release144_live_gate_accepts_only_current_application_with_driver21(self):
        current = {**self._request().expected_nevras,
                   "lto-archiver": "lto-archiver-0.11.27-144.el9.noarch"}
        request = dataclasses.replace(self._request(), expected_nevras=current)
        host = FakeLiveHost(self.module, self._observation(installed_nevras=current))
        report = self.module.verify_deployment(request, host)
        self.assertEqual("green", report.status)
        self.assertEqual([], host.mutation_calls)
        for application, driver in ((143, 21), (141, 21), (144, 20), (141, 20)):
            changed = {**current,
                       "lto-archiver": f"lto-archiver-0.11.27-{application}.el9.noarch",
                       "lto-ltfs": f"lto-ltfs-0.1.0-{driver}.el9.x86_64"}
            host = FakeLiveHost(self.module, self._observation(installed_nevras=changed))
            with self.subTest(application=application, driver=driver):
                self.assertEqual("failed", self.module.verify_deployment(request, host).status)

    def test_stale_release_request_is_rejected_before_host_observation(self):
        for release in (141, 142, 143):
            expected = {**self._request().expected_nevras,
                        "lto-archiver": f"lto-archiver-0.11.27-{release}.el9.noarch"}
            request = dataclasses.replace(self._request(), expected_nevras=expected)
            host = FakeLiveHost(self.module, self._observation(installed_nevras=expected))
            with self.subTest(release=release), self.assertRaises(self.module.ContractError):
                self.module.verify_deployment(request, host)
            self.assertEqual(0, host.observe_calls)
            self.assertEqual([], host.mutation_calls)

    def test_live_maintenance_quiescence_accepts_only_safe_persisted_job_states(self):
        base = {
            "job": None,
            "operation": None,
            "admission_blocker": None,
            "critical_recovery": None,
        }
        self.assertTrue(self.module._daemon_quiescent_for_maintenance(base))
        for state in ("waiting_media", "paused"):
            with self.subTest(state=state):
                self.assertTrue(
                    self.module._daemon_quiescent_for_maintenance(
                        {**base, "job": {"state": state}}
                    )
                )
        for status in (
            {**base, "job": {"state": "writing"}},
            {**base, "job": {"state": "planned"}},
            {**base, "job": {}},
            {**base, "job": "waiting_media"},
            {**base, "operation": {"state": "running"}},
            {**base, "admission_blocker": {"state": "recovery_required"}},
            {**base, "critical_recovery": {"state": "required"}},
            {key: value for key, value in base.items() if key != "job"},
            {},
        ):
            with self.subTest(status=status):
                self.assertFalse(
                    self.module._daemon_quiescent_for_maintenance(status)
                )

    def test_live_verifier_rejects_a_caller_selected_application_or_runtime_release(self):
        for package, stale in (
            ("lto-archiver", "lto-archiver-0.11.27-101.el9.noarch"),
            (
                "lto-archiver-python-runtime",
                "lto-archiver-python-runtime-0.11.27-2.el9.x86_64",
            ),
        ):
            with self.subTest(package=package):
                request = self._request()
                expected = dict(request.expected_nevras)
                expected[package] = stale
                request = dataclasses.replace(request, expected_nevras=expected)
                observation = dataclasses.replace(
                    self._observation(), installed_nevras=expected
                )
                host = FakeLiveHost(self.module, observation)

                with self.assertRaises(self.module.ContractError):
                    self.module.verify_deployment(request, host)

                self.assertEqual(0, host.observe_calls)

    def test_catalog_database_observer_rejects_metadata_only_current_schema40(self):
        self.assertIn(
            "catalog_schema",
            inspect.signature(self.module.SystemLiveHost._database).parameters,
        )
        catalog = self.root / "catalog.db"
        connection = sqlite3.connect(catalog)
        connection.execute("CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT)")
        connection.execute(
            "INSERT INTO metadata(key,value) VALUES('schema_version','40')"
        )
        connection.commit()
        connection.close()

        predecessor = self.module.SystemLiveHost._database(
            catalog,
            catalog=True,
            catalog_schema="39",
        )
        legacy = self.module.SystemLiveHost._database(
            catalog,
            catalog=True,
            catalog_schema="38",
        )
        current = self.module.SystemLiveHost._database(
            catalog,
            catalog=True,
            catalog_schema="40",
        )

        self.assertTrue(predecessor.integrity_ok)
        self.assertTrue(predecessor.foreign_keys_ok)
        self.assertFalse(predecessor.schema_ok)
        self.assertTrue(legacy.integrity_ok)
        self.assertTrue(legacy.foreign_keys_ok)
        self.assertFalse(legacy.schema_ok)
        self.assertTrue(current.integrity_ok)
        self.assertTrue(current.foreign_keys_ok)
        self.assertFalse(current.schema_ok)

        complete = self.root / "complete-schema39.db"
        build_frozen_job_fixture(complete, schema_version=39)
        validated = self.module.SystemLiveHost._database(
            complete,
            catalog=True,
            catalog_schema="39",
        )
        self.assertTrue(all(dataclasses.asdict(validated).values()))

    def test_catalog_database_observer_accepts_only_authentic_schema41(self):
        authentic = self.root / "schema41.db"
        BackupManager(
            authentic, self.root / "schema41-backups", retention=5
        ).prepare_and_initialize()
        with Catalog(authentic) as catalog:
            self.assertEqual(
                "41",
                catalog.connection.execute(
                    "SELECT value FROM metadata WHERE key='schema_version'"
                ).fetchone()[0],
            )

        observed = self.module.SystemLiveHost._database(
            authentic, catalog=True, catalog_schema="41"
        )
        self.assertTrue(all(dataclasses.asdict(observed).values()))

        forged = self.root / "forged-schema41.db"
        with sqlite3.connect(forged) as connection:
            connection.execute("CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT)")
            connection.execute(
                "INSERT INTO metadata(key,value) VALUES('schema_version','41')"
            )
        rejected = self.module.SystemLiveHost._database(
            forged, catalog=True, catalog_schema="41"
        )
        self.assertFalse(rejected.schema_ok)

    def test_database_observer_reads_protected_backups_from_application_layout(self):
        backup_root = self.root / "backups"
        backup_root.mkdir(mode=0o750)
        backup = backup_root / (
            "20260830T120000000000Z-abcdef123456-p-v37-"
            "0123456789abcdef.sqlite3"
        )
        connection = sqlite3.connect(backup)
        connection.execute("CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT)")
        connection.execute(
            "INSERT INTO metadata(key,value) VALUES('schema_version','37')"
        )
        connection.commit()
        connection.close()
        backup.chmod(0o600)
        host = object.__new__(self.module.SystemLiveHost)

        with (
            mock.patch.object(
                self.module, "_PROTECTED_BACKUP_ROOT", backup_root, create=True
            ),
            mock.patch.object(host, "_share_state_ok", return_value=True),
        ):
            databases = host._databases(catalog_schema="40")

        self.assertTrue(
            all(
                dataclasses.asdict(
                    databases["protected_catalog_backup"]
                ).values()
            )
        )

    def test_legacy_schema35_database_gate_requires_an_exact_backup(self):
        backup_root = self.root / "legacy-backups"
        backup_root.mkdir(mode=0o750)
        host = object.__new__(self.module.SystemLiveHost)

        def write_backup(name: str, schema: str) -> Path:
            path = backup_root / name
            connection = sqlite3.connect(path)
            connection.execute(
                "CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT)"
            )
            connection.execute(
                "INSERT INTO metadata(key,value) VALUES('schema_version',?)",
                (schema,),
            )
            connection.commit()
            connection.close()
            path.chmod(0o600)
            return path

        write_backup(
            "20260830T120000000000Z-abcdef123456-p-v34-"
            "0123456789abcdef.sqlite3",
            "34",
        )
        with (
            mock.patch.object(
                self.module, "_PROTECTED_BACKUP_ROOT", backup_root, create=True
            ),
            mock.patch.object(
                host,
                "_database",
                return_value=self.module.DatabaseObservation(True, True, True),
            ),
            mock.patch.object(host, "_share_state_ok", return_value=True),
        ):
            only_older = host._databases(
                catalog_schema="35", protected_backup_required=True
            )
        self.assertFalse(only_older["protected_catalog_backup"].schema_ok)

        write_backup(
            "20260830T120000000001Z-abcdef123456-p-v35-"
            "0123456789abcdef.sqlite3",
            "35",
        )
        with (
            mock.patch.object(
                self.module, "_PROTECTED_BACKUP_ROOT", backup_root, create=True
            ),
            mock.patch.object(host, "_database", return_value=self.module.DatabaseObservation(True, True, True)),
            mock.patch.object(host, "_share_state_ok", return_value=True),
        ):
            exact = host._databases(
                catalog_schema="35", protected_backup_required=True
            )
        self.assertTrue(exact["protected_catalog_backup"].schema_ok)

        with (
            mock.patch.object(
                self.module, "_PROTECTED_BACKUP_ROOT", backup_root, create=True
            ),
            mock.patch.object(host, "_database", return_value=self.module.DatabaseObservation(True, True, True)),
            mock.patch.object(host, "_share_state_ok", return_value=True),
        ):
            legacy = host._databases(
                catalog_schema="35", protected_backup_required=False
            )
        self.assertTrue(legacy["protected_catalog_backup"].schema_ok)

    def test_protected_backup_observer_matches_canonical_filename_schema_and_range(
        self,
    ) -> None:
        cases = (
            (
                "20260830T120000000000Z-abcdef123456-p-v13-"
                "0123456789abcdef.sqlite3",
                "13",
                True,
            ),
            (
                "20260830T120000000000Z-abcdef123456-p-v34-"
                "0123456789abcdef.sqlite3",
                "34",
                True,
            ),
            (
                "20260830T120000000000Z-abcdef123456-p-v33-"
                "0123456789abcdef.sqlite3",
                "34",
                False,
            ),
            (
                "20260830T120000000000Z-abcdef123456-p-v12-"
                "0123456789abcdef.sqlite3",
                "12",
                False,
            ),
            (
                "20260830T120000000000Z-abcdef123456-p-v35-"
                "0123456789abcdef.sqlite3",
                "35",
                True,
            ),
            (
                "20260830T120000000000Z-abcdef123456-o-v35-"
                "0123456789abcdef.sqlite3",
                "35",
                False,
            ),
            (
                "20260830T120000000000Z-abcdef123456-p-v36-"
                "0123456789abcdef.sqlite3",
                "36",
                True,
            ),
            (
                "20260830T120000000000Z-abcdef123456-p-v37-"
                "0123456789abcdef.sqlite3",
                "37",
                True,
            ),
            (
                "20260830T120000000000Z-abcdef123456-p-v38-"
                "0123456789abcdef.sqlite3",
                "38",
                True,
            ),
            (
                "20260830T120000000000Z-abcdef123456-p-v39-"
                "0123456789abcdef.sqlite3",
                "39",
                True,
            ),
            (
                "20260830T120000000000Z-abcdef123456-p-v40-"
                "0123456789abcdef.sqlite3",
                "40",
                True,
            ),
            (
                "20260830T120000000000Z-abcdef123456-p-v41-"
                "0123456789abcdef.sqlite3",
                "41",
                False,
            ),
            ("invalid-p-v34-name.sqlite3", "34", False),
        )
        host = object.__new__(self.module.SystemLiveHost)
        for index, (filename, schema, expected) in enumerate(cases):
            with self.subTest(filename=filename, schema=schema):
                backup_root = self.root / f"protected-{index}"
                backup_root.mkdir(mode=0o750)
                connection = sqlite3.connect(backup_root / filename)
                connection.execute(
                    "CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT)"
                )
                connection.execute(
                    "INSERT INTO metadata(key,value) VALUES('schema_version',?)",
                    (schema,),
                )
                connection.commit()
                connection.close()
                (backup_root / filename).chmod(0o600)
                observation = host._protected_backup(backup_root / filename)
                self.assertEqual(
                    expected,
                    all(dataclasses.asdict(observation).values()),
                )

    def test_live_protected_backup_rejects_symlink_hardlink_and_insecure_mode(self):
        backup_root = self.root / "secure-live-backups"
        backup_root.mkdir(mode=0o750)
        backup = backup_root / (
            "20260831T120000000000Z-abcdef123456-p-v37-"
            "0123456789abcdef.sqlite3"
        )
        connection = sqlite3.connect(backup)
        connection.execute("CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT)")
        connection.execute("INSERT INTO metadata VALUES('schema_version','37')")
        connection.commit()
        connection.close()
        backup.chmod(0o600)

        self.assertTrue(
            all(dataclasses.asdict(self.module.SystemLiveHost._protected_backup(backup)).values())
        )
        backup.chmod(0o666)
        self.assertFalse(
            self.module.SystemLiveHost._protected_backup(backup).schema_ok
        )
        backup.chmod(0o600)
        hardlink = backup_root / backup.name.replace("000000Z", "000001Z")
        hardlink.hardlink_to(backup)
        self.assertFalse(
            self.module.SystemLiveHost._protected_backup(backup).schema_ok
        )
        hardlink.unlink()
        symlink = backup_root / backup.name.replace("000000Z", "000002Z")
        symlink.symlink_to(backup)
        self.assertFalse(
            self.module.SystemLiveHost._protected_backup(symlink).schema_ok
        )

    def test_unit_contract_enables_sockets_and_web_but_keeps_static_services_active(self):
        self.assertEqual(
            {
                "lto-archiver-command-broker.socket",
                "lto-archiver-log-reader.socket",
                "lto-archiver-share-broker.socket",
                "lto-archiver-web.service",
                "lto-archiverd.socket",
            },
            set(self.module.REQUIRED_ENABLED_UNITS),
        )
        self.assertEqual(
            {
                "lto-archiver-log-reader.service",
                "lto-archiver-share-broker.service",
            },
            set(self.module.REQUIRED_STATIC_UNITS),
        )
        self.assertEqual(
            {
                "lto-archiver-command-broker.service",
                "lto-archiverd.service",
            },
            set(self.module.PRESERVED_ENABLEMENT_UNITS),
        )
        for unit in self.module.PRESERVED_ENABLEMENT_UNITS:
            unit_text = (ROOT / "packaging/systemd" / unit).read_text()
            self.assertIn("[Install]", unit_text)
            self.assertIn("WantedBy=multi-user.target", unit_text)
        share_text = (
            ROOT
            / "packaging/systemd/lto-archiver-share-broker.service"
        ).read_text()
        self.assertNotIn("[Install]", share_text)
        base = dict(self._observation().units)
        for unit, enablement in (
            ("lto-archiverd.socket", "disabled"),
            ("lto-archiver-share-broker.service", "enabled"),
            ("lto-archiver-command-broker.service", "static"),
        ):
            with self.subTest(unit=unit):
                units = dict(base)
                units[unit] = dataclasses.replace(
                    units[unit], enablement=enablement
                )
                report, _host = self._verify(self._observation(units=units))
                self.assertEqual("failed", report.status)

        units = dict(base)
        unit = "lto-archiver-command-broker.service"
        units[unit] = dataclasses.replace(units[unit], enablement="enabled")
        report, _host = self._verify(self._observation(units=units))
        self.assertEqual("green", report.status)

        for returncode, stdout, expected in (
            (0, "enabled\n", "enabled"),
            (1, "disabled\n", "disabled"),
            (0, "static\n", "static"),
        ):
            result = subprocess.CompletedProcess(
                ("/usr/bin/systemctl",), returncode, stdout, ""
            )
            self.assertEqual(
                expected, self.module._canonical_unit_enablement(result)
            )
        for returncode, stdout, stderr in (
            (4, "not-found\n", ""),
            (1, "not-found\n", ""),
            (0, "enabled-runtime\n", ""),
            (0, "enabled\n", "warning"),
        ):
            with self.subTest(returncode=returncode, stdout=stdout):
                with self.assertRaises(self.module.ContractError):
                    self.module._canonical_unit_enablement(
                        subprocess.CompletedProcess(
                            ("/usr/bin/systemctl",),
                            returncode,
                            stdout,
                            stderr,
                        )
                    )

    def test_rpm_verify_accepts_only_exact_package_path_and_flag_policy(self):
        accepted = self._observation(
            rpm_verify={
                "lto-archiver": (
                    "S.5....T.  c /etc/lto-archiver/config.toml",
                    "..5......  c /etc/lto-archiver/web.toml",
                ),
                "lto-archiver-python-runtime": (),
            }
        )
        self.assertEqual("green", self._verify(accepted)[0].status)

        rejected = (
            "M.5....T.  c /etc/lto-archiver/config.toml",
            "S.5....T.    /etc/lto-archiver/config.toml",
            "S.5....T.  c /etc/lto-archiver/extra.toml",
            "malformed",
        )
        for line in rejected:
            with self.subTest(line=line):
                observation = self._observation(
                    rpm_verify={
                        "lto-archiver": (line,),
                        "lto-archiver-python-runtime": (),
                    }
                )
                self.assertEqual("failed", self._verify(observation)[0].status)

    def test_inventory_reconciles_library_share_and_findmnt_ids_with_no_unmanaged_test_mount(self):
        for change in (
            {"reconciled": False},
            {"no_unmanaged_test_mount": False},
            {"mount_count": 2},
        ):
            with self.subTest(change=change):
                inventory = dataclasses.replace(
                    self._observation().inventory, **change
                )
                report, _ = self._verify(self._observation(inventory=inventory))
                self.assertEqual("failed", report.status)

    def test_system_inventory_enumerates_mounts_when_managed_root_is_not_mounted(self):
        managed_root = Path("/mnt/lto-archiver/sources")
        host = object.__new__(self.module.SystemLiveHost)
        host._config = SimpleNamespace(managed_sources_root=managed_root)
        libraries = [
            {
                "library_id": share_id,
                "source": {"kind": "managed_share", "share_id": share_id},
            }
            for share_id in ("anime", "film", "telefilm")
        ]
        shares = [
            {
                "share_id": share_id,
                "lifecycle": "active",
                "desired_state": "connected",
                "observed_state": "connected",
            }
            for share_id in ("anime", "film", "telefilm")
        ]
        mount_rows = {
            "filesystems": [
                {"target": "/"},
                {"target": str(managed_root / "anime")},
                {"target": str(managed_root / "film")},
                {"target": str(managed_root / "telefilm")},
            ]
        }

        with mock.patch.object(
            host, "_command", return_value=json.dumps(mount_rows)
        ) as command:
            observation = host._inventory(libraries, shares)

        self.assertTrue(observation.reconciled)
        self.assertEqual(3, observation.mount_count)
        command.assert_called_once_with(
            self.module._FINDMNT,
            "--json",
            "--list",
            "--output",
            "TARGET",
        )

        mount_rows["filesystems"].append(
            {"target": str(managed_root / "unknown")}
        )
        with mock.patch.object(
            host, "_command", return_value=json.dumps(mount_rows)
        ):
            self.assertFalse(host._inventory(libraries, shares).reconciled)

    def test_journal_accepts_only_policy_unit_message_id_and_priority_tuple(self):
        event = self.module.JournalEvent(
            unit="lto-archiverd.service", message_id="9" * 32, priority=3
        )
        failed, _ = self._verify(
            self._observation(priority_journal_events=(event,))
        )
        self.assertEqual("failed", failed.status)

        self.journal_policy.write_text(
            json.dumps(
                {
                    "allowlist": [
                        {
                            "message_id": "9" * 32,
                            "priority": 3,
                            "unit": "lto-archiverd.service",
                        }
                    ],
                    "schema": 1,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n",
            encoding="utf-8",
        )
        passed, _ = self._verify(
            self._observation(priority_journal_events=(event,))
        )
        self.assertEqual("green", passed.status)

    def test_journal_uses_epoch_and_keeps_missing_message_id_as_an_event(self):
        host = object.__new__(self.module.SystemLiveHost)
        commands: list[tuple[object, ...]] = []

        def command(*args, **_kwargs):
            commands.append(args)
            return (
                '{"_SYSTEMD_UNIT":"lto-archiverd.service",'
                '"PRIORITY":"3"}\n'
            )

        with mock.patch.object(host, "_command", side_effect=command):
            events = host._journal("2026-08-29T05:00:00Z")

        self.assertEqual(1, len(commands))
        self.assertIn("--since=@1787979600", commands[0])
        self.assertIn("setroubleshootd.service", commands[0])
        self.assertEqual(
            (
                self.module.JournalEvent(
                    unit="lto-archiverd.service",
                    message_id="",
                    priority=3,
                ),
            ),
            events,
        )
        with self.assertRaises(self.module.ContractError):
            host._journal("2026-08-29 05:00:00")

    def test_firewall_requires_lan_only_8443_and_three_source_rules_without_broad_opening(self):
        base = self._observation().firewall
        changes = (
            {"listener_exact": False},
            {"lan_only": False},
            {"source_rules": frozenset({"10.0.0.0/8"})},
            {"broad_port_open": True},
            {"broad_service_open": True},
        )
        for change in changes:
            with self.subTest(change=change):
                firewall = dataclasses.replace(base, **change)
                report, _ = self._verify(self._observation(firewall=firewall))
                self.assertEqual("failed", report.status)

        rich = "\n".join(
            f'rule family="ipv4" source address="{source}" port port="8443" protocol="tcp" accept'
            for source in sorted(self.module.REQUIRED_FIREWALL_RULES)
        )
        calls: list[tuple[str, ...]] = []

        extra_rich = False

        def runner(argv, accepted=(0,)):
            calls.append(argv)
            if argv[-1] == "--list-rich-rules":
                stdout = rich + (
                    '\nrule family="ipv4" port port="8000-9000" protocol="tcp" accept'
                    if extra_rich
                    else ""
                )
            elif argv[-1] == "--list-ports":
                stdout = ""
            elif argv[-1] == "--list-services":
                stdout = "legacy-web" if "--permanent" in argv else ""
            elif argv[-1] == "--info-service=legacy-web":
                stdout = "ports: 8000-9000/tcp\n"
            else:
                raise AssertionError(argv)
            return subprocess.CompletedProcess(argv, 0, stdout, "")

        host = self.module.SystemLiveHost.__new__(self.module.SystemLiveHost)
        host._config = SimpleNamespace(firewall_zone="public")
        host._runner = runner
        host._require_root_tool = lambda _path: None
        host._listener_exact = lambda: True
        observation = host._firewall()
        self.assertTrue(observation.broad_service_open)
        self.assertIn(
            (
                "/usr/bin/firewall-cmd",
                "--permanent",
                "--info-service=legacy-web",
            ),
            calls,
        )
        extra_rich = True
        self.assertFalse(host._firewall().lan_only)

    def test_each_job_operation_blocker_recovery_failed_unit_or_priority_error_fails_closed(self):
        m = self.module
        cases = (
            ("job", m.DaemonObservation(True, True, False, True, 0, 0)),
            ("blocker", m.DaemonObservation(True, True, True, True, 1, 0)),
            ("recovery", m.DaemonObservation(True, True, True, True, 0, 1)),
        )
        for name, daemon in cases:
            with self.subTest(name=name):
                self.assertEqual(
                    "failed",
                    self._verify(self._observation(daemon=daemon))[0].status,
                )
        self.assertEqual(
            "failed",
            self._verify(self._observation(failed_unit_count=1))[0].status,
        )

    def test_report_redacts_all_operational_values_and_performs_no_probe_scan_or_broker_mutation(self):
        report, host = self._verify()
        payload = report.to_json()

        for forbidden in (
            "192.0.2.26",
            "/srv/private",
            "smb://server/share",
            "LIBRARY-A",
            "TAPE001",
            "/dev/nst0",
            "secret",
        ):
            self.assertNotIn(forbidden, payload)
        self.assertEqual([], host.mutation_calls)
        self.assertEqual("green", json.loads(payload)["status"])

        request = self._request()
        request_file = self.root / "live-request.json"
        request_value = {
            "artifact_manifest_sha256": request.artifact_manifest_sha256,
            "driver_input_contract": str(request.driver_input_contract),
            "expected_driver_input_sha256": request.expected_driver_input_sha256,
            "expected_nevras": dict(request.expected_nevras),
            "journal_policy": str(request.journal_policy),
            "maintenance_started_at": request.maintenance_started_at,
            "rollback_manifest_sha256": request.rollback_manifest_sha256,
            "rpm_verify_policy": str(request.rpm_verify_policy),
            "schema": 1,
        }
        request_file.write_bytes(self.module._canonical_bytes(request_value))
        private_config = self.root / "private-live.json"
        private_config.write_text(
            json.dumps(
                {
                    "application_rpm": str(self.root / "app.rpm"),
                    "daemon_socket": str(self.root / "daemon.sock"),
                    "driver_rpm": str(self.root / "driver.rpm"),
                    "driver_rpm_verify_policy": str(self.root / "driver-policy.json"),
                    "driver_signing_policy": str(self.root / "driver-signing.json"),
                    "driver_public_key": str(self.root / "driver.asc"),
                    "driver_source_provenance_evidence": str(
                        self.root / "driver-provenance.json"
                    ),
                    "driver_digest_authority": str(
                        self.root / "driver-digest-authority.json"
                    ),
                    "expected_listen_address": "192.0.2.26",
                    "firewall_zone": "public",
                    "https_ca_certificate": str(self.root / "ca.crt"),
                    "https_health_url": "https://192.0.2.26:8443/api/v1/health",
                    "managed_sources_root": str(self.root / "sources"),
                    "runtime_rpm": str(self.root / "runtime.rpm"),
                    "schema": 1,
                    "signing_policy": str(self.root / "signing.json"),
                    "signing_public_key": str(self.root / "signing.asc"),
                }
            ),
            encoding="utf-8",
        )
        output = self.root / "live-result.json"
        cli_host = FakeLiveHost(self.module, self._observation())
        with (
            mock.patch.object(self.module.os, "geteuid", return_value=0),
            mock.patch.object(
                self.module, "SystemLiveHost", return_value=cli_host
            ),
        ):
            return_code = self.module.main(
                [
                    "--request",
                    str(request_file),
                    "--private-config",
                    str(private_config),
                    "--json-output",
                    str(output),
                ]
            )
        self.assertEqual(0, return_code)
        self.assertEqual("green", json.loads(output.read_text())["status"])

    def _driver_signature_fixture(
        self, *, legacy=False, provenance="local-build-identity-only"
    ):
        config = SimpleNamespace()
        contents = {
            "driver_rpm": b"hash-bound-driver-rpm",
            "driver_public_key": b"public-key-fixture",
            "driver_source_provenance_evidence": b"local-source-evidence",
            "driver_rpm_verify_policy": (
                ROOT / "packaging/rpm/driver-rpm-verify-policy.json"
            ).read_bytes(),
            "driver_digest_authority": (
                ROOT / "packaging/rpm/driver-input-digest-authority.json"
            ).read_bytes(),
        }
        policy = {
            "accepted_digest_algorithms": ["SHA256"],
            "accepted_public_key_algorithm": "RSA",
            "exact_package_names": ["lto-ltfs"],
            "minimum_rsa_bits": 3072,
            "primary_fingerprint": "A" * 40,
            "public_key_path": "public.asc",
            "public_key_sha256": _sha(contents["driver_public_key"]),
            "schema_version": 1,
            "signing_subkey_fingerprint": "B" * 40,
        }
        if legacy:
            policy = {
                "package_names": ["lto-ltfs"],
                "schema": 1,
                "status": "unsigned-local-build",
            }
        contents["driver_signing_policy"] = self.module._canonical_bytes(policy)
        for name, data in contents.items():
            path = self.root / name
            path.write_bytes(data)
            setattr(config, name, path)
        metadata = "installed-driver-file-metadata\n"
        query = "lto-ltfs\nlto-ltfs-0.1.0-21.el9.x86_64\n" + "3" * 64 + "\n"
        contract = json.loads(self.driver_bytes)
        contract.update({
            "installed_file_metadata_sha256": _sha(metadata.encode()),
            "rpm_header_sha256": _sha(query.encode()),
            "rpm_raw_sha256": _sha(contents["driver_rpm"]),
            "rpm_public_key_sha256": _sha(contents["driver_public_key"]),
            "rpm_signing_policy_sha256": _sha(contents["driver_signing_policy"]),
            "source_provenance_evidence_sha256": _sha(
                contents["driver_source_provenance_evidence"]
            ),
            "source_provenance_status": provenance,
        })
        self.driver_bytes = self.module._canonical_bytes(contract)
        self.driver_contract.write_bytes(self.driver_bytes)
        host = object.__new__(self.module.SystemLiveHost)
        host._config = config
        host._root_authority = lambda _path: True
        key_listing = "\n".join((
            "pub:-:4096:1:AAAAAAAAAAAAAAAA:0:0::::::scESC::::::23::0:",
            "fpr:::::::::" + "A" * 40 + ":",
            "sub:-:4096:1:BBBBBBBBBBBBBBBB:0:0::::::s::::::23:",
            "fpr:::::::::" + "B" * 40 + ":",
        ))
        observation = SimpleNamespace(
            signature=(
                "driver.rpm: digests OK\n" if legacy else
                "driver.rpm:\n"
                "    Header V4 RSA/SHA256 Signature, key ID bbbbbbbb: OK\n"
                "    Header SHA256 digest: OK\n"
                "    Payload SHA256 digest: OK\n"
            ),
            metadata=metadata,
            checks=[],
        )

        def command_result(tool, *args, **_kwargs):
            if tool == self.module._RPM and args == (
                "-qp", "--qf",
                "%{NAME}\n%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n%{PAYLOADDIGEST}\n",
                config.driver_rpm,
            ):
                stdout = query
            elif tool == self.module._RPM and args == (
                "-ql", "--dump", "lto-ltfs"
            ):
                stdout = observation.metadata
            elif tool == self.module._GPG and "show-only" in args:
                stdout = key_listing
            elif tool == self.module._RPMKEYS and "--import" in args:
                self.assertEqual(config.driver_public_key, args[-1])
                stdout = ""
            elif tool == self.module._RPMKEYS and "--checksig" in args:
                self.assertEqual(config.driver_rpm, args[-1])
                observation.checks.append(args)
                stdout = observation.signature
            else:
                raise AssertionError(f"unexpected command: {tool} {args}")
            return subprocess.CompletedProcess((tool, *args), 0, stdout, "")

        host._command_result = command_result
        host._command = lambda *args, **kwargs: command_result(
            *args, **kwargs
        ).stdout
        return host, observation

    def test_signed_driver_verification_does_not_assert_upstream_lineage(self):
        host, observation = self._driver_signature_fixture()
        self.assertEqual((True, True), host._driver_ok(self._request()))
        contract = self.module.load_driver_input_contract(
            self.driver_contract, expected_sha256=_sha(self.driver_bytes)
        )
        self.assertFalse(contract.upstream_lineage_verified)
        self.assertEqual(1, len(observation.checks))
        self.assertIn("--dbpath", observation.checks[0])
        self.assertIn("--verbose", observation.checks[0])
        observation.metadata = "different-installed-driver\n"
        self.assertEqual((True, False), host._driver_ok(self._request()))

    def test_driver_artifact_preflight_never_queries_installed_metadata(self):
        host, observation = self._driver_signature_fixture()
        verify = getattr(host, "_driver_artifact_ok", None)
        self.assertTrue(callable(verify), "candidate RPM needs artifact-only verification")
        command = host._command_result

        def artifact_command(tool, *args, **kwargs):
            if tool == self.module._RPM and "-ql" in args:
                raise AssertionError("candidate preflight queried installed metadata")
            return command(tool, *args, **kwargs)

        host._command_result = artifact_command
        observation.metadata = "predecessor metadata differs from candidate\n"
        self.assertTrue(verify(self._request()))
        observation.signature = "driver.rpm: digests OK\n"
        self.assertFalse(verify(self._request()))
        host._config.driver_rpm.write_bytes(b"tampered candidate")
        self.assertFalse(verify(self._request()))

    def test_signed_driver_policy_never_falls_back_to_unsigned(self):
        host, observation = self._driver_signature_fixture()
        for signature in (
            "driver.rpm: digests OK\n",
            observation.signature.replace("bbbbbbbb", "cccccccc"),
            observation.signature.replace("RSA/SHA256", "RSA/SHA1"),
        ):
            with self.subTest(signature=signature):
                observation.signature = signature
                self.assertEqual((False, True), host._driver_ok(self._request()))

    def test_candidate_driver_rejects_legacy_unsigned_policy_even_with_local_lineage(self):
        host, observation = self._driver_signature_fixture(legacy=True)
        self.assertEqual((False, True), host._driver_ok(self._request()))
        self.assertEqual([], observation.checks)
        observation.signature = "driver.rpm: digests signatures OK\n"
        self.assertEqual((False, True), host._driver_ok(self._request()))
        host, _ = self._driver_signature_fixture(
            legacy=True, provenance="authenticated-release"
        )
        self.assertEqual((False, True), host._driver_ok(self._request()))

    def test_driver_rejects_unrecognized_or_misbound_signing_policy(self):
        for changes in (
            {"exact_package_names": ["another-package"]},
            {"accepted_digest_algorithms": ["SHA1"]},
            {"public_key_sha256": "f" * 64},
            {"schema_version": True},
            {"schema_version": 1.0},
            {"unexpected": True},
        ):
            with self.subTest(changes=changes):
                host, observation = self._driver_signature_fixture()
                policy = json.loads(
                    host._config.driver_signing_policy.read_bytes()
                )
                policy.update(changes)
                raw = self.module._canonical_bytes(policy)
                host._config.driver_signing_policy.write_bytes(raw)
                contract = json.loads(self.driver_bytes)
                contract["rpm_signing_policy_sha256"] = _sha(raw)
                self.driver_bytes = self.module._canonical_bytes(contract)
                self.driver_contract.write_bytes(self.driver_bytes)
                observation.signature = "driver.rpm: digests OK\n"
                self.assertEqual((False, True), host._driver_ok(self._request()))
                self.assertEqual([], observation.checks)

    def test_legacy_driver_policy_requires_integer_schema(self):
        for schema in (True, 1.0):
            with self.subTest(schema=schema):
                host, observation = self._driver_signature_fixture(legacy=True)
                raw = self.module._canonical_bytes({
                    "package_names": ["lto-ltfs"],
                    "schema": schema,
                    "status": "unsigned-local-build",
                })
                host._config.driver_signing_policy.write_bytes(raw)
                contract = json.loads(self.driver_bytes)
                contract["rpm_signing_policy_sha256"] = _sha(raw)
                self.driver_bytes = self.module._canonical_bytes(contract)
                self.driver_contract.write_bytes(self.driver_bytes)
                self.assertEqual((False, True), host._driver_ok(self._request()))
                self.assertEqual([], observation.checks)

    def test_driver_input_contract_requires_canonical_bytes_independent_digest_and_local_identity_semantics(self):
        contract = self.module.load_driver_input_contract(
            self.driver_contract, expected_sha256=_sha(self.driver_bytes)
        )
        self.assertEqual("local-build-identity-only", contract.source_provenance_status)
        self.assertFalse(contract.upstream_lineage_verified)

        noncanonical = self.root / "noncanonical.json"
        noncanonical.write_text(
            json.dumps(json.loads(self.driver_bytes), indent=2) + "\n",
            encoding="utf-8",
        )
        with self.assertRaises(self.module.ContractError):
            self.module.load_driver_input_contract(
                noncanonical,
                expected_sha256=_sha(noncanonical.read_bytes()),
            )
        with self.assertRaises(self.module.ContractError):
            self.module.load_driver_input_contract(
                self.driver_contract,
                expected_sha256=_sha(b"checksum line identity"),
            )
        wrong_policy = self.root / "wrong-driver-policy.json"
        wrong_value = json.loads(self.driver_bytes)
        wrong_value["rpm_verify_policy_sha256"] = "b" * 64
        wrong_bytes = self.module._canonical_bytes(wrong_value)
        wrong_policy.write_bytes(wrong_bytes)
        with self.assertRaises(self.module.ContractError):
            self.module.load_driver_input_contract(
                wrong_policy, expected_sha256=_sha(wrong_bytes)
            )

        rpm_bytes = b"private-driver-rpm"
        payload = "a" * 64
        query_text = (
            "lto-ltfs\n"
            "lto-ltfs-0.1.0-21.el9.x86_64\n"
            f"{payload}\n"
        )
        bound = dataclasses.replace(
            contract,
            rpm_raw_sha256=_sha(rpm_bytes),
            rpm_header_sha256=_sha(query_text.encode()),
            rpm_payload_sha256=payload,
        )
        query = subprocess.CompletedProcess(
            args=(), returncode=0, stdout=query_text, stderr=""
        )
        self.assertTrue(
            self.module._driver_artifact_identity_ok(bound, rpm_bytes, query)
        )
        for field in (
            "package_nevra",
            "rpm_raw_sha256",
            "rpm_header_sha256",
            "rpm_payload_sha256",
        ):
            with self.subTest(field=field):
                changed = dataclasses.replace(bound, **{field: "b" * 64})
                self.assertFalse(
                    self.module._driver_artifact_identity_ok(
                        changed, rpm_bytes, query
                    )
                )
        unsigned = subprocess.CompletedProcess(
            args=(), returncode=0, stdout="driver.rpm: digests OK\n", stderr=""
        )
        self.assertTrue(
            self.module._local_unsigned_driver_signature_ok(unsigned)
        )
        signed = subprocess.CompletedProcess(
            args=(),
            returncode=0,
            stdout="driver.rpm: digests signatures OK\n",
            stderr="",
        )
        self.assertFalse(
            self.module._local_unsigned_driver_signature_ok(signed)
        )

        exact_driver_verify = subprocess.CompletedProcess(
            args=("/usr/bin/rpm", "-V", "lto-ltfs"),
            returncode=1,
            stdout="S.5....T.  c /etc/lto-ltfs/device.json\n",
            stderr="",
        )
        self.assertTrue(
            self.module._driver_rpm_verify_result_ok(exact_driver_verify)
        )

        policy_path = ROOT / "packaging/rpm/driver-rpm-verify-policy.json"
        policy = json.loads(policy_path.read_bytes())
        self.assertTrue(
            self.module._driver_rpm_verify_policy_ok(
                policy, policy_path.read_bytes()
            )
        )
        for field, value in (
            ("permitted_rows", []),
            ("success_exit_codes", [0]),
            ("stderr", "warning"),
        ):
            with self.subTest(field=field):
                changed_policy = dict(policy)
                changed_policy[field] = value
                changed_raw = self.module._canonical_bytes(changed_policy)
                self.assertFalse(
                    self.module._driver_rpm_verify_policy_ok(
                        changed_policy, changed_raw
                    )
                )

        def changed_driver_verify(**changes):
            values = {
                "args": exact_driver_verify.args,
                "returncode": exact_driver_verify.returncode,
                "stdout": exact_driver_verify.stdout,
                "stderr": exact_driver_verify.stderr,
            }
            values.update(changes)
            return subprocess.CompletedProcess(**values)

        for changed in (
            changed_driver_verify(returncode=0),
            changed_driver_verify(stdout=""),
            changed_driver_verify(
                stdout="S.5....T.  c /etc/lto-ltfs/device.json",
            ),
            changed_driver_verify(
                stdout=(
                    "S.5....T.  c /etc/lto-ltfs/device.json\n"
                    "S........    /usr/bin/ltfs\n"
                ),
            ),
            changed_driver_verify(stderr="warning\n"),
        ):
            with self.subTest(changed=changed):
                self.assertFalse(
                    self.module._driver_rpm_verify_result_ok(changed)
                )

        signing_policy = {
            "minimum_rsa_bits": 3072,
            "primary_fingerprint": "A" * 40,
            "signing_subkey_fingerprint": "B" * 40,
        }
        key_listing = "\n".join(
            (
                "pub:-:4096:1:AAAAAAAAAAAAAAAA:0:0::::::scESC::::::23::0:",
                f"fpr:::::::::{'A' * 40}:",
                "sub:-:4096:1:BBBBBBBBBBBBBBBB:0:0::::::s::::::23:",
                f"fpr:::::::::{'B' * 40}:",
            )
        )
        self.assertTrue(
            self.module._signing_key_listing_authorized(
                key_listing, signing_policy
            )
        )
        self.assertFalse(
            self.module._signing_key_listing_authorized(
                key_listing.replace("sub:-:4096:1", "sub:-:2048:1"),
                signing_policy,
            )
        )
        self.assertFalse(
            self.module._signing_key_listing_authorized(
                key_listing.replace("pub:-:4096:1", "pub:r:4096:1"),
                signing_policy,
            )
        )
        self.assertFalse(
            self.module._signing_key_listing_authorized(
                key_listing.replace(
                    "sub:-:4096:1:BBBBBBBBBBBBBBBB:0:0",
                    "sub:-:4096:1:BBBBBBBBBBBBBBBB:0:1",
                ),
                signing_policy,
            )
        )
        for key_id in ("B" * 8, "B" * 16):
            with self.subTest(key_id=key_id):
                signature_output = subprocess.CompletedProcess(
                    args=(),
                    returncode=0,
                    stdout=(
                        "app.rpm:\n"
                        "    Header V4 RSA/SHA256 Signature, key ID "
                        f"{key_id}: OK\n"
                        "    Header SHA256 digest: OK\n"
                        "    Payload SHA256 digest: OK\n"
                    ),
                    stderr="",
                )
                self.assertTrue(
                    self.module._rpm_signature_authorized(
                        signature_output, signing_policy
                    )
                )
        signature_output = subprocess.CompletedProcess(
            args=(),
            returncode=0,
            stdout=(
                "app.rpm:\n"
                "    Header V4 RSA/SHA256 Signature, key ID "
                f"{'B' * 16}: OK\n"
                "    Header SHA256 digest: OK\n"
                "    Payload SHA256 digest: OK\n"
            ),
            stderr="",
        )
        self.assertTrue(
            self.module._rpm_signature_authorized(
                signature_output, signing_policy
            )
        )
        for tampered in (
            signature_output.stdout.replace("RSA/SHA256", "RSA/SHA1"),
            signature_output.stdout.replace("B" * 16, "C" * 16),
            signature_output.stdout.replace("Signature", "Signature", 1)
            + "    V4 RSA/SHA256 Signature, key ID "
            + "C" * 16
            + ": OK\n",
        ):
            with self.subTest(tampered=tampered):
                self.assertFalse(
                    self.module._rpm_signature_authorized(
                        subprocess.CompletedProcess(
                            args=(), returncode=0, stdout=tampered, stderr=""
                        ),
                        signing_policy,
                    )
                )

        self.assertTrue(
            self.module._tcp_port_specs_expose_web_range("8443/tcp")
        )
        self.assertTrue(
            self.module._tcp_port_specs_expose_web_range("8000-9000/tcp")
        )
        self.assertFalse(
            self.module._tcp_port_specs_expose_web_range("7999/tcp 8443/udp")
        )
        self.assertTrue(
            self.module._rich_rule_exposes_web_range(
                'rule family="ipv4" port port="8000-9000" protocol="tcp" accept'
            )
        )
        self.assertTrue(
            self.module._healthy_api_v1({"api_version": 1, "status": "ok"})
        )
        for degraded in (
            {"api_version": 1},
            {"api_version": 1, "status": "degraded"},
            {"api_version": 2, "status": "ok"},
            {"api_version": 1, "status": "ok", "extra": True},
        ):
            self.assertFalse(self.module._healthy_api_v1(degraded))

    def test_https_probe_requires_exact_healthy_api_v1_payload(self):
        config = self.module.SystemLiveConfig(
            daemon_socket=Path("/run/lto-archiver/daemon.sock"),
            https_health_url="https://console.example.invalid:8443/api/v1/health",
            https_ca_certificate=Path("/etc/lto-archiver/tls/server.crt"),
            firewall_zone="public",
            expected_listen_address="192.0.2.10",
            managed_sources_root=Path("/var/lib/lto-archiver/sources"),
            application_rpm=Path("/root/stage/app.rpm"),
            runtime_rpm=Path("/root/stage/runtime.rpm"),
            signing_public_key=Path("/root/stage/signing.asc"),
            signing_policy=Path("/root/stage/signing.json"),
            driver_rpm=Path("/root/stage/driver.rpm"),
            driver_rpm_verify_policy=Path("/root/stage/driver-verify.json"),
            driver_signing_policy=Path("/root/stage/driver-signing.json"),
            driver_public_key=Path("/root/stage/driver.asc"),
            driver_source_provenance_evidence=Path("/root/stage/provenance.json"),
            driver_digest_authority=Path("/root/stage/authority.json"),
        )
        host = self.module.SystemLiveHost(config)

        class Response:
            status = 200

            def __init__(self, payload: dict[str, object]) -> None:
                self.payload = json.dumps(payload).encode()

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _limit: int) -> bytes:
                return self.payload

        with mock.patch.object(
            self.module.ssl, "create_default_context", return_value=object()
        ):
            for payload, expected in (
                ({"api_version": 1, "status": "ok"}, True),
                ({"api_version": 1, "status": "healthy"}, True),
                ({"api_version": 1, "status": "degraded"}, False),
                ({"api_version": 2, "status": "ok"}, False),
                ({"api_version": 1, "status": "ok", "extra": True}, False),
            ):
                with self.subTest(payload=payload), mock.patch.object(
                    self.module.urllib.request,
                    "urlopen",
                    return_value=Response(payload),
                ):
                    self.assertEqual(expected, host._https_ok())

    def test_legacy_https_probe_accepts_only_exact_login_surface(self):
        class Response:
            status = 200

            def __init__(
                self,
                *,
                url: str = "https://console.example.invalid:8443/login",
                content_type: str = "text/html; charset=utf-8",
                cache_control: str = "no-store",
                body: bytes = b'<html><form action="/login"></form></html>',
            ) -> None:
                self.url = url
                self.headers = {
                    "Content-Type": content_type,
                    "Cache-Control": cache_control,
                }
                self.body = body

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _limit: int) -> bytes:
                return self.body

            def geturl(self) -> str:
                return self.url

        probe = {
            "url": "https://console.example.invalid:8443/login",
            "ca_certificate": "/var/lib/lto-archiver-web/tls/server.crt",
        }
        with mock.patch.object(
            self.module.ssl, "create_default_context", return_value=object()
        ):
            self.assertTrue(hasattr(self.module, "_legacy_https_login_ok"))
            for response, expected in (
                (Response(), True),
                (Response(url="https://console.example.invalid:8443/"), False),
                (Response(content_type="application/json"), False),
                (Response(cache_control="public"), False),
                (Response(body=b"<html>not the login form</html>"), False),
            ):
                with self.subTest(response=response), mock.patch.object(
                    self.module.urllib.request,
                    "urlopen",
                    return_value=response,
                ):
                    self.assertEqual(
                        expected, self.module._legacy_https_login_ok(probe)
                    )

    def test_legacy_gate_replays_expected_only_rpm_enablement_and_exact_health(self):
        bundle = self.root / "legacy-bundle"
        contracts = bundle / "contracts"
        tools = bundle / "tools"
        contracts.mkdir(parents=True)
        tools.mkdir()
        recovery = bundle / "release-recovery"
        recovery.mkdir(mode=0o700)
        selected = recovery / (
            "20260831T120000000000Z-abcdef123456-p-v35-"
            "0123456789abcdef.sqlite3"
        )
        selected_connection = sqlite3.connect(selected)
        selected_connection.execute(
            "CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT)"
        )
        selected_connection.execute(
            "INSERT INTO metadata VALUES('schema_version','35')"
        )
        selected_connection.commit()
        selected_connection.close()
        selected.chmod(0o600)
        policy_source = ROOT / "packaging/deployment/rpm-verify-policy.json"
        (tools / "rpm-verify-policy.json").write_bytes(policy_source.read_bytes())
        nevras = {
            "lto-archiver": "lto-archiver-0.11.27-101.el9.noarch",
            "lto-archiver-python-runtime": (
                "lto-archiver-python-runtime-0.11.27-3.el9.x86_64"
            ),
            "lto-ltfs": "lto-ltfs-0.1.0-16.el9.x86_64",
        }
        rich = [
            f'rule family="ipv4" source address="{source}" port port="8443" protocol="tcp" accept'
            for source in sorted(self.module.REQUIRED_FIREWALL_RULES)
        ]
        rpm_rows = {
            "lto-archiver": (
                "S.5....T.  c /etc/lto-archiver/config.toml\n"
            ),
            "lto-archiver-python-runtime": "",
            "lto-ltfs": "S.5....T.  c /etc/lto-ltfs/device.json\n",
        }
        enabled = {
            unit: (
                "enabled"
                if unit in self.module.REQUIRED_ENABLED_UNITS
                else "static"
            )
            for unit in self.module.REQUIRED_ACTIVE_UNITS
        }

        def publish_contract(
            protected_relative: str | None = None,
        ) -> Path:
            package_state = {
                package: {
                    "installed_file_metadata_sha256": _sha(
                        f"metadata-{package}\n".encode()
                    ),
                    "nevra": nevra,
                    "rpm_verify_exit": 1 if rpm_rows[package] else 0,
                    "rpm_verify_rows": list(
                        filter(None, rpm_rows[package].splitlines())
                    ),
                    "rpm_verify_stdout_sha256": _sha(
                        rpm_rows[package].encode()
                    ),
                }
                for package, nevra in nevras.items()
            }
            contract = {
                "captured_at": "2026-08-29T10:00:00Z",
                "custom_web_unit_sha256": "a" * 64,
                "driver_authority": {},
                "firewall_observation_sha256": "b" * 64,
                "firewall_policy": {
                    "ports_permanent": [],
                    "ports_runtime": [],
                    "rich_rules_permanent": rich,
                    "rich_rules_runtime": rich,
                    "schema": 1,
                    "services_permanent": [],
                    "services_runtime": [],
                    "zone": "public",
                },
                "installed_nevras": nevras,
                "installed_package_state": {
                    "packages": package_state,
                    "schema": 1,
                },
                "predecessor_web_probe": {
                    "url": "https://console.example.invalid:8443/login",
                    "ca_certificate": "/var/lib/lto-archiver-web/tls/server.crt",
                },
                "protected_backup_relative_path": (
                    selected.relative_to(bundle).as_posix()
                    if protected_relative is None
                    else protected_relative
                ),
                "protected_backup_sha256": _sha(selected.read_bytes()),
                "schema": 2,
                "source_catalog_schema": 35,
                "source_catalog_sha256": "c" * 64,
                "unit_enablement": enabled,
            }
            path = contracts / "old-live-contract.json"
            path.write_bytes(self.module._canonical_bytes(contract))
            rows = []
            for member in sorted(bundle.rglob("*")):
                if member.is_file() and member.name != "rollback-SHA256SUMS":
                    rows.append(
                        f"{_sha(member.read_bytes())}  {member.relative_to(bundle).as_posix()}"
                    )
            (bundle / "rollback-SHA256SUMS").write_text(
                "\n".join(sorted(rows)) + "\n"
            )
            return path

        contract_path = publish_contract()

        legacy_calls: list[tuple[str, ...]] = []

        def runner(argv, accepted=(0,)):
            command = tuple(argv)
            legacy_calls.append(command)
            if command[0] == "/usr/bin/rpm":
                package = command[-1]
                if "-q" in command and "--qf" in command:
                    stdout = nevras[package]
                    code = 0
                elif "-ql" in command:
                    stdout = f"metadata-{package}\n"
                    code = 0
                else:
                    stdout = rpm_rows[package]
                    code = 1 if stdout else 0
            elif command[0] == "/usr/bin/systemctl":
                if "is-enabled" in command:
                    stdout = enabled[command[-1]]
                    code = 1 if stdout == "disabled" else 0
                    if stdout == "not-found":
                        code = 4
                elif "is-active" in command:
                    stdout, code = "active", 0
                else:
                    stdout, code = "", 0
            elif command[0] == "/usr/bin/firewall-cmd":
                if command[-1] == "--list-rich-rules":
                    stdout = "\n".join(rich)
                else:
                    stdout = ""
                code = 0
            else:
                raise AssertionError(command)
            return subprocess.CompletedProcess(command, code, stdout, "")

        def daemon_get(_host, endpoint):
            if endpoint == "/api/v1/status":
                return {
                    "accepting_mutations": True,
                    "admission_blocker": None,
                    "api_version": 1,
                    "critical_recovery": None,
                    "job": None,
                    "operation": None,
                }
            if endpoint == "/api/v1/health":
                return {"api_version": 1, "status": "ok"}
            return []

        databases = {
            name: self.module.DatabaseObservation(True, True, True)
            for name in self.module.REQUIRED_DATABASES
        }

        def legacy_databases(
            _host,
            *,
            catalog_schema: str,
            protected_backup_required: bool,
        ):
            self.assertEqual("35", catalog_schema)
            self.assertFalse(protected_backup_required)
            return databases

        inventory = self.module.InventoryObservation(
            0, 0, 0, "d" * 64, True, True
        )
        patches = (
            mock.patch.object(
                self.module.SystemLiveHost,
                "_require_root_tool",
                return_value=None,
            ),
            mock.patch.object(
                self.module.SystemLiveHost, "_run", side_effect=runner
            ),
            mock.patch.object(
                self.module.SystemLiveHost, "_daemon_get", new=daemon_get
            ),
            mock.patch.object(
                self.module.SystemLiveHost, "_databases", new=legacy_databases
            ),
            mock.patch.object(
                self.module.SystemLiveHost, "_inventory", return_value=inventory
            ),
            mock.patch.object(
                self.module.SystemLiveHost, "_journal", return_value=()
            ),
            mock.patch.object(
                self.module, "_legacy_https_login_ok", return_value=True
            ),
            mock.patch.object(
                self.module, "_ROOT_UID", os.geteuid(), create=True
            ),
            mock.patch.object(
                self.module, "_ROOT_GID", os.getegid(), create=True
            ),
        )
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patches[7], patches[8]:
            self.assertTrue(
                self.module._legacy_rollback_gate(contract_path, bundle),
                legacy_calls,
            )
            canonical_name = selected.name
            for protected_relative in (
                f"release-recovery//{canonical_name}",
                f"release-recovery/./{canonical_name}",
                f"release-recovery/{canonical_name}/",
                f"release-recovery\\{canonical_name}",
                f"/release-recovery/{canonical_name}",
                "release-recovery/%2e%2e",
            ):
                with self.subTest(protected_relative=protected_relative):
                    contract_path = publish_contract(protected_relative)
                    self.assertFalse(
                        self.module._legacy_rollback_gate(contract_path, bundle)
                    )
            nevras["lto-archiver"] = "lto-archiver-0.11.27-100.el9.noarch"
            contract_path = publish_contract()
            self.assertFalse(
                self.module._legacy_rollback_gate(contract_path, bundle)
            )
            nevras["lto-archiver"] = "lto-archiver-0.11.27-101.el9.noarch"
            contract_path = publish_contract()
            enabled[next(iter(enabled))] = "not-found"
            self.assertFalse(
                self.module._legacy_rollback_gate(contract_path, bundle)
            )
            enabled.update(
                {
                    unit: (
                        "enabled"
                        if unit in self.module.REQUIRED_ENABLED_UNITS
                        else "static"
                    )
                    for unit in enabled
                }
            )
            rpm_rows["lto-archiver"] = (
                "....L....  c /etc/lto-archiver/config.toml\n"
            )
            contract_path = publish_contract()
            self.assertFalse(
                self.module._legacy_rollback_gate(contract_path, bundle)
            )


if __name__ == "__main__":
    unittest.main()
