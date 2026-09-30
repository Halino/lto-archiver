"""The current public RPM must pair with driver 22 and retain notices."""

from __future__ import annotations

import json
import os
import re
import runpy
import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "packaging/rpm/main-rpm-contract.json"
SPEC = ROOT / "packaging/rpm/lto-archiver.spec"
VERIFIER = ROOT / "packaging/rpm/verify-main-rpm.py"
PUBLISHER = ROOT / "packaging/rpm/publish-rpm-tree.py"
EXPECTED_DRIVER = "lto-ltfs = 0.1.2-22.el9"
HISTORICAL_RUNNERS = (
    "deploy-rhel9.py", "rollback-rhel9.py", "verify-deployment-rhel9.py"
)


class PublicMainRpmContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.verifier = runpy.run_path(str(VERIFIER))

    def test_public_destination_is_admitted_but_another_repository_is_not(self) -> None:
        load = self.verifier["_load_contract"]
        contract = load(CONTRACT)
        self.assertEqual("https://github.com/Halino/lto-archiver", contract["project_url"])
        with tempfile.TemporaryDirectory() as raw:
            altered = Path(raw) / "contract.json"
            altered.write_text(json.dumps({
                **contract, "project_url": "https://github.com/other/project",
            }))
            with self.assertRaises(self.verifier["ContractError"]):
                load(altered)

    def test_active_driver_requirement_is_22_in_spec_and_verifier(self) -> None:
        contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        self.assertEqual(EXPECTED_DRIVER, contract["driver_requirement"])
        requirement = re.search(
            r"(?m)^Requires:\s+(lto-ltfs = \S+)$", SPEC.read_text(encoding="utf-8")
        )
        self.assertIsNotNone(requirement)
        self.assertEqual("lto-ltfs = 0.1.2-22%{?dist}", requirement.group(1))
        snapshot = SimpleNamespace(
            requirements=frozenset(
                {EXPECTED_DRIVER, "lto-archiver-python-runtime = 0.11.27-3.el9"}
            ),
            provides=frozenset(),
        )
        self.verifier["_verify_dependencies"](snapshot, contract)
        old_snapshot = SimpleNamespace(
            requirements=frozenset(
                {
                    "lto-ltfs = 0.1.0-21.el9",
                    "lto-archiver-python-runtime = 0.11.27-3.el9",
                }
            ),
            provides=frozenset(),
        )
        with self.assertRaises(self.verifier["ContractError"]):
            self.verifier["_verify_dependencies"](old_snapshot, contract)
        previous_public_snapshot = SimpleNamespace(
            requirements=frozenset(
                {
                    "lto-ltfs = 0.1.0-22.el9",
                    "lto-archiver-python-runtime = 0.11.27-3.el9",
                }
            ),
            provides=frozenset(),
        )
        with self.assertRaises(self.verifier["ContractError"]):
            self.verifier["_verify_dependencies"](previous_public_snapshot, contract)

    def test_installed_license_and_htmx_notice_are_source_bound(self) -> None:
        contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        authorities = contract["required_source_authorities"]
        expected = {
            "/usr/share/licenses/lto-archiver/LICENSE": "LICENSE",
            "/usr/share/licenses/lto-archiver/NOTICE": "NOTICE",
            "/usr/share/doc/lto-archiver/THIRD_PARTY_NOTICES.md": "THIRD_PARTY_NOTICES.md",
            "/usr/lib/python3.11/site-packages/ltobackup/web/static/HTMX-LICENSE.txt": (
                "src/ltobackup/web/static/HTMX-LICENSE.txt"
            ),
            "/usr/lib/python3.11/site-packages/ltobackup/web/static/htmx.js": (
                "src/ltobackup/web/static/htmx.js"
            ),
        }
        for installed, source in expected.items():
            with self.subTest(installed=installed):
                self.assertTrue(installed in authorities, f"missing source authority: {installed}")
                self.assertEqual(source, authorities[installed]["source"])

    def test_existing_byte_guard_rejects_changed_htmx_license_and_missing_notice(self) -> None:
        contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        selected = {
            name: contract["required_source_authorities"][name]
            for name in (
                "/usr/lib/python3.11/site-packages/ltobackup/web/static/HTMX-LICENSE.txt",
                "/usr/lib/python3.11/site-packages/ltobackup/web/static/htmx.js",
                "/usr/share/doc/lto-archiver/THIRD_PARTY_NOTICES.md",
            )
        }
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            metadata = {}
            for installed, authority in selected.items():
                extracted = root / installed.removeprefix("/")
                extracted.parent.mkdir(parents=True, exist_ok=True)
                extracted.write_bytes((ROOT / authority["source"]).read_bytes())
                metadata[installed] = (
                    authority["mode"],
                    authority["user"],
                    authority["group"],
                )
            snapshot = SimpleNamespace(extracted_root=root, payload_metadata=metadata)
            verify = self.verifier["_verify_source_authorities"]
            verify(snapshot, ROOT, {"required_source_authorities": selected})
            license_path = root / (
                "usr/lib/python3.11/site-packages/ltobackup/web/static/HTMX-LICENSE.txt"
            )
            license_path.write_bytes(license_path.read_bytes() + b"altered")
            with self.assertRaises(self.verifier["ContractError"]):
                verify(snapshot, ROOT, {"required_source_authorities": selected})
            license_path.write_bytes(
                (ROOT / "src/ltobackup/web/static/HTMX-LICENSE.txt").read_bytes()
            )
            (root / "usr/share/doc/lto-archiver/THIRD_PARTY_NOTICES.md").unlink()
            with self.assertRaises(self.verifier["ContractError"]):
                verify(snapshot, ROOT, {"required_source_authorities": selected})

    def test_installed_application_license_and_notice_are_required_bytes(self) -> None:
        contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        selected = {
            name: contract["required_source_authorities"][name]
            for name in (
                "/usr/share/licenses/lto-archiver/LICENSE",
                "/usr/share/licenses/lto-archiver/NOTICE",
            )
        }
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            metadata = {}
            for installed, authority in selected.items():
                extracted = root / installed.removeprefix("/")
                extracted.parent.mkdir(parents=True, exist_ok=True)
                extracted.write_bytes((ROOT / authority["source"]).read_bytes())
                metadata[installed] = (
                    authority["mode"], authority["user"], authority["group"],
                )
            snapshot = SimpleNamespace(extracted_root=root, payload_metadata=metadata)
            verify = self.verifier["_verify_source_authorities"]
            verify(snapshot, ROOT, {"required_source_authorities": selected})
            for installed in selected:
                with self.subTest(installed=installed):
                    payload = root / installed.removeprefix("/")
                    original = payload.read_bytes()
                    payload.write_bytes(original + b"changed")
                    with self.assertRaises(self.verifier["ContractError"]):
                        verify(snapshot, ROOT, {"required_source_authorities": selected})
                    payload.write_bytes(original)

    def test_current_rpm_has_no_historical_144_runner_bytes(self) -> None:
        contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        verify = self.verifier["_verify_payload_classes"]
        reject_bytes = self.verifier.get("_reject_historical_runner_bytes")
        self.assertTrue(callable(reject_bytes), "historical byte guard is missing")
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            baseline_metadata = {
                path: tuple(metadata)
                for path, metadata in contract["required_payload_metadata"].items()
            }
            verify(
                SimpleNamespace(extracted_root=root, payload_metadata=baseline_metadata),
                contract,
            )
            for name in HISTORICAL_RUNNERS:
                source = ROOT / "packaging/scripts" / name
                for installed in (
                    f"/usr/libexec/lto-archiver/{name}",
                    f"/usr/share/doc/lto-archiver/renamed-{name}",
                ):
                    with self.subTest(installed=installed):
                        extracted = root / installed.removeprefix("/")
                        extracted.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copyfile(source, extracted)
                        snapshot = SimpleNamespace(
                            extracted_root=root,
                            payload_metadata=baseline_metadata | {
                                installed: ("-rwxr-xr-x", "root", "root")
                            },
                        )
                        with self.assertRaises(self.verifier["ContractError"]):
                            verify(snapshot, contract)
                            reject_bytes(snapshot, ROOT)
                        extracted.unlink()

    def test_current_deploy_candidate_rejects_historical_runners_and_driver21(self) -> None:
        publisher = runpy.run_path(str(PUBLISHER))
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            current = set(publisher["_MAIN_OPTIONAL_PAYLOAD"])
            forbidden = {
                ("DEPLOY", name) for name in HISTORICAL_RUNNERS
            } | {("DEPLOY", "driver-input-digest-authority.json")}
            for directory, name in current | forbidden:
                target = root / directory / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(b"candidate fixture")
            root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                payload = {
                    relative: os.open(root.joinpath(*relative), os.O_RDONLY)
                    for relative in current | forbidden
                }
                try:
                    with self.assertRaises(RuntimeError):
                        publisher["_verify_optional_payload_set"](root_fd, payload)
                finally:
                    for descriptor in payload.values():
                        os.close(descriptor)
            finally:
                os.close(root_fd)

    def test_historical_source_and_identity_tests_remain(self) -> None:
        for name in HISTORICAL_RUNNERS:
            self.assertTrue((ROOT / "packaging/scripts" / name).is_file())
        self.assertTrue((ROOT / "tests/test_rhel9_rollback.py").is_file())


if __name__ == "__main__":
    unittest.main()
