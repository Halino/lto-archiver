"""Substitution and identity refusal tests for a public RPM release candidate."""

from __future__ import annotations

import hashlib
import re
import runpy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

TOOL = Path(__file__).resolve().parents[1] / "packaging/rpm/verify-public-release.py"
PUBLISH = Path(__file__).resolve().parents[1] / ".github/workflows/publish-release.yml"
COMMIT = "a" * 40
FPR = "B" * 40
SUBFPR = "C" * 40
REPO = "example/lto-archiver"
WORKFLOW = f"{REPO}/.github/workflows/build-release.yml"
PACKAGES = (
    "signed/app/RPMS/noarch/lto-archiver-0.11.30-155.el9.noarch.rpm",
    "signed/app/SRPMS/lto-archiver-0.11.30-155.el9.src.rpm",
    "signed/runtime/RPMS/x86_64/lto-archiver-python-runtime-0.11.27-3.el9.x86_64.rpm",
    "signed/runtime/SRPMS/lto-archiver-python-runtime-0.11.27-3.el9.src.rpm",
)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def candidate(root: Path) -> tuple[Path, str]:
    for relative in PACKAGES:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(relative.encode())
    manifest = root / "FINAL-RPM-SHA256SUMS"
    manifest.write_text(
        "".join(
            f"{sha((root / name).read_bytes())}  {Path(name).name}\n"
            for name in sorted(PACKAGES)
        ),
        encoding="ascii",
    )
    return manifest, sha(manifest.read_bytes())


class PublicReleasePublicationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.gate = runpy.run_path(str(TOOL))

    def test_exact_signed_candidate_passes_and_changed_byte_fails(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            manifest, approved = candidate(root)
            self.gate["verify_manifest"](manifest, root, approved, set(PACKAGES))
            (root / PACKAGES[0]).write_bytes(b"changed after approval")
            with self.assertRaises(self.gate["PublicReleaseError"]):
                self.gate["verify_manifest"](manifest, root, approved, set(PACKAGES))

    def test_missing_and_extra_signed_rpm_fail(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            manifest, approved = candidate(root)
            (root / PACKAGES[0]).unlink()
            with self.assertRaises(self.gate["PublicReleaseError"]):
                self.gate["verify_manifest"](manifest, root, approved, set(PACKAGES))
            (root / PACKAGES[0]).write_bytes(PACKAGES[0].encode())
            extra = root / "signed/app/RPMS/noarch/extra.rpm"
            extra.write_bytes(b"not approved")
            with self.assertRaises(self.gate["PublicReleaseError"]):
                self.gate["verify_manifest"](manifest, root, approved, set(PACKAGES))

    def test_wrong_attestation_identity_cannot_be_requested(self) -> None:
        make = self.gate["attestation_command"]
        command = make(
            Path("package.rpm"), REPO, WORKFLOW, "refs/tags/v0.11.30", COMMIT
        )
        self.assertEqual(command[0:3], ["gh", "attestation", "verify"])
        self.assertIn("--repo", command)
        self.assertIn(REPO, command)
        self.assertIn(WORKFLOW, command)
        self.assertIn("refs/tags/v0.11.30", command)
        self.assertIn(COMMIT, command)
        for wrong in (
            "refs/tags/v0.11.26",
            "other/repo/.github/workflows/build-release.yml",
        ):
            with self.assertRaises(self.gate["PublicReleaseError"]):
                make(Path("package.rpm"), REPO, wrong, "refs/tags/v0.11.30", COMMIT)

    def test_wrong_gpg_fingerprint_fails(self) -> None:
        check = self.gate["verify_signature_output"]
        check(b"Header V4 RSA/SHA256 Signature, key ID bbbbbbbb: OK\n", FPR)
        with self.assertRaises(self.gate["PublicReleaseError"]):
            check(b"Header V4 RSA/SHA256 Signature, key ID cccccccc: OK\n", FPR)
        with self.assertRaises(self.gate["PublicReleaseError"]):
            check(b"Header V4 RSA/SHA256 Signature, key ID bbbbbbbb: NOKEY\n", FPR)

    def test_changed_srpm_source_archive_fails(self) -> None:
        check = self.gate["verify_expected_source"]
        with tempfile.TemporaryDirectory() as raw:
            actual, expected = (
                Path(raw) / "actual.tar.gz",
                Path(raw) / "expected.tar.gz",
            )
            actual.write_bytes(b"changed source")
            expected.write_bytes(b"published tag source")
            with self.assertRaises(self.gate["PublicReleaseError"]):
                check(actual, expected)

    def test_install_order_requires_external_driver_then_runtime_then_app(self) -> None:
        order = self.gate["install_order"]
        self.assertEqual(
            order({"lto-archiver", "lto-ltfs", "lto-archiver-python-runtime"}),
            ("lto-ltfs", "lto-archiver-python-runtime", "lto-archiver"),
        )
        with self.assertRaises(self.gate["PublicReleaseError"]):
            order({"lto-archiver", "lto-archiver-python-runtime"})

    def test_exact_signed_fresh_install_tuple_precedes_all_package_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            approved = {
                "app_repo": REPO, "app_tag": "v0.11.30", "app_commit": COMMIT,
                "app_primary_fingerprint": FPR, "app_signing_subkey_fingerprint": SUBFPR,
                "app_manifest_sha256": "a" * 64, "app_signature_sha256": "b" * 64,
                "app_key_sha256": "c" * 64, "app_attestation_sha256": "d" * 64,
                "driver_repo": "example/lto-ltfs", "driver_tag": "v0.1.2",
                "driver_commit": COMMIT, "driver_approval_file": str(root / "approval.json"),
                "driver_approval_sha256": "e" * 64,
                "driver_verifier_sha256": "f" * 64,
            }
            responses = {
                "lto-ltfs-0.1.2-22.el9.x86_64.rpm": b"lto-ltfs-0.1.2-22.el9.x86_64\n",
                "lto-archiver-python-runtime-0.11.27-3.el9.x86_64.rpm": b"lto-archiver-python-runtime-0.11.27-3.el9.x86_64\n",
                "lto-archiver-0.11.30-155.el9.noarch.rpm": b"lto-archiver-0.11.30-155.el9.noarch\n",
            }
            commands: list[list[str]] = []

            def query(command: list[str]) -> bytes:
                commands.append(command)
                self.assertEqual(command[:2], ["rpm", "-qp"])
                if "--requires" in command:
                    return (b"lto-ltfs = 0.1.2-22.el9\n"
                            b"lto-archiver-python-runtime = 0.11.27-3.el9\n")
                return responses[Path(command[-1]).name]

            verify = self.gate["verify_fresh_install_inputs"]
            with patch.dict(verify.__globals__, {
                "verify_release": Mock(), "_verify_driver_candidate": Mock(),
                "_run": query,
            }):
                paths = verify(root / "app", root / "driver", root / "driver-source", approved)
                self.assertEqual(tuple(path.name for path in paths), (
                    "lto-ltfs-0.1.2-22.el9.x86_64.rpm",
                    "lto-archiver-python-runtime-0.11.27-3.el9.x86_64.rpm",
                    "lto-archiver-0.11.30-155.el9.noarch.rpm",
                ))
                responses["lto-ltfs-0.1.2-22.el9.x86_64.rpm"] = b"lto-ltfs-0.1.0-21.el9.x86_64\n"
                with self.assertRaises(self.gate["PublicReleaseError"]):
                    verify(root / "app", root / "driver", root / "driver-source", approved)
                responses["lto-ltfs-0.1.2-22.el9.x86_64.rpm"] = b"lto-ltfs-0.1.1-22.el9.x86_64\n"
                with self.assertRaises(self.gate["PublicReleaseError"]):
                    verify(root / "app", root / "driver", root / "driver-source", approved)
                responses["lto-ltfs-0.1.2-22.el9.x86_64.rpm"] = b"lto-ltfs-0.1.2-22.el9.x86_64\n"
                with self.assertRaises(self.gate["PublicReleaseError"]):
                    verify(root / "app", root / "driver", root / "driver-source", approved | {"extra": "wrong"})
            self.assertTrue(commands)

    def test_driver_verifier_bytes_are_pinned_before_loading_code(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source = root / "driver-source"
            (source / "scripts").mkdir(parents=True)
            verifier = source / "scripts/verify-public-release.py"
            verifier.write_text("raise RuntimeError('must not execute')\n", encoding="utf-8")
            approval = root / "approval.json"
            approval.write_text("{}", encoding="utf-8")
            approved = {
                "driver_tag": "v0.1.2", "driver_commit": COMMIT,
                "driver_approval_file": str(approval),
                "driver_approval_sha256": "a" * 64,
                "driver_verifier_sha256": "b" * 64,
            }
            check = self.gate["_verify_driver_candidate"]
            with patch.dict(check.__globals__, {
                "_verify_tag": Mock(), "_run": Mock(return_value=b""),
            }):
                with self.assertRaises(self.gate["PublicReleaseError"]):
                    check(root / "candidate", source, approved)

    def test_public_key_requires_exact_full_primary_fingerprint(self) -> None:
        check = self.gate["verify_public_key_records"]
        good = (
            f"pub:-:4096:1:BBBBBBBBBBBBBBBB::::::\nfpr:::::::::{FPR}:\n"
            f"sub:-:4096:1:CCCCCCCCCCCCCCCC::::::\nfpr:::::::::{SUBFPR}:\n"
        ).encode()
        check(good, FPR, SUBFPR)
        with self.assertRaises(self.gate["PublicReleaseError"]):
            check(
                good.replace(FPR.encode(), ("A" * 32 + "B" * 8).encode()), FPR, SUBFPR
            )
        with self.assertRaises(self.gate["PublicReleaseError"]):
            check(
                good.replace(SUBFPR.encode(), ("D" * 32 + "C" * 8).encode()),
                FPR,
                SUBFPR,
            )
        with self.assertRaises(self.gate["PublicReleaseError"]):
            check(good + good, FPR, SUBFPR)

    def test_publication_is_separate_protected_and_exact(self) -> None:
        workflow = PUBLISH.read_text(encoding="utf-8")
        self.assertIn("workflow_dispatch:", workflow)
        self.assertIn("environment: public-rpm-publication", workflow)
        self.assertIn("contents: write", workflow)
        self.assertIn("approved_manifest_sha256", workflow)
        self.assertIn("approved_fingerprint", workflow)
        self.assertIn("build_run_id", workflow)
        self.assertIn("smoke_report_sha256", workflow)
        self.assertIn("gh attestation verify", workflow)
        self.assertIn("gh release create", workflow)
        self.assertIn("gh release download", workflow)
        self.assertNotIn("PUBLIC_RPM_SECRET_KEY", workflow)

    def test_smoke_report_bytes_are_validated_before_draft_creation(self) -> None:
        workflow = PUBLISH.read_text(encoding="utf-8")
        self.assertIn("PUBLIC_RPM_APPROVED_SMOKE_REPORT_BASE64", workflow)
        self.assertIn("verify-public-fresh-smoke.py", workflow)
        self.assertLess(workflow.index("verify-public-fresh-smoke.py"), workflow.index("gh release create"))

    def test_every_publication_job_selects_python311_before_running_it(self) -> None:
        workflow = PUBLISH.read_text(encoding="utf-8")
        blocks = re.split(r"(?m)^  ([a-z_]+):\s*\n", workflow.split("\njobs:\n", 1)[1])
        jobs = dict(zip(blocks[1::2], blocks[2::2], strict=True))
        for name, body in jobs.items():
            first_use = body.find("python3.11 ")
            if first_use < 0:
                continue
            setup = body.find("actions/setup-python@")
            selected_version = body.find("python-version: '3.11'", setup)
            with self.subTest(job=name):
                self.assertTrue(
                    0 <= setup < selected_version < first_use,
                    f"{name} invokes python3.11 before selecting it",
                )

    def test_immutability_api_requires_http_200_and_enabled_true(self) -> None:
        check = self.gate["verify_immutability_response"]
        good = b'HTTP/2.0 200 OK\r\ncontent-type: application/json\r\n\r\n{"enabled":true,"enforced_by_owner":false}\n'
        check(good)
        check(good.replace(b"application/json", b"application/vnd.github+json"))
        for bad in (
            good.replace(b"200 OK", b"404 Not Found"),
            good.replace(b"true", b"false"),
            good.replace(b'{"enabled":true,"enforced_by_owner":false}', b"{}"),
            good.replace(b'{"enabled":true,"enforced_by_owner":false}', b"not json"),
            b"HTTP/2.0 200 OK\r\n\r\n[]",
        ):
            with self.subTest(bad=bad[:80]), self.assertRaises(self.gate["PublicReleaseError"]):
                check(bad)

    def test_admin_read_preflights_surround_draft_and_credential_is_isolated(self) -> None:
        workflow = PUBLISH.read_text(encoding="utf-8")
        blocks = re.split(r"(?m)^  ([a-z_]+):\s*\n", workflow.split("\njobs:\n", 1)[1])
        jobs = dict(zip(blocks[1::2], blocks[2::2], strict=True))
        self.assertEqual(set(jobs), {"preflight", "publish", "final_preflight", "finalize"})
        self.assertIn("needs: preflight", jobs["publish"])
        self.assertIn("needs: publish", jobs["final_preflight"])
        self.assertIn("needs: final_preflight", jobs["finalize"])
        for name in ("preflight", "final_preflight"):
            self.assertIn("environment: public-rpm-admin-read", jobs[name])
            self.assertIn("secrets.PUBLIC_RPM_ADMIN_READ_TOKEN", jobs[name])
            self.assertIn("immutable-releases", jobs[name])
            self.assertNotIn("contents: write", jobs[name])
        for name in ("publish", "finalize"):
            self.assertNotIn("secrets.PUBLIC_RPM_ADMIN_READ_TOKEN", jobs[name])
        self.assertIn("environment: public-rpm-publication", jobs["publish"])
        self.assertNotIn("environment:", jobs["finalize"])
        self.assertNotIn("PUBLIC_RPM_ADMIN_READ_TOKEN", jobs["finalize"])
        self.assertIn("gh release create", jobs["publish"])
        self.assertNotIn("--draft=false", jobs["publish"])
        self.assertIn("gh release edit", jobs["finalize"])
        self.assertIn("--draft=false", jobs["finalize"])

    def test_final_check_proof_is_direct_dependency(self) -> None:
        workflow = PUBLISH.read_text(encoding="utf-8")
        blocks = re.split(r"(?m)^  ([a-z_]+):\s*\n", workflow.split("\njobs:\n", 1)[1])
        jobs = dict(zip(blocks[1::2], blocks[2::2], strict=True))
        self.assertIn("needs: publish", jobs["final_preflight"])
        self.assertIn("steps.stage.outputs.draft_id", jobs["publish"])
        self.assertIn("steps.stage.outputs.asset_set_sha256", jobs["publish"])
        self.assertIn("outputs:", jobs["final_preflight"])
        self.assertIn("needs: final_preflight", jobs["finalize"])
        self.assertIn("needs.final_preflight.outputs.proof", jobs["finalize"])
        self.assertIn("needs.final_preflight.outputs.draft_id", jobs["finalize"])
        self.assertIn('releases/$DRAFT_ID', jobs["final_preflight"])
        self.assertIn('releases/$DRAFT_ID', jobs["finalize"])
        self.assertNotIn("releases/tags/", jobs["final_preflight"])
        self.assertNotIn("releases/tags/", jobs["finalize"])
        self.assertIn("--verify-immutability-http", jobs["final_preflight"])
        self.assertIn("validate_final_proof", jobs["finalize"])
        self.assertLess(
            jobs["finalize"].index("validate_final_proof"),
            jobs["finalize"].index('gh release edit "$RELEASE_TAG" --draft=false'),
        )

    def test_stale_or_changed_draft_never_reaches_draft_false(self) -> None:
        proof = self.gate["make_final_proof"](
            REPO, "v0.11.30", COMMIT, 99, "b" * 64, "c" * 64, 57, 1000
        )
        expected = {key: value for key, value in proof.items() if key != "checked_at"}
        validate = self.gate["validate_final_proof"]
        error = self.gate["PublicReleaseError"]
        validate(proof, expected, 1120)
        for change, now in (
            ({"draft_id": 100}, 1001),
            ({"asset_set_sha256": "d" * 64}, 1001),
            ({}, 1121),
        ):
            with self.subTest(change=change, now=now), self.assertRaises(error):
                validate(proof, expected | change, now)
        workflow = PUBLISH.read_text(encoding="utf-8")
        finalizer = workflow.split("\n  finalize:\n", 1)[1]
        self.assertLess(
            finalizer.index("validate_final_proof"),
            finalizer.index('gh release edit "$RELEASE_TAG" --draft=false'),
        )

    def test_audit_allows_only_builtin_github_token_reference(self) -> None:
        audit = runpy.run_path(
            str(
                Path(__file__).resolve().parents[1] / "scripts/audit-release-content.py"
            )
        )
        scan = audit["_sensitive_text_findings"]
        path = ".github/workflows/publish-release.yml"
        safe = "github-" + "token" + ": ${{ github.token }}\n"
        literal = "github-" + "token" + ": private-token-value\n"
        self.assertFalse(
            any(
                x.rule == "credential-assignment"
                for x in scan(path, safe, path_scan=False)
            )
        )
        self.assertTrue(
            any(
                x.rule == "credential-assignment"
                for x in scan(path, literal, path_scan=False)
            )
        )


if __name__ == "__main__":
    unittest.main()
