"""Exact-byte approval for every auxiliary public Release asset."""

from __future__ import annotations

import hashlib
import runpy
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GATE = runpy.run_path(str(ROOT / "packaging/rpm/verify-public-release.py"))


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class PublicReleaseAuxiliaryTests(unittest.TestCase):
    def test_signature_key_and_bundle_require_exact_approval(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            assets = {
                "FINAL-RPM-SHA256SUMS.asc": b"detached signature",
                "RPM-PUBLIC-KEY.asc": b"reviewed key",
                "ATTESTATION.json": b"signed provenance bundle",
            }
            for name, contents in assets.items():
                (root / name).write_bytes(contents)
            approved = {name: digest(contents) for name, contents in assets.items()}
            GATE["verify_auxiliary_assets"](root, approved)
            for name, contents in assets.items():
                (root / name).write_bytes(b"substituted")
                with self.assertRaises(GATE["PublicReleaseError"]):
                    GATE["verify_auxiliary_assets"](root, approved)
                (root / name).write_bytes(contents)

    def test_attestation_uses_approved_bundle_not_only_api_lookup(self) -> None:
        command = GATE["attestation_command"](
            Path("signed/package.rpm"),
            "example/lto-archiver",
            "example/lto-archiver/.github/workflows/build-release.yml",
            "refs/tags/v0.11.27",
            "a" * 40,
            Path("ATTESTATION.json"),
        )
        self.assertEqual(command[-2:], ["--bundle", "ATTESTATION.json"])

    def test_manifest_signature_must_use_approved_full_subkey(self) -> None:
        status = ("[GNUPG:] VALIDSIG " + "C" * 40 + " 2026 0 0 0 0 0 0\n").encode()
        GATE["verify_gpg_status"](status, "C" * 40)
        with self.assertRaises(GATE["PublicReleaseError"]):
            GATE["verify_gpg_status"](status, "D" * 40)

    def test_workflow_gates_all_assets_and_stages_draft_before_publish(self) -> None:
        workflow = (ROOT / ".github/workflows/publish-release.yml").read_text()
        for token in (
            "APPROVED_SIGNATURE_SHA256",
            "APPROVED_KEY_SHA256",
            "APPROVED_ATTESTATION_SHA256",
            "--bundle published/ATTESTATION.json",
            "gh release create",
            "--draft",
            'gh release edit "$RELEASE_TAG" --draft=false',
            '--notes-file "$RUNNER_TEMP/release-notes.md"',
        ):
            self.assertIn(token, workflow)
        self.assertNotIn("--notes-file docs/release-notes-0.11.27-155.md", workflow)
        draft = workflow.index("gh release create")
        checksums = workflow.index("sha256sum -c FINAL-RPM-SHA256SUMS")
        attestation = workflow.index("--bundle published/ATTESTATION.json")
        publication = workflow.index('gh release edit "$RELEASE_TAG" --draft=false')
        self.assertLess(draft, checksums)
        self.assertLess(checksums, attestation)
        self.assertLess(attestation, publication)
        self.assertLess(workflow.index("Exact approved release assets"), draft)
        self.assertLess(workflow.index("--report"), draft)

    def test_finalizer_rechecks_exact_draft_before_publish(self) -> None:
        workflow = (ROOT / ".github/workflows/publish-release.yml").read_text()
        finalizer = workflow.split("\n  finalize:\n", 1)[1]
        for token in (
            "draft.json",
            "asset_set_sha256",
            "validate_final_proof",
            "gh release download",
            "gh attestation verify",
            "isImmutable",
        ):
            self.assertIn(token, finalizer)
        self.assertLess(finalizer.index("validate_final_proof"), finalizer.index("--draft=false"))
        self.assertLess(finalizer.index("--draft=false"), finalizer.rindex("gh release download"))

    def test_auditor_exempts_only_builtin_oidc_permission_lines(self) -> None:
        audit = runpy.run_path(str(ROOT / "scripts/audit-release-content.py"))
        scan = audit["_sensitive_text_findings"]
        permission = "id-" + "token" + ": write"
        allowed = (
            (".github/workflows/build-release.yml", "      " + permission + "\n"),
            (
                "tests/test_public_workflow_policy.py",
                '        self.assertIn("' + permission + '", source)\n',
            ),
        )
        for path, line in allowed:
            self.assertFalse(
                any(
                    finding.rule == "credential-assignment"
                    for finding in scan(path, line, path_scan=False)
                )
            )
        bad = "id-" + "token" + ": opaque-private-value\n"
        self.assertTrue(
            any(
                finding.rule == "credential-assignment"
                for finding in scan(
                    ".github/workflows/build-release.yml", bad, path_scan=False
                )
            )
        )


if __name__ == "__main__":
    unittest.main()
