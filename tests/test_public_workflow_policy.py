"""Safety policy for workflows shipped in the public source tree."""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
PINNED_ACTION = re.compile(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}\Z")


def policy_violations(source: str) -> list[str]:
    """Check active workflow lines; comments cannot satisfy or break policy."""
    lines = [
        line.split(" #", 1)[0]
        for line in source.splitlines()
        if not line.lstrip().startswith("#")
    ]
    active = "\n".join(lines)
    violations: list[str] = []
    if re.search(r"(?m)^\s*pull_request_target\s*:", active):
        violations.append("privileged PR event")
    if re.search(r"\bself-hosted\b", active.replace("--deny-self-hosted-runners", "")):
        violations.append("self-hosted runner")
    for line in lines:
        match = re.match(r"^\s*-?\s*uses:\s*(\S+)\s*$", line)
        if match and not PINNED_ACTION.fullmatch(match.group(1)):
            violations.append("un-pinned action")
    if re.search(r"(?m)^  pull_request\s*:", active):
        if not re.search(
            r"(?m)^permissions:\s*\n(?:  [^\n]*\n)*  contents:\s*read\s*$", active
        ):
            violations.append("PR token is not globally read-only")
        if re.search(r"(?m)^\s*[\w-]+:\s*write\s*$", active):
            violations.append("PR workflow grants write permission")
        if re.search(r"(?m)^\s*environment\s*:", active):
            violations.append("PR workflow reaches protected environment")
        if re.search(r"\bsecrets\.", active):
            violations.append("PR workflow reads secrets")
        if re.search(r"(?m)^  (?:sign|publish|release)[\w-]*\s*:", active):
            violations.append("release job reachable from PR")
    if "\njobs:\n" in active:
        before_jobs, job_source = active.split("\njobs:\n", 1)
        if re.search(r"(?m)^  contents:\s*write\s*$", before_jobs):
            violations.append("release-write permission outside publication")
        blocks = re.split(r"(?m)^  ([\w-]+):\s*\n", job_source)
        for name, body in zip(blocks[1::2], blocks[2::2], strict=True):
            if name.startswith(("build-", "compare")):
                if "secrets." in body:
                    violations.append("build job reads secrets")
                if re.search(
                    r"(?m)^      (?:contents|packages|actions):\s*write\s*$", body
                ):
                    violations.append("build job has publication permission")
            if name not in {"publish", "finalize"} and re.search(
                r"(?m)^      contents:\s*write\s*$", body
            ):
                violations.append("release-write permission outside publication")

    return violations


class PublicWorkflowPolicyTests(unittest.TestCase):
    def test_finalizer_has_no_environment_or_admin_secret(self) -> None:
        source = (WORKFLOWS / "publish-release.yml").read_text(encoding="utf-8")
        blocks = re.split(r"(?m)^  ([\w-]+):\s*\n", source.split("\njobs:\n", 1)[1])
        jobs = dict(zip(blocks[1::2], blocks[2::2], strict=True))
        self.assertNotRegex(jobs["finalize"], r"(?m)^    environment:")
        self.assertNotIn("PUBLIC_RPM_ADMIN_READ_TOKEN", jobs["finalize"])
        self.assertIn("contents: write", jobs["finalize"])
        self.assertIn("environment: public-rpm-admin-read", jobs["final_preflight"])
        self.assertNotIn("contents: write", jobs["final_preflight"])

    def test_ci_runs_unprivileged_pr_checks(self) -> None:
        source = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
        self.assertRegex(source, r"(?m)^  pull_request:\s*$")
        self.assertRegex(source, r"(?m)^  push:\s*$")
        self.assertEqual(policy_violations(source), [])

    def test_every_public_workflow_respects_policy(self) -> None:
        paths = sorted((*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")))
        self.assertTrue(paths, "the public repository needs at least one CI workflow")
        for path in paths:
            with self.subTest(path=path.name):
                self.assertEqual(
                    policy_violations(path.read_text(encoding="utf-8")), []
                )

    def test_rejects_self_hosted_and_mutable_action_fixture(self) -> None:
        safe = """on:\n  pull_request:\npermissions:\n  contents: read\njobs:\n  test:\n    runs-on: ubuntu-24.04\n    steps:\n      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n"""
        self.assertEqual(policy_violations(safe), [])
        self.assertIn(
            "self-hosted runner",
            policy_violations(safe.replace("ubuntu-24.04", "self-hosted")),
        )
        self.assertIn(
            "un-pinned action",
            policy_violations(
                safe.replace("11bd71901bbe5b1630ceea73d27597364c9af683", "v4")
            ),
        )
        self.assertIn(
            "privileged PR event",
            policy_violations(safe.replace("pull_request:", "pull_request_target:")),
        )
        self.assertIn(
            "PR workflow grants write permission",
            policy_violations(safe.replace("contents: read", "contents: write")),
        )

    def test_release_build_workflow_has_separated_privilege_boundaries(self) -> None:
        source = (WORKFLOWS / "build-release.yml").read_text(encoding="utf-8")
        self.assertEqual(policy_violations(source), [])
        self.assertIn("workflow_dispatch:", source)
        self.assertNotIn("pull_request:", source)
        self.assertNotIn("pull_request_target:", source)
        self.assertRegex(source, r"(?m)^  build-a:\s*$")
        self.assertRegex(source, r"(?m)^  build-b:\s*$")
        self.assertRegex(source, r"(?m)^  compare:\s*$")
        self.assertRegex(source, r"(?m)^  sign:\s*$")
        self.assertIn("public-rpm-signing", source)
        self.assertIn("attestations: write", source)
        self.assertIn("id-token: write", source)
        self.assertNotIn("contents: write", source)
        self.assertNotIn("gh release create", source)

    def test_manifest_signing_forces_approved_subkey(self) -> None:
        source = (WORKFLOWS / "build-release.yml").read_text(encoding="utf-8")
        sign_job = source.split("\n  sign:\n", 1)[1]
        self.assertRegex(
            sign_job,
            r'(?m)^\s+--local-user "\$PUBLIC_RPM_SUBKEY_FPR!" \\\s*$',
        )

    def test_build_job_cannot_read_signing_secret(self) -> None:
        safe = """on:\n  workflow_dispatch:\npermissions:\n  contents: read\njobs:\n  build-a:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: echo safe\n  sign:\n    environment: public-rpm-signing\n    steps:\n      - run: echo ${{ secrets.PUBLIC_KEY }}\n"""
        self.assertEqual(policy_violations(safe), [])
        injected = safe.replace("echo safe", "echo ${{ secrets.PUBLIC_KEY }}")
        self.assertIn("build job reads secrets", policy_violations(injected))

    def test_release_write_permission_is_rejected_outside_publication(self) -> None:
        safe = "on:\n  workflow_dispatch:\npermissions:\n  contents: read\njobs:\n  build-a:\n    permissions:\n      contents: read\n"
        self.assertEqual(policy_violations(safe), [])


if __name__ == "__main__":
    unittest.main()
