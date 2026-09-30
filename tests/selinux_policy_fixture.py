"""Portable SELinux policy assertions shared by public source tests."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


SELINUX_RUNTIME_LOOKUPS = {
    "/var/lib/lto-archiver-share-broker/state.json": "lto_archiver_share_broker_state_t",
    "/etc/lto-archiver/share-credentials/share-id.cred": "lto_archiver_share_credential_t",
    "/mnt/lto-archiver/sources/share-id": "lto_archiver_share_source_t",
    "/var/run/lto-archiver/daemon.sock": "lto_archiver_runtime_t",
    "/var/run/lto-archiver-broker/control.sock": "lto_archiver_broker_runtime_t",
    "/var/run/lto-archiver-share-broker/control.sock": "lto_archiver_share_broker_runtime_t",
    "/var/run/lto-archiver-log-reader/control.sock": "lto_archiver_log_reader_runtime_t",
    "/var/lock/lto-ltfs/operation.lock": "lto_archiver_ltfs_lock_t",
    "/var/run/credentials/lto-archiverd.service/broker-capability": "lto_archiver_credential_t",
    "/var/run/credentials/lto-archiver-command-broker.service/broker-proof-key": "lto_archiver_credential_t",
    "/var/run/credentials/lto-archiver-ltfs-qualification.service/token": "lto_archiver_credential_t",
    "/var/run/credentials/lto-archiver-preflight.service/broker-capability": "lto_archiver_credential_t",
    "/dev/lto-archiver-scsi-TEST_DRIVE": "lto_archiver_device_t",
}


def unpack_policy_file_contexts(
    policy_package: Path, output_directory: Path, unpacker: str
) -> Path:
    module = output_directory / "lto_archiver.mod"
    contexts = output_directory / "lto_archiver.compiled.fc"
    completed = subprocess.run(
        [unpacker, str(policy_package), str(module), str(contexts)],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stdout + completed.stderr)
    if not contexts.is_file():
        raise AssertionError("compiled SELinux package has no file contexts")
    return contexts


def match_compiled_runtime_contexts(contexts: Path, matcher: str) -> None:
    substitutions = next(
        (
            candidate
            for candidate in sorted(
                Path("/etc/selinux").glob("*/contexts/files/file_contexts.subs_dist")
            )
            if {
                tuple(line.split()) for line in candidate.read_text().splitlines()
            }.issuperset(
                {
                    ("/run", "/var/run"),
                    ("/run/lock", "/var/lock"),
                }
            )
        ),
        None,
    )
    if substitutions is None:
        raise AssertionError("SELinux distribution runtime aliases are incomplete")
    shutil.copy2(substitutions, Path(f"{contexts}.subs_dist"))
    for canonical_path, context_type in SELINUX_RUNTIME_LOOKUPS.items():
        for lookup_path in (
            canonical_path,
            canonical_path.replace("/var/lock/", "/run/lock/", 1).replace(
                "/var/run/", "/run/", 1
            ),
        ):
            completed = subprocess.run(
                [matcher, "-N", "-n", "-f", str(contexts), lookup_path],
                check=False,
                capture_output=True,
                text=True,
            )
            if completed.returncode != 0:
                raise AssertionError(
                    f"matchpathcon failed for {lookup_path}: "
                    f"{completed.stdout}{completed.stderr}"
                )
            expected = f"system_u:object_r:{context_type}:s0"
