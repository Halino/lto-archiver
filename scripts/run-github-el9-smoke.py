#!/usr/bin/env python3
"""Limited unsigned EL9 compatibility smoke, only on disposable hosted runners."""
from __future__ import annotations

import argparse
import base64
import functools
import hashlib
import http.server
import json
import os
from pathlib import Path
import signal
import subprocess
import tarfile
import threading
import time
import urllib.parse
import zipfile

APP_COMMIT = "4507cd23e96fef48dd3099d0da69bb7cda3a9a27"
DRIVER_COMMIT = "61f8b6acb547e715624856e85786e7676fa28c37"
PROFILE = "github-almalinux9-unsigned-compatibility"
IMAGE_NAME = "AlmaLinux-9-GenericCloud-9.8-20260810.x86_64.qcow2"
IMAGE_SHA = "6bdab6376d46d42e4203ace3733efafc7c5d37c7cb443a6cc74750097002d74b"
PACKAGES = {
    "lto-ltfs-0.1.2-22.el9.x86_64.rpm": "a2f234284c96c3f35f358f46d8977e7fbba53f8d292d04eb5d909f7dd5f46a44",
    "lto-archiver-python-runtime-0.11.27-3.el9.x86_64.rpm": "59c9694981bcbff8583b4d16b0fe7ea3137cb2b102e506a4af897193fe895bb3",
    "lto-archiver-0.11.31-155.el9.noarch.rpm": "bfc77147a6b98623eb74cb8c19d4fe477bd9af71abcea7dd693b8e6488b916c9",
}
CHECKS = frozenset({"fresh_host", "hardware_absent", "hash_pinned_unsigned_tuple",
    "install_order", "installed_nevras", "rpm_verify", "unit_syntax", "service_accounts",
    "selinux", "live_web_login", "preflight_refuses_unsupported_host",
    "uninstall_residue_recorded", "uninstall_no_owned_executables", "uninstall_no_active_units"})
UNVERIFIED = ["backup_restore", "daemon_import", "physical_ltfs", "rhel9", "rpm_signatures", "snapshot_restoration"]


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def validate_archive(path, archive_sha, member, rpm_sha, output):
    if digest(path) != archive_sha:
        raise ValueError("GitHub artifact ZIP digest differs")
    with zipfile.ZipFile(path) as archive:
        selected = [item for item in archive.infolist() if item.filename == member]
        if len(selected) != 1 or selected[0].file_size > 64 * 1024 * 1024:
            raise ValueError("RPM member missing, ambiguous or oversized")
        data = archive.read(selected[0])
    if hashlib.sha256(data).hexdigest() != rpm_sha:
        raise ValueError("RPM digest differs")
    with Path(output).open("xb") as stream:
        stream.write(data)  # No other ZIP member is ever extracted.


def check_report(report):
    if (report.get("schema_version") != 1 or report.get("errors") != []
            or report.get("profile") != PROFILE or report.get("qualified") is not False
            or report.get("compatibility_passed") is not True
            or report.get("rpm_sha256") != PACKAGES
            or report.get("app_commit") != APP_COMMIT or report.get("driver_commit") != DRIVER_COMMIT
            or report.get("unverified_features") != UNVERIFIED
            or set(report.get("checks", {})) != CHECKS
            or any(value is not True for value in report["checks"].values())):
        raise ValueError("Incomplete compatibility smoke; not release qualification")


def command(*argv, **kwargs):
    print(json.dumps({"command": argv}), flush=True)
    return subprocess.run(argv, check=True, timeout=kwargs.pop("timeout", 300), **kwargs)


def fetch_artifact(root, repository, artifact_id, archive_sha, members):
    path = root / (str(artifact_id) + ".zip")
    with path.open("xb") as stream:
        if repository == "Halino/lto-ltfs-driver":
            # Official short-lived URL grants only access to this already public-source artifact.
            # Never log the URL or pass a personal GitHub token to this workflow.
            url = os.environ.get("EL9_DRIVER_ARTIFACT_URL", "")
            parsed = urllib.parse.urlsplit(url)
            if (parsed.scheme != "https" or not parsed.hostname
                    or not parsed.hostname.endswith(".blob.core.windows.net")
                    or parsed.username or parsed.password):
                raise ValueError("Missing authorized short-lived driver artifact URL")
            try:
                result = subprocess.run(["curl", "--fail", "--silent", "--show-error", "--max-time", "120", url],
                                        stdout=stream, timeout=130)
            except (OSError, subprocess.SubprocessError):
                raise ValueError("Short-lived driver artifact download could not complete") from None
            if result.returncode:
                raise ValueError("Short-lived driver artifact download failed")
        else:
            command("gh", "api", f"repos/{repository}/actions/artifacts/{artifact_id}/zip", stdout=stream)
    for member, name in members:
        validate_archive(path, archive_sha, member, PACKAGES[name], root / "payload/rpms" / name)


def run_vm(work):
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
        raise ValueError("This controller is restricted to disposable GitHub-hosted runners")
    work.mkdir(mode=0o700)  # Refuse reuse or ambiguous cleanup targets.
    (work / "payload/rpms").mkdir(parents=True)
    root = Path(__file__).resolve().parents[1]
    fetch_artifact(work, "Halino/lto-ltfs-driver", 11120292193,
        "1902ecee45ac064412e4b5ce1c7d39c1909fc20544744792c84d1fb041975a73",
        [("unsigned/lto-ltfs-0.1.2-22.el9.x86_64.rpm", "lto-ltfs-0.1.2-22.el9.x86_64.rpm")])
    fetch_artifact(work, "Halino/lto-archiver", 11126185637,
        "aa0377acc7f6a89b3f2914ee0e5e1532cfd486690c16cfd151663bed4564aa6e",
        [("unsigned/runtime/RPMS/x86_64/lto-archiver-python-runtime-0.11.27-3.el9.x86_64.rpm",
          "lto-archiver-python-runtime-0.11.27-3.el9.x86_64.rpm"),
         ("unsigned/app/RPMS/noarch/lto-archiver-0.11.31-155.el9.noarch.rpm",
          "lto-archiver-0.11.31-155.el9.noarch.rpm")])
    source_files = ["packaging/rpm/public_fresh_guest.py", "packaging/rpm/run-public-fresh-vm-smoke.py",
                    "packaging/rpm/check-public-fresh-host.py", "THIRD_PARTY_NOTICES.md",
                    "packaging/python-runtime/THIRD_PARTY_NOTICES.md", "packaging/python-runtime/runtime.spdx.json"]
    for name in source_files:
        destination = work / "payload/source" / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(subprocess.check_output(["git", "-C", str(root), "show", f"{APP_COMMIT}:{name}"]))
    (work / "payload/guest.py").write_bytes((root / "scripts/github_el9_guest.py").read_bytes())
    http_root = work / "http"
    http_root.mkdir()
    payload = http_root / "payload.tar.gz"
    with tarfile.open(payload, "w:gz") as archive:
        for path in sorted((work / "payload").rglob("*")):
            if path.is_file():
                archive.add(path, arcname=path.relative_to(work / "payload"))
    image = work / "guest.qcow2"
    command("curl", "--fail", "--location", "--silent", "--show-error", "--max-time", "300",
            "https://repo.almalinux.org/almalinux/9/cloud/x86_64/images/" + IMAGE_NAME, "--output", str(image))
    if digest(image) != IMAGE_SHA:
        raise ValueError("Official AlmaLinux image digest differs")
    command("qemu-img", "resize", str(image), "16G")
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0),
        functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(http_root)))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_port
    bootstrap = f"""set -euo pipefail
trap 'echo LTO_EL9_BOOT_FAILED' ERR
dnf -y install python3.11 curl
mkdir -m 700 /var/tmp/lto-el9-smoke
curl --fail --silent --show-error http://10.0.2.2:{port}/payload.tar.gz -o /var/tmp/lto-el9-input.tar.gz
echo '{digest(payload)}  /var/tmp/lto-el9-input.tar.gz' | sha256sum --check --strict
tar -xzf /var/tmp/lto-el9-input.tar.gz -C /var/tmp/lto-el9-smoke
/usr/bin/python3.11 -I /var/tmp/lto-el9-smoke/guest.py
"""
    seed = work / "seed"
    seed.mkdir()
    (seed / "meta-data").write_text("instance-id: lto-el9-ci\nlocal-hostname: lto-el9-ci\n")
    (seed / "user-data").write_text("#cloud-config\n" + json.dumps({
        "ssh_pwauth": False, "disable_root": True,
        "runcmd": [["bash", "-c", bootstrap]],
        "output": {"all": "| tee -a /var/log/cloud-init-output.log /dev/ttyS0"}}))
    command("genisoimage", "-quiet", "-output", str(work / "seed.iso"), "-volid", "cidata",
            "-joliet", "-rock", str(seed / "user-data"), str(seed / "meta-data"))
    accelerator = "kvm" if os.access("/dev/kvm", os.R_OK | os.W_OK) else "tcg"
    (work / "environment.json").write_text(json.dumps({"accelerator": accelerator,
        "image": IMAGE_NAME, "image_sha256": IMAGE_SHA, "rpm_sha256": PACKAGES,
        "tooling_commit": subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()}))
    serial = work / "serial.log"
    process = subprocess.Popen(["qemu-system-x86_64", "-nodefaults", "-accel", accelerator,
        "-cpu", "host" if accelerator == "kvm" else "max",
        "-m", "4096", "-smp", "2", "-display", "none", "-monitor", "none",
        "-serial", "file:" + str(serial), "-drive", f"file={image},format=qcow2,if=virtio",
        "-drive", f"file={work / 'seed.iso'},format=raw,if=virtio,readonly=on",
        "-netdev", "user,id=net", "-device", "virtio-net-pci,netdev=net", "-no-reboot"])
    def interrupted(signum, frame):
        raise KeyboardInterrupt("Hosted smoke interrupted")
    prior_handler = signal.signal(signal.SIGTERM, interrupted)
    try:
        deadline = time.monotonic() + 1200
        while time.monotonic() < deadline:
            text = serial.read_text(errors="replace") if serial.exists() else ""
            for line in text.splitlines():
                if line.startswith("LTO_EL9_RESULT="):
                    report = json.loads(base64.b64decode(line.split("=", 1)[1], validate=True))
                    (work / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
                    check_report(report)
                    return
            if "LTO_EL9_BOOT_FAILED\n" in text or process.poll() is not None:
                raise ValueError("Guest bootstrap failed; inspect serial.log")
            time.sleep(5)
        raise ValueError("Guest smoke exceeded its 20-minute bound; inspect serial.log")
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        process.terminate()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        server.shutdown()
        server.server_close()
        signal.signal(signal.SIGTERM, prior_handler)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="operation", required=True)
    validate = commands.add_parser("validate-archive")
    for name in ("archive", "archive_sha", "member", "rpm_sha", "output"):
        validate.add_argument(name)
    report = commands.add_parser("check-report")
    report.add_argument("report", type=Path)
    vm = commands.add_parser("run")
    vm.add_argument("work", type=Path)
    args = parser.parse_args()
    try:
        if args.operation == "validate-archive":
            validate_archive(args.archive, args.archive_sha, args.member, args.rpm_sha, args.output)
        elif args.operation == "check-report":
            check_report(json.loads(args.report.read_text()))
        else:
            run_vm(args.work)
    except (OSError, ValueError, KeyError, zipfile.BadZipFile, subprocess.SubprocessError) as error:
        print(type(error).__name__ + ": " + str(error), flush=True)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
