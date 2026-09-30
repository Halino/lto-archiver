#!/usr/bin/env python3
"""Run the limited public fresh-install smoke on an explicitly disposable VM.

Only local libvirt, running guests, internal memory+qcow2 snapshots, and QEMU
guest-agent transport are supported. An explicitly pinned private-use managed
NAT network is optional. Raw evidence is private and controller-owned.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
SHA = re.compile(r"[0-9a-f]{64}\Z")
CHECKS = (
    "disposable_marker", "snapshot_created", "fresh_host", "signed_tuple",
    "install_order", "installed_nevras", "rpm_verify", "unit_syntax",
    "service_accounts", "selinux", "live_web_login", "hardware_absence_refused",
    "uninstall_residue_recorded", "uninstall_no_owned_executables",
    "uninstall_no_active_units", "snapshot_restored",
)

# Read-only, deterministic coverage. Volatile logs, /run, /tmp, timestamps and
# unrelated /var/lib data are deliberately excluded; this is not a full disk hash.
BASELINE = r'''
import hashlib,json,os,stat,subprocess
from pathlib import Path
rows=[]
def visit(path):
 s=path.lstat(); mode=stat.S_IMODE(s.st_mode)
 item=[str(path),mode,s.st_uid,s.st_gid,stat.S_IFMT(s.st_mode)]
 if stat.S_ISLNK(s.st_mode): item.append(os.readlink(path))
 elif stat.S_ISREG(s.st_mode): item.append(hashlib.sha256(path.read_bytes()).hexdigest())
 rows.append(item)
 if stat.S_ISDIR(s.st_mode):
  for p in sorted(path.iterdir()): visit(p)
for p in [Path('/etc')]+[p for parent in ('/var/lib','/usr/bin','/usr/libexec','/usr/lib/systemd/system','/usr/share/selinux/packages') for p in sorted(Path(parent).glob('lto*'))]:
 if p.exists() or p.is_symlink(): visit(p)
for args in [['rpm','-qa','--qf','%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n'],['systemctl','list-unit-files','--all','--no-legend','--no-pager','lto-*'],['systemctl','list-units','--all','--full','--plain','--no-legend','--no-pager','lto-*'],['getenforce'],['semodule','-l']]:
 out=subprocess.run(args,check=True,capture_output=True,text=True).stdout
 rows.append([args,sorted(out.splitlines())])
print(hashlib.sha256(json.dumps(rows,sort_keys=True,separators=(',',':')).encode()).hexdigest())
'''
PLATFORM = r'''
import json,os,stat
from pathlib import Path
p=Path('/etc/redhat-release')
assert os.geteuid()==0 and p.read_text().startswith('Red Hat Enterprise Linux release 9.')
assert not list(Path('/sys/class/scsi_tape').glob('*'))
assert not list(Path('/sys/class/scsi_generic').glob('*'))
print('fresh platform ready')
'''


class SmokeError(RuntimeError):
    pass


class SmokeInterrupted(BaseException):
    """Cancellation must propagate through best-effort diagnostic retrieval."""


def ordinary(path: Path, expected: str | None = None) -> bytes:
    # A selected verifier must never silently traverse a symlinked ancestor.
    if not path.is_absolute() or any(p.is_symlink() for p in (path, *path.parents)):
        raise SmokeError("unsafe input path")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise SmokeError("input is not an ordinary single-link file")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read()
    finally:
        os.close(descriptor)
    if expected is not None and (SHA.fullmatch(expected) is None or hashlib.sha256(raw).hexdigest() != expected):
        raise SmokeError("input differs from approved hash")
    return raw


def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise SmokeError("duplicate JSON key")
        value[key] = item
    return value


class Controller:
    def __init__(self, args, evidence):
        self.args = args
        self.evidence = evidence
        self.domain_uuid = ""
        self.serial = 0

    def command(self, *args, timeout=None):
        command = ["virsh", "--connect", self.args.libvirt_uri, *args]
        self.serial += 1
        self.evidence.joinpath(f"{self.serial:04d}-command.json").write_text(json.dumps(command))
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   start_new_session=True, env={**os.environ, "LC_ALL": "C"})
        try:
            out, err = process.communicate(timeout=timeout or self.args.timeout_seconds)
        except BaseException:
            os.killpg(process.pid, signal.SIGKILL)
            out, err = process.communicate()
            self.evidence.joinpath(f"{self.serial:04d}-stdout").write_bytes(out)
            self.evidence.joinpath(f"{self.serial:04d}-stderr").write_bytes(err)
            raise
        self.evidence.joinpath(f"{self.serial:04d}-stdout").write_bytes(out)
        self.evidence.joinpath(f"{self.serial:04d}-stderr").write_bytes(err)
        if process.returncode:
            raise SmokeError(f"libvirt {args[0]} failed")
        return out

    def bound(self, operation, *args, timeout=None):
        return self.command(operation, self.domain_uuid, *args, timeout=timeout)

    def network(self, name):
        selected_name = getattr(self.args, "test_network_name", None)
        selected_uuid = getattr(self.args, "test_network_uuid", None)
        if not selected_name or name != selected_name:
            raise SmokeError("guest network was not explicitly selected")
        active = ET.fromstring(self.command("net-dumpxml", name))
        inactive = ET.fromstring(self.command("net-dumpxml", name, "--inactive"))
        def identity(node):
            return (node.tag, sorted(node.attrib.items()), (node.text or "").strip(),
                    [identity(child) for child in node])
        if identity(active) != identity(inactive):
            raise SmokeError("active and persistent network definitions differ")
        forward, bridge = active.find("forward"), active.find("bridge")
        if (active.tag != "network" or active.findtext("name") != name
                or active.findtext("uuid") != selected_uuid
                or forward is None or forward.attrib != {"mode": "nat"}
                or any(child.tag != "nat" for child in forward)
                or active.find("virtualport") is not None
                or bridge is None or re.fullmatch(r"virbr[0-9]+", bridge.get("name", "")) is None):
            raise SmokeError("network is not the exact managed NAT profile")
        info = self.command("net-info", name).decode()
        if not re.search(r"^Active:\s+yes\s*$", info, re.MULTILINE):
            raise SmokeError("selected network is not active")
        # A shared network is refused; no other guest is mutated or contacted.
        for other in self.command("list", "--all", "--uuid").decode().splitlines():
            other = other.strip()
            if not other or other == self.domain_uuid:
                continue
            if str(uuid.UUID(other)) != other:
                raise SmokeError("invalid domain inventory UUID")
            tree = ET.fromstring(self.command("dumpxml", other))
            if any(source.get("network") == name for source in tree.findall("./devices/interface/source")):
                raise SmokeError("selected test network is referenced by another domain")
        return bridge.get("name")

    def domain(self):
        value = ET.fromstring(self.bound("dumpxml"))
        if value.tag != "domain" or value.get("type") not in {"kvm", "qemu"} or value.findtext("uuid") != self.domain_uuid:
            raise SmokeError("domain identity changed")
        if any(node.tag.startswith("{http://libvirt.org/schemas/domain/qemu/")
               for node in value.iter()) or value.find("memoryBacking") is not None:
            raise SmokeError("unsupported QEMU overrides or host memory backing")
        markers = [node for node in value.findall("./metadata/*")
                   if node.tag.split("}")[-1] == "lto-disposable-test"]
        if len(markers) != 1 or (markers[0].text or "").strip() != "true":
            raise SmokeError("explicit lto-disposable-test=true metadata absent")
        devices = value.find("devices")
        if devices is None or any(child.tag not in {
                "disk", "controller", "emulator", "channel", "serial", "console", "memballoon", "interface"
        } for child in devices):
            raise SmokeError("guest has unsupported host-backed devices")
        for character in devices.findall("serial") + devices.findall("console"):
            source = character.find("source")
            if (character.get("type") != "pty" or source is not None and (
                    set(source.attrib) != {"path"} or re.fullmatch(r"/dev/pts/[0-9]+", source.get("path", "")) is None)):
                raise SmokeError("unsupported host character-device override")
        for channel in devices.findall("channel"):
            source, target = channel.find("source"), channel.find("target")
            if (channel.get("type") != "unix" or target is None
                    or target.get("type") != "virtio" or target.get("name") != "org.qemu.guest_agent.0"
                    or set(target.attrib) - {"type", "name", "state"}
                    or target.get("state") not in {None, "connected", "disconnected"}
                    or source is None or source.get("mode") != "bind"
                    or set(source.attrib) - {"mode", "path"}
                    or source.get("path") and not re.fullmatch(
                        r"(?:/var/lib/libvirt/qemu/channel/target|/run/libvirt/qemu/channel/target|/run/user/[0-9]+/libvirt/qemu/channel/target)/[^/]+/org\.qemu\.guest_agent\.0", source.get("path"))):
                raise SmokeError("unsupported guest-agent host socket override")
        emulator = devices.findtext("emulator")
        if emulator is not None and emulator not in {"/usr/bin/qemu-system-x86_64", "/usr/libexec/qemu-kvm"}:
            raise SmokeError("unsupported QEMU emulator override")
        networks = devices.findall("interface")
        if len(networks) > 1:
            raise SmokeError("at most one explicitly selected test network is supported")
        for interface in networks:
            source = interface.find("source")
            if (interface.get("type") != "network" or source is None
                    or "network" not in source.attrib
                    or set(source.attrib) - {"network", "bridge", "portid"}
                    or any(interface.find(name) is not None for name in ("virtualport", "hostdev", "driver"))):
                raise SmokeError("unsupported physical/shared network interface")
            bridge = self.network(source.get("network"))
            if source.get("bridge") is not None and source.get("bridge") != bridge:
                raise SmokeError("live interface bridge differs from selected managed network")
            if source.get("portid") is not None:
                try:
                    if str(uuid.UUID(source.get("portid"))) != source.get("portid"):
                        raise ValueError
                except ValueError:
                    raise SmokeError("invalid live managed-network port UUID") from None
        if value.find("./os/nvram") is not None:
            raise SmokeError("external firmware state is not snapshotted")
        disks = devices.findall("disk")
        if not disks:
            raise SmokeError("no snapshot-supported disk")
        targets = []
        for disk in disks:
            driver, source, target = disk.find("driver"), disk.find("source"), disk.find("target")
            if (disk.get("type") != "file" or disk.get("device") != "disk"
                    or driver is None or driver.get("type") != "qcow2"
                    or source is None or set(source.attrib) != {"file"}
                    or target is None or not target.get("dev")
                    or any(disk.find(name) is not None for name in ("readonly", "shareable"))
                    or any(backing.attrib or len(backing) or (backing.text or "").strip()
                           for backing in disk.findall("backingStore"))
                    or len(disk.findall("backingStore")) > 1):
                raise SmokeError("unsupported storage; internal qcow2 disks required")
            path = Path(source.get("file"))
            if (not path.is_absolute() or any(p.is_symlink() for p in (path, *path.parents))
                    or not stat.S_ISREG(path.lstat().st_mode) or path.stat().st_nlink != 1):
                raise SmokeError("disk is not an ordinary local private file")
            targets.append(target.get("dev"))
        if len(set(targets)) != len(targets):
            raise SmokeError("duplicate disk target")
        return targets

    def agent(self, operation, _timeout=None, **arguments):
        raw = self.bound("qemu-agent-command", json.dumps({"execute": operation, "arguments": arguments}),
                         "--timeout", str(max(1, int(_timeout or self.args.timeout_seconds))), timeout=_timeout)
        value = json.loads(raw, object_pairs_hook=unique)
        if set(value) != {"return"}:
            raise SmokeError("guest agent refused operation")
        return value["return"]

    def capture_logs(self, logs, offsets, label, budget=3):
        """Best-effort bounded file transport before rollback removes guest logs."""
        deadline = time.monotonic() + budget
        errors = []
        for index, path in enumerate(logs):
            handle = None
            def query(op, **arguments):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise SmokeError("guest evidence retrieval budget exhausted")
                return self.agent(op, _timeout=min(remaining, self.args.timeout_seconds), **arguments)
            try:
                handle = query("guest-file-open", path=path, mode="rb")
                position = query("guest-file-seek", handle=handle, offset=offsets[index], whence=0)
                if position.get("position") != offsets[index]:
                    raise SmokeError("guest log seek differs")
                with self.evidence.joinpath(f"{label}-stream-{index}.raw").open("ab") as output:
                    for _ in range(8):
                        row = query("guest-file-read", handle=handle, count=65536)
                        chunk = base64.b64decode(row.get("buf-b64", ""), validate=True)
                        if row.get("count") != len(chunk) or len(chunk) > 65536:
                            raise SmokeError("invalid guest log read")
                        output.write(chunk)
                        output.flush()
                        offsets[index] += len(chunk)
                        if offsets[index] > 16 * 1024 * 1024:
                            raise SmokeError("guest log retention limit exceeded")
                        if row.get("eof") is True:
                            break
                    else:
                        raise SmokeError("guest log retrieval chunk budget exhausted")
            except Exception as error:
                errors.append({"stream": index, "error": type(error).__name__})
            finally:
                if handle is not None:
                    try:
                        query("guest-file-close", handle=handle)
                    except Exception as error:
                        errors.append({"stream": index, "close_error": type(error).__name__})
        return errors

    def execute(self, path, args, timeout=None, logs=None):
        offsets = [0] * len(logs or [])
        label = "guest-live-" + uuid.uuid4().hex
        self.guest_process_exited = False
        try:
            return self._execute(path, args, timeout, logs, offsets, label)
        finally:
            if logs:
                pending = sys.exc_info()[1]
                # Do not allow another SIGINT/SIGTERM to skip bounded retention.
                old = {sig: signal.signal(sig, signal.SIG_IGN) for sig in (signal.SIGTERM, signal.SIGINT)}
                try:
                    errors = self.capture_logs(logs, offsets, label)
                    self.evidence.joinpath(label + "-completeness.json").write_text(json.dumps({
                        "complete": not errors and self.guest_process_exited,
                        "guest_process_exited": self.guest_process_exited,
                        "retrieval_errors": errors, "retained_bytes": offsets}))
                    if errors and pending is None:
                        raise SmokeError("guest diagnostic evidence incomplete; restoration required")
                finally:
                    for sig, handler in old.items():
                        signal.signal(sig, handler)

    def _execute(self, path, args, timeout, logs, offsets, label):
        result = self.agent("guest-exec", path=path, arg=args, **{"capture-output": True})
        pid = result["pid"]
        if type(pid) is not int or pid <= 0:
            raise SmokeError("invalid guest process identity")
        deadline = time.monotonic() + (timeout or self.args.timeout_seconds)
        while time.monotonic() < deadline:
            state = self.agent("guest-exec-status", pid=pid)
            if logs:
                self.capture_logs(logs, offsets, label, budget=min(1, max(.01, deadline-time.monotonic())))
            if state.get("exited") is True:
                self.guest_process_exited = True
                if state.get("out-truncated") or state.get("err-truncated"):
                    raise SmokeError("guest evidence was truncated")
                out = base64.b64decode(state.get("out-data", ""), validate=True)
                err = base64.b64decode(state.get("err-data", ""), validate=True)
                self.evidence.joinpath(f"{self.serial:04d}-guest-stdout").write_bytes(out)
                self.evidence.joinpath(f"{self.serial:04d}-guest-stderr").write_bytes(err)
                return state.get("exitcode", -1), out
            time.sleep(min(.1, max(0, deadline - time.monotonic())))
        raise SmokeError("guest execution timed out; snapshot restore required")

    def checked(self, path, args, timeout=None):
        status, output = self.execute(path, args, timeout)
        if status != 0:
            raise SmokeError("guest process refused smoke")
        return output

    def baseline(self):
        output = self.checked("/usr/bin/python3.11", ["-I", "-c", BASELINE]).decode().strip()
        if SHA.fullmatch(output) is None:
            raise SmokeError("invalid baseline digest")
        return output

    def snapshot_identity(self, snapshot, targets):
        raw = self.bound("snapshot-dumpxml", snapshot)
        self.evidence.joinpath("snapshot.xml").write_bytes(raw)
        value = ET.fromstring(raw)
        disks = value.findall("./disks/disk")
        if (value.findtext("name") != snapshot or value.findtext("domain/uuid") != self.domain_uuid
                or value.findtext("state") != "running"
                or value.find("memory") is None or value.find("memory").get("snapshot") != "internal"
                or {disk.get("name") for disk in disks} != set(targets)
                or len(disks) != len(targets) or any(disk.get("snapshot") != "internal" for disk in disks)):
            raise SmokeError("snapshot does not cover exact guest memory and disks")

    def upload(self, source, destination):
        handle = self.agent("guest-file-open", path=destination, mode="wb")
        try:
            with source.open("rb") as stream:
                while chunk := stream.read(48 * 1024):
                    result = self.agent("guest-file-write", handle=handle,
                                        **{"buf-b64": base64.b64encode(chunk).decode()})
                    if result.get("count") != len(chunk):
                        raise SmokeError("short guest upload")
            self.agent("guest-file-flush", handle=handle)
        finally:
            self.agent("guest-file-close", handle=handle)


def pinned_admission(args):
    approved = json.loads(ordinary(args.approval, args.approval_sha256), object_pairs_hook=unique)
    source = args.app_tag_source
    if source.is_symlink() or not source.is_dir():
        raise SmokeError("unsafe reviewed application source")
    def git(*command):
        return subprocess.run(["git", "-C", str(source), *command], check=True,
                              capture_output=True, text=True).stdout.strip()
    if git("rev-parse", "HEAD") != approved["app_commit"] or git("rev-parse", "refs/tags/" + approved["app_tag"] + "^{commit}") != approved["app_commit"] or git("status", "--porcelain=v1", "--untracked-files=all"):
        raise SmokeError("reviewed application source identity changed or dirty")
    for name, pin in (("verify-public-release.py", args.app_verifier_sha256),
                      ("check-public-fresh-host.py", args.fresh_host_sha256),
                      ("verify-public-fresh-smoke.py", args.report_verifier_sha256)):
        ordinary(source / "packaging/rpm" / name, pin)
    api = runpy.run_path(str(source / "packaging/rpm/verify-public-release.py"))
    paths = api["verify_fresh_install_inputs"](args.app_candidate, args.driver_candidate,
                                               args.driver_tag_source, approved)
    return approved, paths


def bundle(args, approved, path):
    # Exact immutable archive bytes are the staged inputs; guest repeats admission.
    # No link entries or special files can enter the guest extraction.
    mapping = {
        "app-source": args.app_tag_source, "driver-source": args.driver_tag_source,
        "app-candidate": args.app_candidate, "driver-candidate": args.driver_candidate,
    }
    with tarfile.open(path, "w:gz") as archive:
        for prefix, root in mapping.items():
            for item in (root, *sorted(root.rglob("*"))):
                info = item.lstat()
                if item.is_symlink() or not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
                    raise SmokeError("staged source/candidate contains unsafe links or special files")
                archive.add(item, arcname=str(Path(prefix) / item.relative_to(root)), recursive=False)
        for name in ("run-public-fresh-vm-smoke.py", "public_fresh_guest.py", "smoke-public-fresh-rhel9.sh"):
            archive.add(HERE / name, arcname=name, recursive=False)
        approval = Path(approved["driver_approval_file"])
        ordinary(approval, approved["driver_approval_sha256"])
        archive.add(approval, arcname="driver-approval.json", recursive=False)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("libvirt-uri", "domain", "approval-sha256", "app-verifier-sha256",
                 "fresh-host-sha256", "report-verifier-sha256"):
        parser.add_argument("--" + name, required=True)
    for name in ("app-candidate", "driver-candidate", "app-tag-source", "driver-tag-source", "approval", "report"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--timeout-seconds", type=float, default=600)
    parser.add_argument("--test-network-name")
    parser.add_argument("--test-network-uuid")
    args = parser.parse_args(argv)
    if args.libvirt_uri not in {"qemu:///system", "qemu:///session"} or not 0 < args.timeout_seconds <= 7200:
        parser.error("only local libvirt and a bounded positive timeout are supported")
    if bool(args.test_network_name) != bool(args.test_network_uuid):
        parser.error("test network requires both explicit name and UUID")
    if args.test_network_name:
        if re.fullmatch(r"[A-Za-z0-9_.-]+", args.test_network_name) is None:
            parser.error("invalid test network name")
        try:
            if str(uuid.UUID(args.test_network_uuid)) != args.test_network_uuid:
                raise ValueError
        except ValueError:
            parser.error("invalid test network UUID")
    # Never overwrite an earlier report or place evidence through a symlink.
    if not args.report.is_absolute() or args.report.exists() or args.report.is_symlink() or any(p.is_symlink() for p in args.report.parents):
        parser.error("report must be a new absolute ordinary controller file")
    args.report.parent.mkdir(parents=True, exist_ok=True)
    evidence = Path(tempfile.mkdtemp(prefix=args.report.name + ".private-", dir=args.report.parent))
    os.umask(0o077)
    controller = Controller(args, evidence)
    report = {"schema_version": 2, "profile": "fresh-rhel9-webui-hardware-absent",
              "qualified": False, "unverified_features": ["backup_restore", "daemon_import", "physical_ltfs"],
              "app_commit": "0" * 40, "driver_commit": "0" * 40, "rpm_sha256": {},
              "baseline_sha256": "0" * 64, "restored_sha256": "0" * 64,
              "uninstall_generated_state_count": 0, "checks": dict.fromkeys(CHECKS, False)}
    snapshot = "lto-fresh-" + uuid.uuid4().hex
    snapshot_attempted = False
    failures = []
    def interrupted(signum, frame):
        raise SmokeInterrupted("controller interrupted; restoring snapshot")
    previous = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGTERM, signal.SIGINT)}
    try:
        value = controller.command("domuuid", args.domain).decode().strip()
        if str(uuid.UUID(value)) != value:
            raise SmokeError("invalid stable domain UUID")
        controller.domain_uuid = value
        targets = controller.domain()
        if controller.bound("domstate").decode().strip() != "running":
            raise SmokeError("running guest required for internal memory snapshot")
        report["checks"]["disposable_marker"] = True
        report["baseline_sha256"] = controller.baseline()
        controller.domain()  # Rebind just before creating a rollback point.
        snapshot_attempted = True
        controller.bound("snapshot-create-as", snapshot, "--atomic",
                         "--description", "LTO explicit disposable first-install recovery")
        controller.snapshot_identity(snapshot, targets)
        report["checks"]["snapshot_created"] = True
        controller.checked("/usr/bin/python3.11", ["-I", "-c", PLATFORM])
        approved, paths = pinned_admission(args)
        report.update(app_commit=approved["app_commit"], driver_commit=approved["driver_commit"])
        report["rpm_sha256"] = {path.name: hashlib.sha256(ordinary(path)).hexdigest() for path in paths}
        with tempfile.TemporaryDirectory(prefix="lto-fresh-stage-") as raw:
            archive = Path(raw) / "inputs.tar.gz"
            digest = bundle(args, approved, archive)
            stage = "/var/tmp/" + snapshot
            controller.domain()
            controller.checked("/usr/bin/mkdir", ["-m", "0700", stage])
            controller.upload(archive, stage + "/inputs.tar.gz")
            extract = "import hashlib,tarfile;from pathlib import Path;p=Path(" + repr(stage) + ");a=p/'inputs.tar.gz';assert hashlib.sha256(a.read_bytes()).hexdigest()==" + repr(digest) + ";tarfile.open(a).extractall(p,filter='data')"
            controller.checked("/usr/bin/python3.11", ["-I", "-c", extract])
            config = {"approved": {**approved, "driver_approval_file": stage + "/driver-approval.json"},
                      "app_verifier_sha256": args.app_verifier_sha256,
                      "fresh_host_sha256": args.fresh_host_sha256,
                      "report_verifier_sha256": args.report_verifier_sha256,
                      "rpm_sha256": report["rpm_sha256"], "domain_uuid": controller.domain_uuid,
                      "snapshot": snapshot, "baseline_sha256": report["baseline_sha256"]}
            config_path = Path(raw) / "controller-proof.json"
            config_path.write_text(json.dumps(config))
            controller.upload(config_path, stage + "/controller-proof.json")
            # Preserve exact archive bytes outside guest even on later failures.
            evidence.joinpath("staging-sha256").write_text(digest + "\n")
            status, output = controller.execute("/usr/bin/bash", [stage + "/smoke-public-fresh-rhel9.sh",
                         stage + "/app-candidate", stage + "/driver-candidate", stage + "/guest-report.json"], args.timeout_seconds,
                         logs=[stage + "/guest.stdout", stage + "/guest.stderr"])
            observation = json.loads(controller.checked("/usr/bin/cat", [stage + "/guest-report.json"]), object_pairs_hook=unique)
            if set(observation) != {"checks", "uninstall_generated_state_count", "rpm_sha256"} or observation["rpm_sha256"] != report["rpm_sha256"]:
                raise SmokeError("guest observation identity differs")
            if set(observation["checks"]) != set(CHECKS) - {"disposable_marker", "snapshot_created", "snapshot_restored"} or any(type(v) is not bool for v in observation["checks"].values()):
                raise SmokeError("guest check closure differs")
            report["checks"].update(observation["checks"])
            report["uninstall_generated_state_count"] = observation["uninstall_generated_state_count"]
            if status != 0 or not all(observation["checks"].values()):
                raise SmokeError("guest smoke failed")
    except BaseException as error:
        failures.append(type(error).__name__ + ": " + str(error))
    finally:
        # Repeated signals cannot skip rollback. A failed/ambiguous snapshot create
        # is also reverted by its unique name, never guessed from a current pointer.
        for sig in previous:
            signal.signal(sig, signal.SIG_IGN)
        if snapshot_attempted:
            try:
                controller.domain()
                controller.snapshot_identity(snapshot, targets)
                controller.bound("snapshot-revert", snapshot, "--running")
                controller.domain()
                report["restored_sha256"] = controller.baseline()
                report["checks"]["snapshot_restored"] = report["baseline_sha256"] == report["restored_sha256"]
                if not report["checks"]["snapshot_restored"]:
                    failures.append("restored baseline differs")
            except BaseException as error:
                failures.append("restore failed: " + type(error).__name__ + ": " + str(error))
        report["qualified"] = not failures and all(report["checks"].values())
        if report["qualified"]:
            # The pinned schema validator remains the final admission authority.
            try:
                raw = json.dumps(report, sort_keys=True, separators=(",", ":")).encode()
                trial = evidence / "report-validation.json"
                trial.write_bytes(raw)
                gate = args.app_tag_source / "packaging/rpm/verify-public-fresh-smoke.py"
                ordinary(gate, args.report_verifier_sha256)
                api = runpy.run_path(str(gate))
                api["verify_report"](trial, hashlib.sha256(raw).hexdigest(), report["app_commit"], paths[2], paths[1])
            except BaseException as error:
                report["qualified"] = False
                failures.append("schema validation failed: " + type(error).__name__)
        with args.report.open("x", encoding="utf-8") as stream:
            json.dump(report, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        evidence.joinpath("failures.json").write_text(json.dumps(failures))
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    print("qualified" if report["qualified"] else "unqualified; inspect retained private controller evidence")
    return 0 if report["qualified"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
