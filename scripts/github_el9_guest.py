#!/usr/bin/env python3
"""Actual installed-package observations; never claims signed/RHEL qualification."""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import runpy
import stat

ROOT = Path(__file__).resolve().parent
API = runpy.run_path(str(ROOT / "source/packaging/rpm/public_fresh_guest.py"))
run = API["run"]
PACKAGES = {
    "lto-ltfs-0.1.2-22.el9.x86_64.rpm": "a2f234284c96c3f35f358f46d8977e7fbba53f8d292d04eb5d909f7dd5f46a44",
    "lto-archiver-python-runtime-0.11.27-3.el9.x86_64.rpm": "59c9694981bcbff8583b4d16b0fe7ea3137cb2b102e506a4af897193fe895bb3",
    "lto-archiver-0.11.31-155.el9.noarch.rpm": "bfc77147a6b98623eb74cb8c19d4fe477bd9af71abcea7dd693b8e6488b916c9",
}
CHECKS = ["fresh_host", "hardware_absent", "hash_pinned_unsigned_tuple", "install_order",
          "installed_nevras", "rpm_verify", "unit_syntax", "service_accounts", "selinux",
          "live_web_login", "preflight_refuses_unsupported_host", "uninstall_residue_recorded",
          "uninstall_no_owned_executables", "uninstall_no_active_units"]


def main():
    checks = dict.fromkeys(CHECKS, False)
    report = {"schema_version": 1, "profile": "github-almalinux9-unsigned-compatibility",
        "qualified": False, "compatibility_passed": False, "checks": checks,
        "app_commit": "4507cd23e96fef48dd3099d0da69bb7cda3a9a27",
        "driver_commit": "61f8b6acb547e715624856e85786e7676fa28c37", "rpm_sha256": {},
        "unverified_features": ["backup_restore", "daemon_import", "physical_ltfs", "rhel9",
                                "rpm_signatures", "snapshot_restoration"], "errors": []}
    packages = [ROOT / "rpms" / name for name in PACKAGES]
    attempted, executables, units = False, [], []
    try:
        if "AlmaLinux release 9." not in Path("/etc/redhat-release").read_text():
            raise ValueError("Expected actual AlmaLinux 9, not a substituted identity")
        API["fresh_host"](ROOT / "source/packaging/rpm/check-public-fresh-host.py")
        checks["fresh_host"] = True
        if list(Path("/sys/class/scsi_tape").glob("*")) or list(Path("/sys/class/scsi_generic").glob("*")):
            raise ValueError("Guest unexpectedly contains tape/SCSI devices")
        checks["hardware_absent"] = True
        report["rpm_sha256"] = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in packages}
        if report["rpm_sha256"] != PACKAGES or run(["getenforce"]).stdout.strip() != b"Enforcing":
            raise ValueError("RPM input drift or SELinux not enforcing")
        checks["hash_pinned_unsigned_tuple"] = True
        attempted = True
        for path in packages:
            # Unsigned test artifacts only; distribution dependencies retain their normal GPG checks.
            run(["dnf", "-y", "--setopt=localpkg_gpgcheck=0", "install", str(path)], timeout=300)
        checks["install_order"] = True
        executables, units = API["installed_checks"](packages, ROOT / "source", checks)
        API["tls_login"]()
        checks["live_web_login"] = True
        result = run(["/usr/libexec/lto-archiver/preflight-rhel9.sh", "--config",
                      "/etc/lto-archiver/config.toml", "--json"], check=False)
        observed = json.loads(result.stdout)
        rows = observed["checks"]
        if (result.returncode != 2 or observed.get("ok") is not False or observed.get("schema") != 1
                or len(rows) != len(API["HARDWARE_CHECKS"])
                or {row["name"] for row in rows} != API["HARDWARE_CHECKS"]
                or any(type(row["ok"]) is not bool for row in rows)):
            raise ValueError("Expected complete real preflight refusal")
        values = {row["name"]: row["ok"] for row in rows}
        if (values["platform.rhel9"] is not False or values["devices.stable"] is not False
                or any(values[name] is not True for name in ("selinux.enforcing", "accounts.present", "windows.inactive"))):
            raise ValueError("Unsupported AlmaLinux identity/hardware not correctly refused")
        checks["preflight_refuses_unsupported_host"] = True
        report["preflight"] = observed
    except Exception as error:
        report["errors"].append(type(error).__name__ + ": " + str(error))
    finally:
        if attempted:
            try:
                units = sorted(set(units) | set(API["managed_units"]()) | {"lto-archiver-fresh-web.service"})
                for unit in units:
                    run(["systemctl", "stop", unit], check=False)
                installed = []
                for path in reversed(packages):
                    name = run(["rpm", "-qp", "--qf", "%{NAME}", str(path)]).stdout.decode().strip()
                    if run(["rpm", "-q", name], check=False).returncode == 0:
                        installed.append(name)
                        rows = run(["rpm", "-q", "--qf", "[%{FILENAMES}\t%{FILEMODES:octal}\n]", name]).stdout.decode().splitlines()
                        executables += [row.split("\t")[0] for row in rows
                            if int(row.split("\t")[1], 8) & 0o111 and not stat.S_ISDIR(int(row.split("\t")[1], 8))]
                if installed:
                    run(["rpm", "-e", *installed])
                for name in installed:
                    if run(["rpm", "-q", name], check=False).returncode != 1:
                        raise ValueError("Installed package remains after erase")
                fresh = runpy.run_path(str(ROOT / "source/packaging/rpm/check-public-fresh-host.py"))
                report["uninstall_generated_state"] = fresh["collect_host_state"]()._asdict()
                checks["uninstall_residue_recorded"] = True
                API["no_owned_executables"](executables)
                checks["uninstall_no_owned_executables"] = True
                API["no_active_units"](units)
                checks["uninstall_no_active_units"] = True
            except Exception as error:
                report["errors"].append("uninstall: " + type(error).__name__ + ": " + str(error))
        report["compatibility_passed"] = all(checks.values()) and not report["errors"]
        encoded = base64.b64encode(json.dumps(report, sort_keys=True).encode()).decode()
        print("LTO_EL9_RESULT=" + encoded, flush=True)
    return 0 if report["compatibility_passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
