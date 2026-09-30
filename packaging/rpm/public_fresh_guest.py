#!/usr/bin/env python3
"""Indispensable stdlib guest observations for the disposable-VM controller.

No application imports come from the staged source. Source is used exclusively
by the exact pinned signed-input verifier and byte comparisons.
"""
from __future__ import annotations

import argparse
import grp
import hashlib
import http.cookiejar
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import pwd
import runpy
import secrets
import selectors
import signal
import ssl
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

# Import sibling controller utilities without admitting an ambient PYTHONPATH.
_HERE = Path(__file__).resolve().parent
_controller = runpy.run_path(str(_HERE / "run-public-fresh-vm-smoke.py"))
SmokeError = _controller["SmokeError"]
ordinary = _controller["ordinary"]
unique = _controller["unique"]
CHECKS = _controller["CHECKS"]
HARDWARE_CHECKS = frozenset({
    "platform.rhel9", "selinux.enforcing", "accounts.present", "devices.stable",
    "ltfs.tools", "ltfs.provenance", "ltfs.fuse_boundary", "shares.helpers",
    "shares.broker_boundary", "shares.permissions", "sources.readable",
    "mount.empty_unmounted", "state.permissions", "windows.inactive",
})


def run(command, *, check=True, input=None, timeout=180):
    # Only argv is logged. Ephemeral password input is NEVER logged.
    print(json.dumps({"command": command}), file=sys.stderr, flush=True)
    process = subprocess.Popen(command, stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    outputs = {"stdout": bytearray(), "stderr": bytearray()}
    try:
        if input is not None:
            process.stdin.write(input)
            process.stdin.close()
        deadline = time.monotonic() + timeout
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ, "stdout")
            selector.register(process.stderr, selectors.EVENT_READ, "stderr")
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(command, timeout, bytes(outputs["stdout"]), bytes(outputs["stderr"]))
                for key, event in selector.select(min(remaining, .2)):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    outputs[key.data].extend(chunk)
                    # Stream diagnostics immediately; retain parsed output too.
                    print(chunk.decode("utf-8", "replace"), end="", file=sys.stderr, flush=True)
        process.wait(timeout=max(.001, deadline - time.monotonic()))
    except BaseException as error:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        out, err = process.communicate() if input is None else (process.stdout.read(), process.stderr.read())
        process.wait()
        if isinstance(error, subprocess.TimeoutExpired):
            partial_out = bytes(outputs["stdout"]) + (out or b"")
            partial_err = bytes(outputs["stderr"]) + (err or b"")
            print(json.dumps({"timeout": True, "stdout": partial_out.decode("utf-8", "replace"),
                              "stderr": partial_err.decode("utf-8", "replace")}), file=sys.stderr, flush=True)
            raise subprocess.TimeoutExpired(command, timeout, partial_out, partial_err) from None
        raise
    finally:
        if process.stdin is not None and not process.stdin.closed:
            process.stdin.close()
        process.stdout.close()
        process.stderr.close()
    result = subprocess.CompletedProcess(command, process.returncode, bytes(outputs["stdout"]), bytes(outputs["stderr"]))
    print(json.dumps({"returncode": result.returncode,
                      "stdout": result.stdout.decode("utf-8", "replace"),
                      "stderr": result.stderr.decode("utf-8", "replace")}), file=sys.stderr, flush=True)
    if check and result.returncode:
        raise SmokeError("guest command failed: " + command[0])
    return result


def fresh_host(verifier):
    api = runpy.run_path(str(verifier))
    state = api["collect_host_state"]()
    reasons = api["evaluate_fresh_host"](state)
    print(json.dumps({"fresh_host_observed": state._asdict(), "reasons": reasons}), file=sys.stderr)
    if reasons:
        raise SmokeError("actual fresh-host preflight refused")


class CSRF(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tokens = []
    def handle_starttag(self, tag, attrs):
        value = dict(attrs)
        if tag == "input" and value.get("name") == "login_csrf":
            self.tokens.append(value.get("value", ""))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def live_login(url, password, tls_context):
    cookies = http.cookiejar.CookieJar()
    handlers = [urllib.request.HTTPCookieProcessor(cookies), NoRedirect()]
    if tls_context is not None:
        handlers.append(urllib.request.HTTPSHandler(context=tls_context))
    client = urllib.request.build_opener(*handlers)
    try:
        with client.open(url + "/login", timeout=10) as response:
            if response.status != 200:
                raise SmokeError("live login page failed")
            parser = CSRF()
            parser.feed(response.read(262144).decode("utf-8"))
        if len(parser.tokens) != 1 or not parser.tokens[0] or not list(cookies):
            raise SmokeError("live login CSRF or cookie absent")
        body = urllib.parse.urlencode({"username": "lto-smoke", "password": password,
                                      "login_csrf": parser.tokens[0], "next": "/account"}).encode()
        try:
            client.open(urllib.request.Request(url + "/login", data=body), timeout=10)
        except urllib.error.HTTPError as response:
            try:
                if response.code != 303 or response.headers.get("Location") != "/account":
                    raise SmokeError("authentication did not produce protected-account redirect") from None
            finally:
                response.close()
        else:
            raise SmokeError("static HTTP response cannot prove authentication")
        if not any(cookie.name == "lto_archiver_session" and cookie.value for cookie in cookies):
            raise SmokeError("authentication session cookie absent")
        with client.open(url + "/account", timeout=10) as response:
            content = response.read(262144)
            if response.status != 200 or b"lto-smoke" not in content or b"Current credential" not in content:
                raise SmokeError("protected authenticated account request failed")
        print('live login: CSRF, 303, session cookie and protected account observed', file=sys.stderr)
    except (OSError, urllib.error.URLError, UnicodeError) as error:
        raise SmokeError("live WebUI authentication failed") from error


def hardware_refusal(command):
    result = run(command, check=False)
    try:
        value = json.loads(result.stdout, object_pairs_hook=unique)
        checks = value["checks"]
        if (set(value) != {"schema", "ok", "checks"} or value["schema"] != 1
                or value["ok"] is not False or result.returncode != 2
                or type(checks) is not list or len(checks) != len(HARDWARE_CHECKS)
                or any(set(row) != {"name", "ok"} or type(row["ok"]) is not bool for row in checks)
                or {row["name"] for row in checks} != HARDWARE_CHECKS):
            raise SmokeError("hardware refusal is not a complete real preflight result")
        observed = {row["name"]: row["ok"] for row in checks}
        if observed["devices.stable"] is not False or any(observed[name] is not True for name in (
                "platform.rhel9", "selinux.enforcing", "accounts.present", "windows.inactive")):
            raise SmokeError("missing hardware was not specifically refused")
    except (KeyError, TypeError, ValueError) as error:
        raise SmokeError("invalid hardware preflight evidence") from error


def no_owned_executables(paths):
    leftovers = []
    for name in paths:
        path = Path(name)
        try:
            path.lstat()
            leftovers.append(name)  # Catch dangling links and changed modes too.
        except FileNotFoundError:
            pass
    print(json.dumps({"remaining_owned_executable_paths": leftovers}), file=sys.stderr)
    if leftovers:
        raise SmokeError("owned executable remains after package erase")


def no_active_units(units):
    for unit in units:
        result = run(["systemctl", "show", "--property=ActiveState", unit], check=False)
        # An unloaded removed unit still reports inactive; unknown/error is refused.
        if result.returncode != 0 or result.stdout.strip() not in {b"ActiveState=inactive", b"ActiveState=failed"}:
            raise SmokeError("managed unit remains active or cannot be observed")


def managed_units():
    output = run(["systemctl", "list-units", "--all", "--full", "--plain", "--no-legend", "--no-pager",
                  "lto-archiver*", "lto-ltfs*"]).stdout.decode().splitlines()
    return sorted({line.split()[0] for line in output if line.split()})


def account_checks():
    daemon, web = pwd.getpwnam("lto-archiver"), pwd.getpwnam("lto-web")
    if daemon.pw_uid <= 0 or web.pw_uid <= 0 or daemon.pw_uid == web.pw_uid:
        raise SmokeError("unsafe service accounts")
    for account in (daemon, web):
        if account.pw_shell not in {"/usr/sbin/nologin", "/sbin/nologin"}:
            raise SmokeError("service account has an interactive shell")
    if web.pw_gid != grp.getgrnam("lto-web").gr_gid or "lto-web" not in grp.getgrnam("lto-archiver").gr_mem:
        raise SmokeError("WebUI service group contract differs")
    print(json.dumps({"accounts": {daemon.pw_name: daemon.pw_uid, web.pw_name: web.pw_uid}}), file=sys.stderr)


def tls_login():
    # Runtime-only disposable test material, never controller credentials/keys.
    cert = Path("/etc/lto-archiver/tls/smoke.crt")
    key = Path("/etc/lto-archiver/tls/smoke.key")
    if cert.exists() or key.exists():
        raise SmokeError("ephemeral TLS target already exists")
    run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
         "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1",
         "-keyout", str(key), "-out", str(cert)])
    key.chmod(0o640)
    os.chown(key, 0, grp.getgrnam("lto-web").gr_gid)
    cert.chmod(0o644)
    run(["restorecon", str(cert), str(key)])
    password = secrets.token_urlsafe(32)
    try:
        run(["runuser", "-u", "lto-web", "--", "/usr/bin/lto-archiver-web", "admin", "create",
             "--username", "lto-smoke", "--password-fd", "0"], input=(password + "\n").encode())
        run(["systemd-run", "--unit=lto-archiver-fresh-web.service", "--property=User=lto-web",
             "--property=Group=lto-web", "--property=SupplementaryGroups=lto-archiver",
             "--property=UMask=0077", "/usr/bin/lto-archiver-web", "serve", "--host", "127.0.0.1",
             "--port", "8443", "--tls-certfile", str(cert), "--tls-keyfile", str(key)])
        context = ssl.create_default_context(cafile=str(cert))
        # Retry only reachability, never authentication failures or static substitutes.
        deadline = time.monotonic() + 30
        while True:
            try:
                with urllib.request.urlopen("https://127.0.0.1:8443/login", context=context, timeout=2) as response:
                    if response.status == 200:
                        break
            except (OSError, urllib.error.URLError):
                if time.monotonic() >= deadline:
                    raise SmokeError("installed WebUI did not become reachable")
                time.sleep(.2)
        live_login("https://127.0.0.1:8443", password, context)
    finally:
        password = ""


def installed_checks(packages, source, checks):
    files, executables, units = [], [], []
    for path in packages:
        expected = path.name.removesuffix(".rpm")
        name = run(["rpm", "-qp", "--qf", "%{NAME}", str(path)]).stdout.decode().strip()
        actual = run(["rpm", "-q", "--qf", "%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}", name]).stdout.decode().strip()
        if actual != expected:
            raise SmokeError("installed NEVRA differs from admitted RPM")
        result = run(["rpm", "-V", name])
        if result.stdout.strip():
            raise SmokeError("installed RPM verification reports modified payload")
        listing = run(["rpm", "-q", "--qf", "[%{FILENAMES}\t%{FILEMODES:octal}\n]", name]).stdout.decode().splitlines()
        for row in listing:
            filename, mode = row.split("\t")
            files.append(filename)
            if int(mode, 8) & 0o111 and not stat.S_ISDIR(int(mode, 8)):
                executables.append(filename)
            if filename.startswith("/usr/lib/systemd/system/") and filename.endswith((".service", ".socket")):
                units.append(filename)
    checks["installed_nevras"] = True
    # Source-identical license/SBOM evidence is included in the rpm_verify gate.
    for installed, reviewed in (
        ("/usr/share/doc/lto-archiver/THIRD_PARTY_NOTICES.md", "THIRD_PARTY_NOTICES.md"),
        ("/usr/share/licenses/lto-archiver-python-runtime/THIRD_PARTY_NOTICES.md", "packaging/python-runtime/THIRD_PARTY_NOTICES.md"),
        ("/usr/share/doc/lto-archiver-python-runtime/runtime.spdx.json", "packaging/python-runtime/runtime.spdx.json"),
    ):
        if ordinary(Path(installed)) != ordinary(source / reviewed):
            raise SmokeError("installed notices/SBOM differ from reviewed source")
    checks["rpm_verify"] = True
    if not units:
        raise SmokeError("installed managed unit inventory is empty")
    run(["systemd-analyze", "verify", *sorted(units)])
    checks["unit_syntax"] = True
    account_checks()
    checks["service_accounts"] = True
    if run(["getenforce"]).stdout.strip() != b"Enforcing":
        raise SmokeError("SELinux is not enforcing")
    modules = run(["semodule", "-l"]).stdout.decode().splitlines()
    if not any(line.split()[0] == "lto_archiver" for line in modules if line.split()):
        raise SmokeError("installed SELinux policy absent")
    for filename in sorted(set(files)):
        if Path(filename).exists() and not Path(filename).is_symlink():
            run(["matchpathcon", "-V", filename])
    checks["selinux"] = True
    return executables, [Path(name).name for name in units]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("app_candidate", type=Path)
    parser.add_argument("driver_candidate", type=Path)
    parser.add_argument("report", type=Path)
    args = parser.parse_args(argv)
    checks = dict.fromkeys(set(CHECKS) - {"disposable_marker", "snapshot_created", "snapshot_restored"}, False)
    report = {"checks": checks, "rpm_sha256": {}, "uninstall_generated_state_count": 0}
    packages, executable_paths, units = (), [], []
    install_attempted = False
    failed = False
    stage = _HERE
    try:
        proof_path = stage / "controller-proof.json"
        if (os.geteuid() != 0 or stage.is_symlink() or stage.stat().st_uid != 0
                or stat.S_IMODE(stage.stat().st_mode) != 0o700
                or not stage.name.startswith("lto-fresh-")):
            raise SmokeError("guest requires private root-owned controller staging")
        proof = json.loads(ordinary(proof_path), object_pairs_hook=unique)
        if (proof["snapshot"] != stage.name or not _controller["SHA"].fullmatch(proof["baseline_sha256"])
                or str(_controller["uuid"].UUID(proof["domain_uuid"])) != proof["domain_uuid"]
                or args.app_candidate != stage / "app-candidate" or args.driver_candidate != stage / "driver-candidate"
                or args.report != stage / "guest-report.json"):
            raise SmokeError("controller staging proof is unbound")
        source = stage / "app-source"
        for name, pin in (("verify-public-release.py", proof["app_verifier_sha256"]),
                          ("check-public-fresh-host.py", proof["fresh_host_sha256"]),
                          ("verify-public-fresh-smoke.py", proof["report_verifier_sha256"])):
            ordinary(source / "packaging/rpm" / name, pin)
        # Require the staged whole reviewed source identity, not a standalone file.
        for prefix, identity in (("app", proof["approved"]["app_commit"]), ("driver", proof["approved"]["driver_commit"])):
            repo = stage / (prefix + "-source")
            if run(["git", "-C", str(repo), "rev-parse", "HEAD"]).stdout.decode().strip() != identity or run([
                    "git", "-C", str(repo), "status", "--porcelain=v1", "--untracked-files=all"]).stdout.strip():
                raise SmokeError("staged reviewed source is dirty or changed")
        fresh_host(source / "packaging/rpm/check-public-fresh-host.py")
        checks["fresh_host"] = True
        api = runpy.run_path(str(source / "packaging/rpm/verify-public-release.py"))
        packages = api["verify_fresh_install_inputs"](args.app_candidate, args.driver_candidate,
                                                      stage / "driver-source", proof["approved"])
        hashes = {path.name: hashlib.sha256(ordinary(path)).hexdigest() for path in packages}
        report["rpm_sha256"] = hashes
        if hashes != proof["rpm_sha256"]:
            raise SmokeError("staged admitted tuple differs from controller")
        checks["signed_tuple"] = True
        # Actual hardware absence is required before mutation as well as afterward.
        if list(Path("/sys/class/scsi_tape").glob("*")) or list(Path("/sys/class/scsi_generic").glob("*")):
            raise SmokeError("guest contains tape/SCSI hardware")
        if run(["getenforce"]).stdout.strip() != b"Enforcing":
            raise SmokeError("guest requires enforcing SELinux")
        # Keys are verified public assets. Import is inside rollback scope.
        install_attempted = True
        for candidate in (args.driver_candidate, args.app_candidate):
            run(["rpmkeys", "--import", str(candidate / "RPM-PUBLIC-KEY.asc")])
        for path in packages:  # Actual verifier returns driver -> runtime -> app.
            if hashlib.sha256(ordinary(path)).hexdigest() != hashes[path.name]:
                raise SmokeError("RPM changed immediately before install")
            run(["dnf", "-y", "--disablerepo=*", "--setopt=localpkg_gpgcheck=1", "install", str(path)])
        checks["install_order"] = True
        executable_paths, units = installed_checks(packages, source, checks)
        tls_login()
        checks["live_web_login"] = True
        # Prove settings load via installed paths, no staged app import.
        installed = "import sys;sys.dont_write_bytecode=True;sys.path[:0]=['/usr/lib64/lto-archiver/python-runtime/3.11/site-packages','/usr/lib/python3.11/site-packages'];from pathlib import Path;from ltobackup.linux_settings import load_linux_settings;load_linux_settings(Path('/etc/lto-archiver/config.toml')).validate();print('installed settings valid')"
        run(["/usr/bin/python3.11", "-I", "-c", installed])
        hardware_refusal(["/usr/libexec/lto-archiver/preflight-rhel9.sh", "--config", "/etc/lto-archiver/config.toml", "--json"])
        checks["hardware_absence_refused"] = True
    except Exception as error:
        failed = True
        print("guest smoke refused: " + type(error).__name__ + ": " + str(error), file=sys.stderr)
    finally:
        if install_attempted:
            try:
                units = sorted(set(units) | set(managed_units()) | {"lto-archiver-fresh-web.service"})
                for unit in units:
                    run(["systemctl", "stop", unit], check=False)
                installed = []
                for path in reversed(packages):
                    name = run(["rpm", "-qp", "--qf", "%{NAME}", str(path)]).stdout.decode().strip()
                    if run(["rpm", "-q", name], check=False).returncode == 0:
                        installed.append(name)
                        # Recover owned executable inventory even if an earlier
                        # installed check failed; never infer erase success.
                        rows = run(["rpm", "-q", "--qf", "[%{FILENAMES}\t%{FILEMODES:octal}\n]", name]).stdout.decode().splitlines()
                        executable_paths += [row.split("\t")[0] for row in rows
                            if int(row.split("\t")[1], 8) & 0o111 and not stat.S_ISDIR(int(row.split("\t")[1], 8))]
                if installed:
                    run(["rpm", "-e", *installed])
                for name in installed:
                    if run(["rpm", "-q", name], check=False).returncode != 1:
                        raise SmokeError("erased package remains or inventory failed")
                # Generated files are deliberately preserved and enumerated.
                fresh = runpy.run_path(str(stage / "app-source/packaging/rpm/check-public-fresh-host.py"))
                observed = fresh["collect_host_state"]()
                roots = list(observed.existing_paths)
                residue = set(roots)
                for name in roots:
                    path = Path(name)
                    if path.is_dir() and not path.is_symlink():
                        residue.update(str(item) for item in path.rglob("*"))
                report["uninstall_generated_state_count"] = len(residue)
                print(json.dumps({"uninstall_observed": observed._asdict(), "generated_paths": sorted(residue)}), file=sys.stderr)
                checks["uninstall_residue_recorded"] = True
                no_owned_executables(sorted(set(executable_paths)))
                checks["uninstall_no_owned_executables"] = True
                no_active_units(sorted(set(units) | set(managed_units())))
                checks["uninstall_no_active_units"] = True
            except Exception as error:
                failed = True
                print("uninstall observation refused: " + type(error).__name__ + ": " + str(error), file=sys.stderr)
        try:
            with args.report.open("x", encoding="utf-8") as stream:
                json.dump(report, stream, sort_keys=True)
                stream.write("\n")
        except OSError:
            failed = True
    return 2 if failed or not all(checks.values()) else 0


if __name__ == "__main__":
    raise SystemExit(main())
