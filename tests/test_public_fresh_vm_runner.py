"""Process-boundary refusal/recovery tests; fixtures NEVER qualify a release."""
from __future__ import annotations

import contextlib
import http.server
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
CONTROLLER = ROOT / "packaging/rpm/run-public-fresh-vm-smoke.py"
GUEST = ROOT / "packaging/rpm/public_fresh_guest.py"

# Removing storage/marker checks or finally restoration must break these cases.
VIRSH = r'''#!/usr/bin/env python3
import base64,json,os,sys,time
from pathlib import Path
p=Path(os.environ['FIXTURE']); case=os.environ['CASE']; args=sys.argv[1:]
assert args[:2] == ['--connect','qemu:///session']
cmd=args[2]; target=args[3] if len(args)>3 else ''
uuid='11111111-2222-3333-4444-555555555555'
with (p/'calls').open('a') as f: f.write(json.dumps(args)+'\n')
if cmd=='domuuid': print(uuid); sys.exit(0)
if cmd=='net-dumpxml':
    assert target=='lto-test-net'
    mode='bridge' if case=='physical-network' else 'nat'
    print('<network><name>lto-test-net</name><uuid>aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee</uuid><forward mode="'+mode+'"/><bridge name="virbr22"/></network>'); sys.exit(0)
if cmd=='net-info': print('Active: yes'); sys.exit(0)
if cmd=='list': print(uuid); sys.exit(0)
assert target==uuid, args
if cmd=='domstate': print('running')
elif cmd=='dumpxml':
    marker='' if case=='unmarked' else '<metadata><lto-disposable-test>true</lto-disposable-test></metadata>'
    disk='<disk type="file" device="disk"><driver name="qemu" type="qcow2"/><source file="'+str(p/'disk')+'"/><target dev="vda" bus="virtio"/></disk>'
    if case=='unsafe': disk+='<hostdev/>'
    if case=='empty-backing': disk=disk.replace('</disk>','<backingStore/></disk>')
    if case=='real-backing': disk=disk.replace('</disk>','<backingStore type="file"><source file="/tmp/backing.qcow2"/></backingStore></disk>')
    if case=='serial-device': disk+='<serial type="dev"><source path="/dev/ttyS0"/></serial>'
    if case in ('network','physical-network','live-network','wrong-bridge','extra-network-attribute','invalid-portid'):
        extra=' bridge="virbr22" portid="bbbbbbbb-cccc-dddd-eeee-ffffffffffff"' if case=='live-network' else ''
        if case=='wrong-bridge': extra=' bridge="br-production"'
        if case=='extra-network-attribute': extra=' dev="eth0"'
        if case=='invalid-portid': extra=' portid="not-a-uuid"'
        disk+='<interface type="network"><source network="lto-test-net"'+extra+'/><model type="virtio"/></interface>'
    override='<q:commandline xmlns:q="http://libvirt.org/schemas/domain/qemu/1.0"><q:arg value="-drive"/><q:arg value="file=/dev/sda,format=raw,if=virtio"/></q:commandline>' if case=='override' else ''
    print('<domain type="kvm"><uuid>'+uuid+'</uuid>'+marker+'<devices>'+disk+'</devices>'+override+'</domain>')
elif cmd=='snapshot-create-as':
    if case=='no-snapshot': sys.exit(2)
    (p/'snapshot').write_text(args[4]); print('created')
elif cmd=='snapshot-dumpxml':
    if not (p/'snapshot').exists(): sys.exit(2)
    identity='00000000-2222-3333-4444-555555555555' if case=='snapshot-mismatch' else uuid
    print('<domainsnapshot><name>'+args[4]+'</name><state>running</state><memory snapshot="internal"/><disks><disk name="vda" snapshot="internal"/></disks><domain><uuid>'+identity+'</uuid></domain></domainsnapshot>')
elif cmd=='snapshot-revert':
    (p/'restore-attempt').write_text('yes')
    if case=='failed-restore': sys.exit(2)
    (p/'restored').write_text('yes')
elif cmd=='qemu-agent-command':
    q=json.loads(args[4]); op=q['execute']; a=q.get('arguments',{})
    if op=='guest-exec':
        if case in ('diagnostic-stall','diagnostic-signal'):
            (p/'guestlog').write_text('RECOGNIZABLE-PARTIAL-INSTALL-DIAGNOSTIC\n')
            print(json.dumps({'return':{'pid':9}})); sys.exit(0)
        if (p/'snapshot').exists() and not (p/'restored').exists():
            (p/'mutation').write_text('attempted')
            if case=='interrupt': (p/'waiting').write_text('yes'); time.sleep(10)
            if case=='timeout': time.sleep(10)
            if case=='nonfresh': print(json.dumps({'error':{'desc':'fresh-host refused'}})); sys.exit(0)
            print(json.dumps({'error':{'desc':'fixture never admits signed inputs'}})); sys.exit(0)
        output='e'*64 if case=='changed' and (p/'restored').exists() else 'd'*64
        (p/'output').write_text(output+'\n'); print(json.dumps({'return':{'pid':7}}))
    elif op=='guest-exec-status':
        if case in ('diagnostic-stall','diagnostic-signal'):
            print(json.dumps({'return':{'exited':False} if not (p/'signal-sent').exists() else {'exited':True,'exitcode':0}}))
        else: print(json.dumps({'return':{'exited':True,'exitcode':0,'out-data':base64.b64encode((p/'output').read_bytes()).decode()}}))
    elif op=='guest-file-open':
        (p/'filemode').write_text(a['mode']); (p/'offset').write_text('0'); print(json.dumps({'return':3}))
    elif op=='guest-file-write':
        data=base64.b64decode(a['buf-b64']); (p/'uploaded').write_bytes((p/'uploaded').read_bytes()+data if (p/'uploaded').exists() else data)
        print(json.dumps({'return':{'count':len(data)}}))
    elif op=='guest-file-read':
        if case=='diagnostic-signal' and not (p/'signal-sent').exists():
            import signal
            (p/'signal-sent').write_text('yes'); os.kill(os.getppid(),signal.SIGTERM); time.sleep(.05)
        offset=int((p/'offset').read_text()); data=(p/'guestlog').read_bytes()[offset:offset+a.get('count',65536)]
        (p/'offset').write_text(str(offset+len(data)))
        print(json.dumps({'return':{'count':len(data),'eof':True,'buf-b64':base64.b64encode(data).decode()}}))
    elif op=='guest-file-seek':
        (p/'offset').write_text(str(a['offset'])); print(json.dumps({'return':{'position':a['offset']}}))
    elif op in ('guest-file-flush','guest-file-close'): print(json.dumps({'return':{}}))
    else: print(json.dumps({'error':{'desc':'fixture refuses transfer'}}))
else: sys.exit(2)
'''


class ControllerRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        (self.work / "disk").write_bytes(b"harmless qcow2 fixture")
        executable = self.work / "virsh"
        executable.write_text(VIRSH)
        executable.chmod(0o755)
        self.env = {**os.environ, "FIXTURE": str(self.work),
                    "PATH": str(self.work) + os.pathsep + os.environ["PATH"]}
        # Deliberately unsigned/non-approved. No positive report may emerge.
        (self.work / "approval.json").write_text("{}")
        self.command = [sys.executable, str(CONTROLLER), "--libvirt-uri", "qemu:///session",
            "--domain", "fixture", "--app-candidate", str(self.work),
            "--driver-candidate", str(self.work), "--report", str(self.work / "report.json"),
            "--app-tag-source", str(ROOT), "--driver-tag-source", str(self.work),
            "--approval", str(self.work / "approval.json"), "--approval-sha256", "a" * 64,
            "--app-verifier-sha256", "b" * 64, "--fresh-host-sha256", "c" * 64,
            "--report-verifier-sha256", "f" * 64, "--timeout-seconds", "0.3"]

    def execute(self, case):
        (self.work / "report.json").unlink(missing_ok=True)
        result = subprocess.run(self.command, env={**self.env, "CASE": case}, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue((self.work / "report.json").exists(), result.stderr)
        self.assertFalse(json.loads((self.work / "report.json").read_text())["qualified"])
        return result

    def test_missing_snapshot_refuses_before_guest_mutation(self):
        self.execute("no-snapshot")
        self.assertFalse((self.work / "mutation").exists())

    def test_unmarked_and_passthrough_domain_never_mutate(self):
        for case in ("unmarked", "unsafe"):
            self.execute(case)
            self.assertFalse((self.work / "mutation").exists())
            self.assertFalse((self.work / "snapshot").exists())

    def test_qemu_override_and_host_serial_refuse_before_snapshot(self):
        for case in ("override", "serial-device", "real-backing"):
            self.execute(case)
            self.assertFalse((self.work / "snapshot").exists())
            self.assertFalse((self.work / "mutation").exists())

    def test_empty_terminal_backing_sentinel_reaches_snapshot(self):
        self.execute("empty-backing")
        self.assertTrue((self.work / "snapshot").exists())
        self.assertTrue((self.work / "restored").exists())

    def test_explicit_pinned_managed_nat_network_gate(self):
        self.command += ["--test-network-name", "lto-test-net", "--test-network-uuid", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"]
        self.execute("network")
        self.assertTrue((self.work / "snapshot").exists())

    def test_unapproved_or_physical_network_never_snapshots(self):
        self.execute("network")
        self.assertFalse((self.work / "snapshot").exists())
        self.command += ["--test-network-name", "lto-test-net", "--test-network-uuid", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"]
        self.execute("physical-network")
        self.assertFalse((self.work / "snapshot").exists())

    def test_wrong_network_uuid_refuses(self):
        self.command += ["--test-network-name", "lto-test-net", "--test-network-uuid", "00000000-bbbb-cccc-dddd-eeeeeeeeeeee"]
        self.execute("network")
        self.assertFalse((self.work / "snapshot").exists())

    def test_managed_nat_live_bridge_portid_metadata_is_admitted(self):
        self.command += ["--test-network-name", "lto-test-net", "--test-network-uuid", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"]
        self.execute("live-network")
        self.assertTrue((self.work / "snapshot").exists())

    def test_changed_bridge_invalid_portid_and_extra_network_attributes_refuse(self):
        self.command += ["--test-network-name", "lto-test-net", "--test-network-uuid", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"]
        for case in ("wrong-bridge", "invalid-portid", "extra-network-attribute"):
            self.execute(case)
            self.assertFalse((self.work / "snapshot").exists())

    def test_snapshot_mismatch_refuses_mutation_and_failed_restore_unqualifies(self):
        self.execute("snapshot-mismatch")
        self.assertFalse((self.work / "mutation").exists())
        self.assertFalse((self.work / "restored").exists())
        (self.work / "snapshot").unlink()
        self.execute("failed-restore")
        self.assertTrue((self.work / "restore-attempt").exists())
        self.assertFalse(json.loads((self.work / "report.json").read_text())["checks"]["snapshot_restored"])

    def test_native_upload_and_stalled_main_transport_preserve_external_diagnostics(self):
        # Actual Controller staging/QGA process seam, no substituted verifier.
        # This unsigned fixture cannot generate a schema2 qualified report.
        script = '''
import argparse,runpy,sys
from pathlib import Path
api=runpy.run_path(sys.argv[1]); work=Path(sys.argv[2])
c=api['Controller'](argparse.Namespace(libvirt_uri='qemu:///session',timeout_seconds=.3),work/'evidence')
c.domain_uuid='11111111-2222-3333-4444-555555555555'
c.upload(work/'payload','/var/tmp/lto-fixture/payload')
try:
 c.execute('/usr/bin/bash',['/var/tmp/lto-fixture/smoke-public-fresh-rhel9.sh'],logs=['/var/tmp/lto-fixture/guest.stdout','/var/tmp/lto-fixture/guest.stderr'])
except Exception:
 (work/'unqualified').write_text('false')
finally:
 c.bound('snapshot-revert','lto-fixture','--running')
'''
        (self.work / "payload").write_bytes(b"harmless unsigned archive fixture")
        (self.work / "evidence").mkdir()
        result = subprocess.run([sys.executable, "-c", script, str(CONTROLLER), str(self.work)],
                                env={**self.env, "CASE": "diagnostic-stall"}, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.work / "uploaded").read_bytes(), b"harmless unsigned archive fixture")
        evidence = b"".join(path.read_bytes() for path in (self.work / "evidence").iterdir() if path.is_file())
        self.assertIn(b"RECOGNIZABLE-PARTIAL-INSTALL-DIAGNOSTIC", evidence)
        self.assertTrue((self.work / "restored").exists())
        self.assertEqual((self.work / "unqualified").read_text(), "false")

    def test_sigterm_during_periodic_log_read_aborts_and_restores(self):
        script = '''
import argparse,runpy,signal,sys
from pathlib import Path
api=runpy.run_path(sys.argv[1]); work=Path(sys.argv[2])
def interrupted(signum,frame): raise api.get('SmokeInterrupted',api['SmokeError'])('SIGTERM fixture')
signal.signal(signal.SIGTERM,interrupted)
c=api['Controller'](argparse.Namespace(libvirt_uri='qemu:///session',timeout_seconds=2),work/'evidence')
c.domain_uuid='11111111-2222-3333-4444-555555555555'
try:
 c.execute('/usr/bin/bash',['/var/tmp/lto-fixture/smoke-public-fresh-rhel9.sh'],logs=['/var/tmp/lto-fixture/guest.stdout','/var/tmp/lto-fixture/guest.stderr'])
except BaseException:
 (work/'qualified').write_text('false')
else:
 (work/'qualified').write_text('true')
finally:
 c.bound('snapshot-revert','lto-fixture','--running')
'''
        (self.work / "evidence").mkdir()
        result = subprocess.run([sys.executable, "-c", script, str(CONTROLLER), str(self.work)],
                                env={**self.env, "CASE": "diagnostic-signal"}, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.work / "qualified").read_text(), "false")
        self.assertTrue((self.work / "restored").exists())
        evidence = b"".join(path.read_bytes() for path in (self.work / "evidence").iterdir() if path.is_file())
        self.assertIn(b"RECOGNIZABLE-PARTIAL-INSTALL-DIAGNOSTIC", evidence)

    def test_unsigned_or_nonfresh_input_restores(self):
        self.execute("nonfresh")
        self.assertTrue((self.work / "restored").exists())

    def test_timeout_restores_bound_snapshot(self):
        self.execute("timeout")
        self.assertTrue((self.work / "restored").exists())
        calls = [json.loads(line) for line in (self.work / "calls").read_text().splitlines()]
        revert = next(i for i, call in enumerate(calls) if call[2] == "snapshot-revert")
        self.assertEqual(calls[revert-1][2], "snapshot-dumpxml")
        self.assertEqual(calls[revert-1][4], calls[revert][4])

    def test_changed_restored_state_never_qualifies(self):
        self.execute("changed")
        report = json.loads((self.work / "report.json").read_text())
        self.assertFalse(report["checks"]["snapshot_restored"])
        self.assertEqual(report["baseline_sha256"], "d" * 64)
        self.assertEqual(report["restored_sha256"], "e" * 64)

    def test_sigterm_restores_after_snapshot(self):
        process = subprocess.Popen(self.command, env={**self.env, "CASE": "interrupt"},
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 5
            while not (self.work / "snapshot").exists() and time.monotonic() < deadline:
                time.sleep(.01)
            self.assertTrue((self.work / "snapshot").exists())
            process.send_signal(signal.SIGTERM)
            process.communicate(timeout=5)
            self.assertTrue((self.work / "restored").exists())
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate()


class GuestObservationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("fresh_guest", GUEST)
        cls.guest = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.guest)

    def test_guest_command_timeout_retains_partial_diagnostic_bytes(self):
        import io
        output = io.StringIO()
        with contextlib.redirect_stderr(output):
            with self.assertRaises(subprocess.TimeoutExpired):
                self.guest.run([sys.executable, "-c", "import time;print('PARTIAL-GUEST-OUTPUT',flush=True);time.sleep(10)"], timeout=.1)
        self.assertIn("PARTIAL-GUEST-OUTPUT", output.getvalue())

    def test_nonfresh_actual_collector_refuses_before_install(self):
        # Real Task2 collector sees RPM inventory; no injectable admission flag.
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            executable = root / "rpm"
            executable.write_text('#!/bin/sh\nprintf "lto-ltfs 0.1.0-21.el9.x86_64\\n"\n')
            executable.chmod(0o755)
            ctl = root / "systemctl"
            ctl.write_text("#!/bin/sh\nexit 0\n")
            ctl.chmod(0o755)
            with patch.dict(os.environ, {"PATH": str(root)}):
                with self.assertRaises(self.guest.SmokeError):
                    self.guest.fresh_host(ROOT / "packaging/rpm/check-public-fresh-host.py")

    def test_login_http_failure_or_static_200_cannot_pass(self):
        for status in (401, 200):
            class Handler(http.server.BaseHTTPRequestHandler):
                def do_GET(self):
                    self.send_response(200)
                    self.send_header("Set-Cookie", "csrf=token")
                    self.end_headers()
                    self.wfile.write(b'<input name="login_csrf" value="token">')
                def do_POST(self):
                    self.send_response(status)
                    self.end_headers()
                def log_message(self, *args): pass
            with http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:
                    with self.assertRaises(self.guest.SmokeError):
                        self.guest.live_login(f"http://127.0.0.1:{server.server_port}", "unused", None)
                finally:
                    server.shutdown()

    def test_live_csrf_session_and_protected_account_positive_control(self):
        # Removing CSRF/session handling or protected-page read must fail.
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/login":
                    self.send_response(200)
                    self.send_header("Set-Cookie", "lto_archiver_csrf=token")
                    self.end_headers()
                    self.wfile.write(b'<input name="login_csrf" value="token">')
                elif self.path == "/account" and "lto_archiver_session=session" in self.headers.get("Cookie", ""):
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b'lto-smoke Current credential')
                else:
                    self.send_response(401)
                    self.end_headers()
            def do_POST(self):
                import urllib.parse
                fields = urllib.parse.parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode())
                if (fields != {"username": ["lto-smoke"], "password": ["ephemeral-fixture"],
                               "login_csrf": ["token"], "next": ["/account"]}
                        or "lto_archiver_csrf=token" not in self.headers.get("Cookie", "")):
                    self.send_response(401)
                else:
                    self.send_response(303)
                    self.send_header("Location", "/account")
                    self.send_header("Set-Cookie", "lto_archiver_session=session")
                self.end_headers()
            def log_message(self, *args): pass
        with http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                self.guest.live_login(f"http://127.0.0.1:{server.server_port}", "ephemeral-fixture", None)
            finally:
                server.shutdown()

    def test_complete_missing_hardware_observation_positive_control(self):
        # An always-refuse parser cannot satisfy this positive limited observation.
        names = ["platform.rhel9", "selinux.enforcing", "accounts.present", "devices.stable",
                 "ltfs.tools", "ltfs.provenance", "ltfs.fuse_boundary", "shares.helpers",
                 "shares.broker_boundary", "shares.permissions", "sources.readable",
                 "mount.empty_unmounted", "state.permissions", "windows.inactive"]
        value = {"schema": 1, "ok": False,
                 "checks": [{"name": name, "ok": name != "devices.stable"} for name in names]}
        with tempfile.TemporaryDirectory() as raw:
            executable = Path(raw) / "preflight"
            executable.write_text("#!/bin/sh\nprintf '%s\\n' '" + json.dumps(value) + "'\nexit 2\n")
            executable.chmod(0o755)
            self.guest.hardware_refusal([str(executable)])

    def test_unexpected_hardware_admission_and_unrelated_failure_refuse(self):
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "preflight"
            for status, body in ((0, '{"schema":1,"ok":true,"checks":[{"name":"devices.stable","ok":true}]}'),
                                 (2, '{"schema":1,"ok":false,"checks":[{"name":"config.valid","ok":false}]}')):
                path.write_text("#!/bin/sh\nprintf '%s\\n' '" + body + "'\nexit " + str(status) + "\n")
                path.chmod(0o755)
                with self.assertRaises(self.guest.SmokeError):
                    self.guest.hardware_refusal([str(path)])

    def test_leftover_owned_executable_or_active_unit_refuses(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            executable = root / "owned"
            executable.write_text("still here")
            executable.chmod(0o755)
            with self.assertRaises(self.guest.SmokeError):
                self.guest.no_owned_executables([str(executable)])
            ctl = root / "systemctl"
            ctl.write_text("#!/bin/sh\nprintf 'ActiveState=active\\n'\n")
            ctl.chmod(0o755)
            with patch.dict(os.environ, {"PATH": str(root)}):
                with self.assertRaises(self.guest.SmokeError):
                    self.guest.no_active_units(["lto-archiver-web.service"])


if __name__ == "__main__":
    unittest.main()
