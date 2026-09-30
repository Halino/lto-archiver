# Development

Use Python 3.11 for hardware-free repository tests. A production drive or
catalog is never a development fixture.

```bash
python3.11 -m venv .build-venv
.build-venv/bin/python -m pip install '.[test]'
PYTHONPATH=src .build-venv/bin/python -m unittest discover -s tests
```

The Linux release wrapper tests an export of the **committed** checkout,
including WebUI tests. Commit the intended source before relying on this gate;
uncommitted edits are not export evidence.

```bash
/bin/bash packaging/scripts/test-linux-release.sh /absolute/python3.11
```

Replace `/absolute/python3.11` with the absolute path of the prepared Python
3.11 interpreter. This wrapper does not sign, publish, deploy, or qualify
physical media. The release gate also includes RPM `%check`, packaging,
signature and source-content checks, then disposable-host acceptance. See the
[release process](release-process.md).

Installed Python launchers must resolve the application from the installed
package rather than an untrusted shadow on a dependency path. Activation
checks the effective import and the catalog compatibility boundary. The
current application source targets schema 41; never change a production
catalog as part of a development test.

Tests must not invoke the command broker, LTFS, FUSE, SCSI, a real drive,
load/unload/eject, format, write, finalization, tape readback, or native
start/resume. Fake-host qualification is not physical qualification.

The content auditor can inspect a release directory or ZIP:

```bash
python3.11 -I scripts/audit-release-content.py /path/to/sealed-release
```

Any finding or malformed archive exits nonzero. Never commit build output,
state, logs, catalogs, credentials, private paths, host identities, or captured
hardware evidence. The public source snapshot also passes its explicit
allowlist and one-root-history audit before publication.

The Linux application RPM entry point is
`packaging/rpm/release-rhel9-rpm.sh`. It requires a clean committed tree,
Python 3.11, an isolated signing home, and exact key fingerprints. Do not
invoke it to publish directly. Driver development and release belong to the
separate driver project and require independent provenance and license gates.
