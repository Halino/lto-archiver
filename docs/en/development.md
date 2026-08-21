# Development

Develop on Windows Server 2022 x64 with Python 3.11; hardware is not needed
for tests and production drives are never development fixtures.

```powershell
py -3.11 -m venv .build-venv
& .\.build-venv\Scripts\Activate.ps1
& .\.build-venv\Scripts\python.exe -m pip install --upgrade pip
& .\.build-venv\Scripts\python.exe -m pip install -r requirements-build.txt
$env:PYTHONPATH = 'src'
& .\.build-venv\Scripts\python.exe -m unittest discover -s tests -v
& .\.build-venv\Scripts\python.exe -m unittest tests.test_docs tests.test_cli tests.test_entry -v
```

`requirements-build.txt` pins PyInstaller. A focused check uses the same
runtime, for example `-m unittest tests.test_cli.CliTests -v`. Build GUI and
CLI with:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-release.ps1 -Version 0.11.27
```

Version seams are `src/ltobackup/__init__.py`, `pyproject.toml`, and both
`packaging/version_info*.txt` files. Before a public snapshot, check LICENSE,
NOTICE, THIRD_PARTY_NOTICES, package metadata, README version/license claims.

## 0.11.27 repository release tools

Apply this entire command block **only in the final 0.11.27 public tree after
Tasks 7–9** have added the tool files. In the **current intermediate checkout**
they are unavailable: do not run them. They are repository tools, never
application/production commands.

```powershell
& .\scripts\build-release.ps1 -Version 0.11.27
& .\scripts\verify-release.ps1 -Version 0.11.27 -ReleaseDirectory .\release

& .\.build-venv\Scripts\python.exe scripts\build-public-snapshot.py `
  --root . --manifest public-files.txt --target C:\Temp\lto-archiver-public
& .\.build-venv\Scripts\python.exe scripts\audit-public-content.py `
  --manifest public-files.txt --root .
& .\.build-venv\Scripts\python.exe scripts\audit-public-content.py `
  C:\Temp\lto-archiver-public
& .\.build-venv\Scripts\python.exe scripts\audit-public-content.py `
  'release\LTO-Archiver-0.11.27.zip'
& .\.build-venv\Scripts\python.exe scripts\audit-public-content.py `
  --manifest public-files.txt --root . --git-history
```

`verify-release.ps1` accepts mandatory `-Version` and optional
`-ReleaseDirectory`, verifies ZIP/checksum, extracts only to its own temporary
directory, checks required files/versions/per-binary hashes, rejects forbidden
state and unexpected executables, then removes that temporary directory.
The snapshot builder uses sorted normalized `public-files.txt`, refuses unsafe
paths/targets, copies allow-listed files only, and writes no Git metadata. The
auditor accepts a directory or ZIP plus `--git-history`, reports redacted
findings, and exits 0 only with no finding; any finding exits nonzero and blocks
publication. In the final public tree, success is `exit 0` for build, verifier,
snapshot, and each audit command; any documented failure is nonzero.

GitHub Actions introduced by Task 9 use `actions/checkout@v4`,
`actions/setup-python@v5`, `windows-latest`, Python 3.11, `pip check`, full
unittest, and audit on `main` pushes/pull requests with `contents: read`.
Tag `v*.*.*` release automation verifies the exact version, builds, verifies,
audits, then uses `gh release create` with only `contents: write`; `GH_TOKEN`
is scoped to that release step.

Test behavior first, record RED, use synthetic fixtures, then run focused/full
checks. Never commit ZIPs, builds, state, logs, catalogs, secrets, or captures.
