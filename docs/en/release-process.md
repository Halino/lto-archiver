# Release process

This is repository work, never a production-server procedure. The 0.11.26 tag
is `v0.11.26`; title is `LTO Archiver 0.11.26`.

1. On an idle build workstation align version seams, run the full unittest
   command in [development](development.md), then check legal files/notices.
2. The final Task 7 builder tests unless skipped, builds GUI/CLI, optionally
   signs only when both signing parameters exist, and writes
   `release/LTO-Archiver-0.11.26.zip` plus
   `release/LTO-Archiver-0.11.26.zip.sha256`. A checksum does not mean signed.
3. Verify executable presence/version, installer/CFA tool, docs/license/notice,
   ZIP hash, and absence of state, logs, databases, secrets, private paths, or
   HPE software. Verifier mismatch, forbidden content, or unexpected executable
   is nonzero and blocks publication; never publish an uncertain artifact.
4. **Precondition:** apply this entire command block only in the **final 0.11.26
   public tree after Tasks 7–9** have added their tool/workflow files. In the
   **current intermediate checkout**, do not run it. These are repository tools,
   never application/production commands. On Windows every successful command
   below returns `exit 0`; a verifier/auditor failure returns nonzero and blocks
   publication:

   ```powershell
   & '.\scripts\build-release.ps1' -Version 0.11.26
   & .\scripts\verify-release.ps1 -Version 0.11.26 -ReleaseDirectory .\release
   & .\.build-venv\Scripts\python.exe scripts\build-public-snapshot.py `
     --root . --manifest public-files.txt --target C:\Temp\lto-archiver-public
   & .\.build-venv\Scripts\python.exe scripts\audit-public-content.py `
     --manifest public-files.txt --root .
   & .\.build-venv\Scripts\python.exe scripts\audit-public-content.py `
     'release\LTO-Archiver-0.11.26.zip'
   & .\.build-venv\Scripts\python.exe scripts\audit-public-content.py `
     --manifest public-files.txt --root . --git-history
   ```

   The verifier checks archive checksum, temporary extraction, exact files,
   executable versions, per-binary hashes, and forbidden content. The snapshot
   builder consumes sorted normalized `public-files.txt`, rejects unsafe paths,
   copies allow-listed files only, and writes no Git metadata. The auditor scans
   directory/ZIP/history, redacts values in findings, and exits 0 only clean;
   every finding exits nonzero and blocks publication.
5. Create tag only after checks. Task 9 CI runs `actions/checkout@v4` and
   `actions/setup-python@v5` on `windows-latest` with Python 3.11, `pip check`,
   full unittest and audit for `main` push/PR under `contents: read`. The
   `v*.*.*` workflow validates tag/version, builds, verifies, audits, and runs
   `gh release create` under only `contents: write`, with `GH_TOKEN` only on
   that release step. The release job runs this exact interface:

   ```powershell
   gh release create $env:GITHUB_REF_NAME `
     "release/LTO-Archiver-$version.zip" `
     "release/LTO-Archiver-$version.zip.sha256" `
     --title "LTO Archiver $version" `
     --notes-file "docs/release-notes-$version.md" `
     --verify-tag
   ```

   If a YAML parser is available locally, parse both workflows. Otherwise local
   YAML syntax is not confirmed: rely on GitHub's workflow parser after the first
   push and do not claim local syntax validation. Verify uncertain remote state
   read-only before retry.

Rollback ends at release boundary: do not overwrite live install, alter private
GitLab history/remote, delete partial public repo, or operate production server.
Failed build, verifier/audit finding, CI, or tag/version mismatch creates no
approved release. Do not overwrite a live install, delete a partial public
repository, or retry publication blindly; report exact state for deliberate repair.
