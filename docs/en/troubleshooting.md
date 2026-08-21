# Troubleshooting

Use each symptom's three-part boundary. “Forbidden” includes starting a second
job, a mutating CLI command, Explorer on a mounted tape, direct `TAPE0` probing,
stopping `FUSE4WinSvc`, ejecting media, or reusing a drive letter unless that
section explicitly says safe release has occurred. Redact all evidence.

## Safe copy for catalog diagnostics

Before `doctor` or `catalog check`, ensure there is no active job and close all
LTO Archiver GUI/CLI instances. Preserve the untouched original state directory;
create a disposable copy of the *entire* directory, then point the global
`--state-dir` at that copy. Never run the diagnostic against the preserved
original.

```powershell
$stateDirectory = 'C:\ProgramData\LtoBackupManager'
$diagnosticRoot = Join-Path $env:TEMP ("LtoArchiver-DiagnosticCopy-" + [guid]::NewGuid())
$diagnosticStateDirectory = Join-Path $diagnosticRoot 'LtoBackupManager'
if (Get-Process -Name 'LtoBackupManager','LtoBackupManagerCli' -ErrorAction SilentlyContinue) {
  throw 'Close all LTO Archiver instances before copying state.'
}
New-Item -ItemType Directory -Path $diagnosticRoot -ErrorAction Stop | Out-Null
Copy-Item -LiteralPath $stateDirectory -Destination $diagnosticRoot -Recurse -ErrorAction Stop
& 'C:\Program Files\LtoBackupManager\LtoBackupManagerCli.exe' `
  --state-dir $diagnosticStateDirectory catalog check
```

Use the same copied `--state-dir $diagnosticStateDirectory` for `doctor`; do not
open a diagnostic copy concurrently with a live application. The original is
preserved for evidence/recovery even if the diagnostic copy upgrades settings,
creates logs, or migrates the catalog. The unique directory is new on every run;
if directory creation or recursive copy fails, `-ErrorAction Stop` prevents the
diagnostic command from proceeding.

## Job saved but not started

**Safe observation:** confirm saved state, selected library, and explicit start
request. **Forbidden concurrent actions:** do not start a duplicate job or treat
saved as running. **Escalation:** provide redacted state and timestamp to admin.

## Conflicting job or `run.lock`

**Safe observation:** identify current owner and its safe boundary. **Forbidden
concurrent actions:** do not kill owner, take its lock, or create another writer.
**Escalation:** preserve lock/log timing for administrator review after release.

## Mount delay

**Safe observation:** watch heartbeat, LTFS letter and `ltfs.exe`/
`FUSE4WinSvc` events; mount can take minutes. **Forbidden concurrent actions:**
do not reuse letter, probe device, or launch another job. **Escalation:** after
safe release, supply sanitized StoreOpen/FUSE events to HPE support.

## Stalled `CopyFileEx` close

**Safe observation:** during `write.pending`/`close.pending`, watch elapsed
heartbeat; completion is only `close.complete`. **Forbidden concurrent actions:**
do not force close, use Explorer, or query the device. **Escalation:** after
release collect logs and an HPE L&TT support ticket.

## No cache samples

**Safe observation:** absent cache trace means no confirmed sample, not zero
speed; compare sample age and effective average. **Forbidden concurrent actions:**
do not invent bytes or restart the job. **Escalation:** retain log/heartbeat
timeline and ask the operator to review StoreOpen telemetry after safe release.

## Long unmount

**Safe observation:** observe `unmount.progress`, index sync, letter release,
and ejection; unmount has no application timeout. **Forbidden concurrent actions:**
do not power off, stop FUSE, remove media, or claim committed. **Escalation:**
after release provide finalization logs and HPE L&TT evidence.

## Residual drive letter

**Safe observation:** verify StoreOpen closed and no LTFS volume remains.
**Forbidden concurrent actions:** do not delete an unfamiliar mapping or reuse
the letter. **Escalation:** preserve logs and use supported cleanup only after
the mapping owner is identified.

## Defender or Controlled Folder Access

**Safe observation:** inspect Defender history and exact executable path.
**Forbidden concurrent actions:** do not disable Defender or make broad
exclusions. **Escalation:** request only installed GUI/CLI allow-list paths via
GPO/Intune, with the blocked-event evidence.

## Wrong tape

**Safe observation:** compare the registered LTFS volume label with `doctor
--tape ... --mount ...`; the Win32 serial is diagnostic and may be shared by
different cartridges. Remember this command can upgrade settings, create logs,
and initialize/migrate catalog, so preserve suspect state first. **Forbidden
concurrent actions:** never write “to test” or bypass identity. **Escalation:**
give the label mismatch and sanitized logs to the tape operator.

## Full tape

**Safe observation:** retain the capacity error and planned/remaining values.
**Forbidden concurrent actions:** do not delete LTFS files or catalog rows to
create space. **Escalation:** plan a new cassette and send capacity evidence to
the operator.

## TapeAlert

**Safe observation:** record TapeAlert and safe event logs. **Forbidden
concurrent actions:** do not run a destructive assessment on data media.
**Escalation:** after release attach the reading to an HPE L&TT support ticket.

## Clean LED

**Safe observation:** inspect physical LED and vendor guidance. **Forbidden
concurrent actions:** do not use swabs or preventative cleaning. **Escalation:**
clean only for flashing LED or `Clean Now`, `Clean Periodic`, `Clean requested`,
using HPE Ultrium universal `C7978A`; persistent request after known-good media
requires drive service.

## Catalog integrity

**Safe observation:** first preserve a copy of suspect state; then, only if
acceptable, use `catalog check`/`doctor`, which are not forensic read-only and
can upgrade settings, create logs, initialize/migrate catalog. **Forbidden
concurrent actions:** do not edit SQLite or open another writer. **Escalation:**
give integrity/foreign-key output and verified backup to an administrator.

## Interrupted job

**Safe observation:** establish whether interruption was before/during provider
flush or unmount. **Forbidden concurrent actions:** do not force eject, delete
checkpoints, or call provisional block complete. **Escalation:** supported
automatic reset restarts/reformats from zero; preserve state and escalate
finalization failure after media release.

## Release verification

**Safe observation:** compare SHA-256, `--version`, `catalog check`, executable
presence, and ZIP contents; preserve state before `catalog check` because it can
mutate diagnostic evidence. **Forbidden concurrent actions:** do not distribute,
overwrite an install, or publish logs/catalog/identifiers on failure.
**Escalation:** report failed check and sanitized artifact metadata for deliberate
release recovery.

References: [HPE indicators](https://support.hpe.com/hpesc/public/docDisplay?docId=c05170118&docLocale=en_US), [HPE L&TT ticket](https://support.hpe.com/hpesc/public/docDisplay?docId=sd00003778en_us&page=GUID-D7147C7F-2016-0901-04BD-000000000A28.html), [Microsoft CFA](https://learn.microsoft.com/windows/security/operating-system-security/virus-and-threat-protection/microsoft-defender-antivirus/controlled-folders).
