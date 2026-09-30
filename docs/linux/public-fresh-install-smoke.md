# Disposable RHEL 9 first-install smoke evidence

Release 155/driver 22 remains **unqualified** until an actual, restorable,
disposable RHEL 9 VM has run the signed driver/runtime/application installation
and the limited WebUI/hardware-absent smoke. A local package test, a synthetic JSON report,
or a successful `rpm -V` alone is not runtime evidence. Do not use a production
host, existing catalog, real tape or active backup for this test.

Use the [disposable-VM controller instructions](public-fresh-vm-runner.md)
for the supported guest profile, pinned inputs and retained restoration
evidence. Local runner tests do not constitute a real installation result.

The VM controller must first verify the explicit
`lto-disposable-test=true` domain marker, capture a restorable snapshot and
the initial host-state digest, and run the read-only fresh-host preflight.
Before installing, it must verify the exact separately approved signed and
attested driver 22, runtime 3 and application 155 RPMs, their source/tag
identities and dependency tuple. Install in that order. Confirm package files,
`rpm -V`, unit syntax, service accounts and SELinux. With test-only TLS and
credentials, record a genuine WebUI login and the real hardware preflight's
expected refusal for absent tape/SCSI devices. Do not emulate a drive, start a
tape operation or label daemon-mediated import as tested. A failed login or
unexpectedly successful hardware admission is a failed smoke; static checks
cannot replace these observations. Record uninstall residue without deleting generated state, prove
no installed package-owned executable or active managed unit remains, restore
the VM snapshot, then compare the restored host-state digest to the initial
digest. Keep the raw VM evidence outside the guest for independent review.

The sanitized report is a UTF-8 JSON object no larger than 16 KiB, with exactly
these fields:

| Field | Value |
| --- | --- |
| `schema_version`, `profile`, `qualified` | `2`, `fresh-rhel9-webui-hardware-absent`, `true` only after every required check |
| `unverified_features` | Exactly `["backup_restore", "daemon_import", "physical_ltfs"]`; qualification applies only to this limited profile |
| `app_commit`, `driver_commit` | Reviewed 40-character lowercase source commits |
| `rpm_sha256` | Exactly the SHA-256 of `lto-ltfs-0.1.1-22.el9.x86_64.rpm`, `lto-archiver-python-runtime-0.11.27-3.el9.x86_64.rpm`, and `lto-archiver-0.11.29-155.el9.noarch.rpm` |
| `baseline_sha256`, `restored_sha256` | Equal digests of the controller's defined host-state baseline |
| `uninstall_generated_state_count` | Nonnegative count; generated state is observed, not silently erased |
| `checks` | Exactly the Boolean checks below; all must be `true` |

The required `checks` keys are `disposable_marker`, `snapshot_created`,
`fresh_host`, `signed_tuple`, `install_order`, `installed_nevras`, `rpm_verify`,
`unit_syntax`, `service_accounts`, `selinux`, `live_web_login`,
`hardware_absence_refused`, `uninstall_residue_recorded`,
`uninstall_no_owned_executables`, `uninstall_no_active_units`, and
`snapshot_restored`. Do not place hostnames, private paths, credentials,
catalog entries, tape identifiers or raw command output in this report.

The publication workflow requires the exact report SHA-256 as a dispatch
input, a matching approved Environment variable
`PUBLIC_RPM_APPROVED_SMOKE_REPORT_SHA256`, and the base64-encoded *same
sanitized report bytes* in `PUBLIC_RPM_APPROVED_SMOKE_REPORT_BASE64`. It decodes
and validates those bytes against the reviewed source and actual signed
application/runtime candidate before creating a draft. A report hash alone is
insufficient. The validator cannot prove that the VM ran; the Environment
reviewer must inspect the independently retained VM transcript and snapshot
restoration proof before approving those variables. If that evidence is
missing, the public Release remains blocked.

This smoke does not qualify a private 144/21 upgrade, catalog migration,
daemon-mediated import, physical LTFS operation, backup/restore, or automatic
Resume. Schema-1 reports from the former profile cannot authorize this release.
