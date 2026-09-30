# RHEL 9 installation and activation

The current source contract is application **0.11.29-155**, Python runtime
**3**, external LTFS driver **22**, and catalog **schema 41**. A source
snapshot does not prove that a public RPM is signed or installed on a host.
Verify the exact package versions, signatures and dependency tuple before
provisioning. The runtime and driver are separate packages; this repository
does not rebuild or embed the driver.

**Public-release preparation, not an install authorization:** the current
155/3/22 route is a **fresh, restorable disposable RHEL 9 VM only**. No upgrade,
catalog migration, backup/restore or physical-tape claim follows from this
guide. The historical source scripts `deploy-rhel9.py`, `rollback-rhel9.py`
and `verify-deployment-rhel9.py` encode the 0.11.27-144/driver 21 transition;
they are not a supported 0.11.29-155/driver 22 upgrade path and are excluded
from the current binary package. Do not execute them for release 155.

Before a first package operation, capture a restorable VM snapshot and run
`check-public-fresh-host.py --json`; it must report no existing LTO packages,
data, credentials or managed unit. Verify the separately approved driver,
runtime and application RPMs with the exact signed-input gate, including
their SHA-256, GPG signatures, tag-bound attestations, source RPMs and exact
dependency tuple. Install in driver, runtime, application order. The steps
below describe provisioning only **after** those gates pass on the disposable
VM. They are not a production-host or active-backup procedure. Never replace
a live SQLite file or bypass a failed integrity or signature gate.
The [disposable-VM smoke evidence contract](public-fresh-install-smoke.md)
describes the additional live login, expected hardware-absence refusal and restoration proof required
before a public release; no such VM qualification is claimed here.
Do not follow the hardware-provisioning steps below in that no-tape VM:
missing tape/SCSI devices must remain a refused hardware preflight. The smoke
does not qualify daemon-mediated import, physical LTFS or backup/restore.

GitHub Releases, once published, provide direct RPM/SRPM/source downloads,
not a configured DNF repository. Their public verification key and checksum
signature must be checked before installation. Hardware-free package tests
do not replace a disposable-host smoke test or physical tape qualification.
Use the [GitHub-built RPM verification guide](../en/github-rpm-verification.md)
to check the exact downloaded bytes, full GPG fingerprints, signed checksum
manifest and tag-bound GitHub attestations before any install.

Installing the RPM creates service accounts, runtime directories, credentials,
systemd units, the direct-TLS WebUI boundary, and the SELinux policy. It
deliberately does not create device allow-list drop-ins, provide TLS key
material, open the firewall, or start units while packaged configuration
markers remain.

Provision the host before activation:

1. Install the supported LTFS/FUSE2 packages and confirm `/usr/bin/ltfs`,
   `/usr/bin/ltfs-info`, and `/usr/bin/fusermount` are present.
2. Replace both `configure-*` device paths in
   `/etc/lto-archiver/config.toml` with the stable tape and SCSI symlinks for
   this drive. The generic-SCSI value must be the direct udev alias
   `/dev/lto-archiver-scsi-$ID_SERIAL`; the legacy nested
   `/dev/lto-archiver/by-id/...` namespace is rejected. Configure the source,
   restore, and mount paths for this host.
   SMB/NFS shares are broker-managed read-only backup sources and are not
   restore destinations. The packaged exclusive daemon-owned restore namespace is
   `/mnt/lto-archiver/restores`, created as `0750 lto-archiver:lto-archiver`;
   configure restore roots at or beneath that namespace. It may be the mount
   point of a filesystem already mounted by an administrator, but its
   snapshotted anchor, root, and traversed directories must be daemon-owned,
   not group/other writable, descriptor-relative and symlink-safe, and
   protected by the full-lifetime nonblocking exclusive root lease.
3. Start both broker sockets, then run the authenticated, read-only RHEL
   preflight with all three required credentials and resolve every failure:

   ```console
   sudo systemctl start lto-archiver-command-broker.socket \
     lto-archiver-share-broker.socket
   sudo systemd-run --unit=lto-archiver-preflight.service --pipe --wait --collect --uid=lto-archiver \
     --property=LoadCredential=broker-capability:/etc/lto-archiver/credentials/broker-capability \
     --property=LoadCredential=share-broker-capability:/etc/lto-archiver/credentials/share-broker-capability \
     --property=LoadCredential=share-broker-proof-key:/etc/lto-archiver/credentials/share-broker-proof-key \
     /usr/libexec/lto-archiver/preflight-rhel9.sh \
       --config /etc/lto-archiver/config.toml --json \
       --broker-socket /run/lto-archiver-broker/control.sock \
       --broker-capability-file /run/credentials/lto-archiver-preflight.service/broker-capability \
       --share-broker-socket /run/lto-archiver-share-broker/control.sock \
       --share-broker-capability-file /run/credentials/lto-archiver-preflight.service/share-broker-capability \
       --share-broker-proof-key-file /run/credentials/lto-archiver-preflight.service/share-broker-proof-key
   ```

   Admission remains closed until the JSON report has `ok: true`, including
   `ltfs.fuse_boundary: true` and the share-broker readiness checks. Those
   checks are produced only after exact broker peers accept the three
   systemd-delivered credentials and return fresh, authenticated readiness
   proofs. Missing, stale, or tampered credentials, sockets, peer identity,
   tool pins, or reconciliation state all produce the same redacted boolean
   failure. The transient unit's three paths under
   `/run/credentials/lto-archiver-preflight.service/` are mandatory; never use
   the daemon service's credential directory for this command.
4. Install the WebUI certificate and key without following symlinks. The TLS
   directory must be `0750 root:lto-web`, the certificate `0644 root:root`, and
   the private key `0640 root:lto-web`. Edit the packaged, preserved
   `/etc/lto-archiver/web.toml` in place, keep it `0640 root:lto-web`, and
   replace the empty `listen_host` marker with the host's single LAN IPv4 address. Keep the
   port at 8443, the active firewalld zone, the paths under
   `/etc/lto-archiver/tls`, and the exact source tuple `10.0.0.0/8`,
   `172.16.0.0/12`, `192.168.0.0/16`.

5. Confirm all nine newly installed managed units remain inactive. If any
   service or socket is already active, stop this fresh-install qualification;
   do not stop or reset it to make the preflight appear clean.

6. Activate the provisioned configuration as root:

   ```console
   sudo /usr/libexec/lto-archiver/activate-rhel9.py
   ```

The activation command first requires every managed service and socket to be
loaded, inactive, and dead. It does not quiesce a running installation. It
validates the configured devices, the closed Web configuration, listener-zone
mapping, and existing firewall state; publishes the exact device policy;
restores the narrow Web config/TLS/runner labels; reloads systemd; and verifies
the policy again. It then enables and starts the command-broker, share-broker,
log-reader, and daemon sockets plus `lto-archiver-web.service`. The log reader
uses socket activation: its reader socket is `root:lto-log-read` mode `0660`,
and only the daemon belongs to `lto-log-read`. Last, it atomically adds
only the three permanent and runtime source-scoped rich rules for TCP 8443.
There is no broad port/service opening and no reverse proxy. A partial firewall
failure removes only rules added by that attempt; any activation failure stops
newly started units and restores their prior enablement state.

The application import gate accepts schema 41 exactly. After activation, the
live verifier requires an integrity- and foreign-key-clean schema-41 catalog,
including the terminal command exit-code and immutable qualification
readback-release-receipt structures. A schema-39 installed application is a
failed activation, while rollback restores and revalidates the bound
schema-41 predecessor source rather than relying on a package-only downgrade.

Both hardware-owning services also run device-policy verification at their
`ExecStartPre` boundary. The daemon then runs
the authenticated preflight as a second `ExecStartPre`, in `lto_archiver_t`
with the same `LoadCredential`, broker socket, and configuration as its main
process. The daemon repeats `assert_ready` during startup, so both the start
boundary and the runtime boundary fail closed if broker state changes.

Do not edit the generated `20-lto-device-policy.conf` files by hand.

After activation, verify the HTTPS and firewall boundary without sending any
media command:

```console
curl --fail --cacert /path/to/operator-ca.pem https://192.0.2.26:8443/login
sudo /usr/libexec/lto-archiver/configure-web-firewall-rhel9.py --verify-only
sudo systemctl --no-pager --full status lto-archiver-web.service lto-archiverd.socket lto-archiver-command-broker.socket lto-archiver-share-broker.socket lto-archiver-log-reader.socket lto-archiver-log-reader.service
```

The confined Web service performs read-only NSS, systemd-userdb, and generic
certificate-store lookups during Python and TLS startup. The SELinux policy provides
only the corresponding RHEL reference-policy client permissions; it does not
grant account, password, userdb, certificate, or private-key management.

The deployment verifier's maintenance-window journal gate includes priority
0-through-3 events from all nine managed service/socket units plus
`setroubleshootd.service`. This deployment query is deliberately broader than
the log reader's six allowlisted source units. A setroubleshoot report of an
SELinux denial therefore fails the gate unconditionally; the exact unit,
message-ID, and priority allowlist is limited to application-unit events.
Resolve the underlying AVC or labeling problem and rerun the full verifier; do
not filter the service or advance the maintenance-window timestamp to hide the
event.

Historical private upgrades migrated a pre-existing custom WebUI unit only
through their deployment runner after a verified rollback bundle. That route
is **not** supported by public 155. Do not run a historical runner or replace
an existing Web unit, config, TLS material, firewall policy or catalog by hand.
