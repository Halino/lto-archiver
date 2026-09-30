%global python3_pkgversion 3.11
%global use_source_date_epoch_as_buildtime 1
%global clamp_mtime_to_source_date_epoch 1
%global __brp_python_bytecompile %{nil}
%global __pythondist_provides %{nil}
%global __pythondist_requires %{nil}

Name:           lto-archiver
Version:        0.11.28
Release:        155%{?dist}
Summary:        Native RHEL service for append-only LTFS archives
License:        Apache-2.0
URL:            https://github.com/Halino/lto-archiver
Source0:        %{name}-%{version}.tar.gz

BuildArch:      noarch
BuildRequires:  python%{python3_pkgversion}-devel
BuildRequires:  python%{python3_pkgversion}-packaging
BuildRequires:  python%{python3_pkgversion}-pip
BuildRequires:  python%{python3_pkgversion}-rpm-macros
BuildRequires:  python%{python3_pkgversion}-setuptools >= 65.5.1
BuildRequires:  python%{python3_pkgversion}-wheel
BuildRequires:  git-core
BuildRequires:  pyproject-rpm-macros
BuildRequires:  systemd-rpm-macros
BuildRequires:  selinux-policy-devel
BuildRequires:  lto-archiver-python-runtime = 0.11.27-3%{?dist}
BuildRequires:  /bin/sh
BuildRequires:  /usr/bin/cmp
BuildRequires:  /usr/bin/chmod
BuildRequires:  /usr/bin/cpio
BuildRequires:  /usr/bin/env
BuildRequires:  /usr/bin/find
BuildRequires:  /usr/bin/git
BuildRequires:  /usr/bin/gpg
BuildRequires:  /usr/bin/install
BuildRequires:  /usr/bin/mkdir
BuildRequires:  /usr/bin/mktemp
BuildRequires:  /usr/bin/python3.11
BuildRequires:  /usr/bin/rm
BuildRequires:  /usr/bin/rpm
BuildRequires:  /usr/bin/rpm2cpio
BuildRequires:  /usr/bin/rpmbuild
BuildRequires:  /usr/bin/rpmkeys
BuildRequires:  /usr/bin/rpmsign
BuildRequires:  /usr/bin/sed
BuildRequires:  /usr/bin/semodule_unpackage
BuildRequires:  /usr/bin/sha256sum
BuildRequires:  /usr/bin/sort
BuildRequires:  /usr/sbin/matchpathcon
BuildRequires:  /usr/sbin/restorecon
Requires:       python3.11
Requires:       lto-archiver-python-runtime = 0.11.27-3%{?dist}
Requires:       lto-ltfs = 0.1.0-22%{?dist}
Requires:       /usr/bin/cpio
Requires:       /usr/bin/dnf-3
Requires:       /usr/bin/firewall-cmd
Requires:       /usr/bin/findmnt
Requires:       /usr/bin/git
Requires:       /usr/bin/gpg
Requires:       /usr/bin/journalctl
Requires:       /usr/bin/ltfs-info
Requires:       /usr/bin/openssl
Requires:       /usr/bin/python3.11
Requires:       /usr/bin/rpm
Requires:       /usr/bin/rpm2cpio
Requires:       /usr/bin/rpmkeys
Requires:       /usr/bin/sha256sum
Requires:       /usr/bin/systemctl
Requires:       /usr/sbin/matchpathcon
Requires:       /usr/sbin/restorecon
Requires:       mt-st
Requires:       sg3_utils
Requires:       /usr/bin/fusermount
Requires:       /usr/bin/mt
Requires:       nfs-utils
Requires:       cifs-utils
Requires:       systemd-libs
Requires:       policycoreutils
Requires(pre):  systemd
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd

%description
LTO Archiver provides the non-root native daemon, migration command, WebUI,
and authenticated root command broker. Hardware-facing LTFS tools remain a
separate auditable dependency.

%generate_buildrequires
%pyproject_buildrequires -R

%prep
%autosetup -p1

%build
%pyproject_wheel
install -d selinux-build
install -pm0644 packaging/selinux/lto_archiver.te selinux-build/lto_archiver.te
install -pm0644 packaging/selinux/lto_archiver.if selinux-build/lto_archiver.if
install -pm0644 packaging/selinux/lto_archiver.fc selinux-build/lto_archiver.fc
%make_build -C selinux-build -f %{_datadir}/selinux/devel/Makefile lto_archiver.pp

%install
%pyproject_install
%{python3} -m compileall -q -f --invalidation-mode checked-hash \
    -s %{buildroot} -p / %{buildroot}%{python3_sitelib}/ltobackup
%pyproject_save_files ltobackup
install -Dpm0755 packaging/launchers/lto-archiver-command-broker %{buildroot}%{_bindir}/lto-archiver-command-broker
install -Dpm0755 packaging/launchers/lto-archiver-share-broker %{buildroot}%{_bindir}/lto-archiver-share-broker
install -Dpm0755 packaging/launchers/lto-archiver-log-reader %{buildroot}%{_bindir}/lto-archiver-log-reader
install -Dpm0755 packaging/launchers/lto-archiver-admin %{buildroot}%{_bindir}/lto-archiver-admin
install -Dpm0755 packaging/launchers/lto-archiverd %{buildroot}%{_bindir}/lto-archiverd
install -Dpm0755 packaging/launchers/lto-archiver-migrate %{buildroot}%{_bindir}/lto-archiver-migrate
install -Dpm0755 packaging/launchers/lto-archiver-qualify-ltfs %{buildroot}%{_bindir}/lto-archiver-qualify-ltfs
install -Dpm0755 packaging/launchers/lto-archiver-qualify-archive-runner %{buildroot}%{_bindir}/lto-archiver-qualify-archive-runner
install -Dpm0755 packaging/launchers/lto-archiver-web %{buildroot}%{_bindir}/lto-archiver-web
install -Dpm0644 packaging/systemd/lto-archiverd.service %{buildroot}%{_unitdir}/lto-archiverd.service
install -Dpm0644 packaging/systemd/lto-archiverd.socket %{buildroot}%{_unitdir}/lto-archiverd.socket
install -Dpm0644 packaging/systemd/lto-archiver-command-broker.service %{buildroot}%{_unitdir}/lto-archiver-command-broker.service
install -Dpm0644 packaging/systemd/lto-archiver-command-broker.socket %{buildroot}%{_unitdir}/lto-archiver-command-broker.socket
install -Dpm0644 packaging/systemd/lto-archiver-share-broker.service %{buildroot}%{_unitdir}/lto-archiver-share-broker.service
install -Dpm0644 packaging/systemd/lto-archiver-share-broker.socket %{buildroot}%{_unitdir}/lto-archiver-share-broker.socket
install -Dpm0644 packaging/systemd/lto-archiver-log-reader.socket %{buildroot}%{_unitdir}/lto-archiver-log-reader.socket
install -Dpm0644 packaging/systemd/lto-archiver-log-reader.service %{buildroot}%{_unitdir}/lto-archiver-log-reader.service
install -Dpm0644 packaging/systemd/lto-archiver-web.service %{buildroot}%{_unitdir}/lto-archiver-web.service
install -Dpm0644 packaging/systemd/lto-archiver-ltfs-qualification.service %{buildroot}%{_unitdir}/lto-archiver-ltfs-qualification.service
install -Dpm0644 packaging/systemd/lto-archiver-archive-runner-qualification.service %{buildroot}%{_unitdir}/lto-archiver-archive-runner-qualification.service
install -Dpm0644 packaging/systemd/lto-archiver.sysusers %{buildroot}%{_sysusersdir}/lto-archiver.conf
install -Dpm0644 packaging/systemd/lto-archiver.tmpfiles %{buildroot}%{_tmpfilesdir}/lto-archiver.conf
install -Dpm0640 config/config.toml.example %{buildroot}%{_sysconfdir}/lto-archiver/config.toml
install -Dpm0640 config/web-rhel9.toml.example %{buildroot}%{_sysconfdir}/lto-archiver/web.toml
install -d -m0700 %{buildroot}%{_sysconfdir}/lto-archiver/credentials
install -d -m0750 %{buildroot}%{_sysconfdir}/lto-archiver/tls
install -Dpm0755 packaging/scripts/provision-credentials.py %{buildroot}%{_libexecdir}/lto-archiver/provision-credentials.py
install -Dpm0755 packaging/scripts/configure-device-policy.py %{buildroot}%{_libexecdir}/lto-archiver/configure-device-policy.py
install -Dpm0755 packaging/scripts/relabel-device-aliases.py %{buildroot}%{_libexecdir}/lto-archiver/relabel-device-aliases.py
install -Dpm0755 packaging/scripts/activate-rhel9.py %{buildroot}%{_libexecdir}/lto-archiver/activate-rhel9.py
install -Dpm0755 packaging/scripts/configure-web-firewall-rhel9.py %{buildroot}%{_libexecdir}/lto-archiver/configure-web-firewall-rhel9.py
install -Dpm0755 packaging/scripts/run-web-rhel9.py %{buildroot}%{_libexecdir}/lto-archiver/run-web-rhel9.py
install -Dpm0755 scripts/preflight-rhel9.sh %{buildroot}%{_libexecdir}/lto-archiver/preflight-rhel9.sh
install -Dpm0644 packaging/rpm/main-rpm-contract.json %{buildroot}%{_datadir}/lto-archiver/deployment/main-rpm-contract.json
install -Dpm0644 packaging/signing/lto-archiver-task9-rpm-public.asc %{buildroot}%{_datadir}/lto-archiver/signing/lto-archiver-task9-rpm-public.asc
install -Dpm0644 packaging/udev/70-lto-archiver-scsi.rules %{buildroot}%{_udevrulesdir}/70-lto-archiver-scsi.rules
install -Dpm0644 selinux-build/lto_archiver.pp %{buildroot}%{_datadir}/selinux/packages/lto_archiver.pp

%check
PYTHONPATH=src:%{_libdir}/lto-archiver/python-runtime/3.11/site-packages %{python3} -m unittest tests.test_linux_preflight -v
PYTHONPATH=src:%{_libdir}/lto-archiver/python-runtime/3.11/site-packages %{python3} -m unittest tests.test_python_runtime_launchers -v
PYTHONPATH=src:%{_libdir}/lto-archiver/python-runtime/3.11/site-packages %{python3} -m unittest tests.test_share_broker_packaging -v
PYTHONPATH=src:%{_libdir}/lto-archiver/python-runtime/3.11/site-packages %{python3} -m unittest tests.test_log_reader_packaging -v

%pre
/usr/bin/systemd-sysusers - <<'LTO_ARCHIVER_SYSUSERS'
u lto-archiver - "LTO Archiver daemon" /var/lib/lto-archiver /usr/sbin/nologin
u lto-web - "LTO Archiver WebUI" /var/lib/lto-archiver-web /usr/sbin/nologin
g lto-log-read -
m lto-web lto-archiver
m lto-archiver tape
m lto-archiver lto-admin
m lto-archiver lto-log-read
LTO_ARCHIVER_SYSUSERS

%post
/usr/sbin/semodule -i %{_datadir}/selinux/packages/lto_archiver.pp || exit 1
%tmpfiles_create %{_tmpfilesdir}/lto-archiver.conf
%{_libexecdir}/lto-archiver/provision-credentials.py || exit 1
/usr/sbin/restorecon -RF /etc/lto-archiver /var/lib/lto-archiver \
    /var/lib/lto-archiver-qualification \
    /var/lib/lto-archiver-broker /var/lib/lto-archiver-share-broker /var/lib/lto-archiver-web \
    /run/lto-archiver /run/lto-archiver-broker /run/lto-archiver-share-broker /run/lto-archiver-log-reader /run/lock/lto-ltfs /mnt/lto-archiver/tape \
    %{_bindir}/lto-archiverd %{_bindir}/lto-archiver-migrate \
    %{_bindir}/lto-archiver-command-broker %{_bindir}/lto-archiver-web \
    %{_bindir}/lto-archiver-share-broker %{_bindir}/lto-archiver-log-reader \
    %{_bindir}/lto-archiver-admin \
    %{_bindir}/lto-archiver-qualify-ltfs \
    %{_bindir}/lto-archiver-qualify-archive-runner \
    %{_libexecdir}/lto-archiver/run-web-rhel9.py \
    %{_libexecdir}/lto-archiver/preflight-rhel9.sh \
    /usr/bin/ltfs /usr/bin/ltfs-info /usr/bin/ltfsck /usr/bin/mkltfs \
    /usr/bin/mt /usr/bin/fusermount \
    /etc/lto-ltfs /etc/ltfs.conf || exit 1
/usr/sbin/restorecon /mnt/lto-archiver/sources || exit 1
%{_libexecdir}/lto-archiver/relabel-device-aliases.py || exit 1
%systemd_post lto-archiver-command-broker.socket lto-archiver-share-broker.socket lto-archiver-log-reader.socket lto-archiver-log-reader.service lto-archiverd.socket lto-archiver-web.service

%preun
%systemd_preun lto-archiver-command-broker.socket lto-archiver-share-broker.socket lto-archiver-log-reader.socket lto-archiver-log-reader.service lto-archiverd.socket lto-archiver-web.service

%postun
%systemd_postun_with_restart lto-archiver-command-broker.service lto-archiver-share-broker.service lto-archiver-log-reader.socket lto-archiver-log-reader.service lto-archiverd.service lto-archiver-web.service
if [ "$1" -eq 0 ]; then
    /usr/sbin/semodule -r lto_archiver >/dev/null 2>&1 || :
    /usr/sbin/restorecon -RF /usr/bin/ltfs /usr/bin/ltfs-info /usr/bin/ltfsck \
        /usr/bin/mkltfs /usr/bin/mt /usr/bin/fusermount \
        /run/lock/lto-ltfs \
        /etc/lto-ltfs /etc/ltfs.conf || :
fi

%files -f %{pyproject_files}
%license LICENSE NOTICE
%doc README.md THIRD_PARTY_NOTICES.md docs/linux/development.md docs/linux/installation-rhel9.md docs/linux/webui.md docs/linux/catalog-search.md docs/qualification/physical-ltfs-runbook.md
%attr(0755,root,root) %{_bindir}/lto-archiver-command-broker
%attr(0755,root,root) %{_bindir}/lto-archiver-share-broker
%attr(0755,root,root) %{_bindir}/lto-archiver-log-reader
%attr(0755,root,root) %{_bindir}/lto-archiver-admin
%attr(0755,root,root) %{_bindir}/lto-archiverd
%attr(0755,root,root) %{_bindir}/lto-archiver-migrate
%attr(0755,root,root) %{_bindir}/lto-archiver-qualify-ltfs
%attr(0755,root,root) %{_bindir}/lto-archiver-qualify-archive-runner
%attr(0755,root,root) %{_bindir}/lto-archiver-web
%{_unitdir}/lto-archiver-command-broker.service
%{_unitdir}/lto-archiver-command-broker.socket
%{_unitdir}/lto-archiver-share-broker.service
%{_unitdir}/lto-archiver-share-broker.socket
%{_unitdir}/lto-archiver-log-reader.socket
%{_unitdir}/lto-archiver-log-reader.service
%{_unitdir}/lto-archiver-web.service
%{_unitdir}/lto-archiver-ltfs-qualification.service
%{_unitdir}/lto-archiver-archive-runner-qualification.service
%{_unitdir}/lto-archiverd.service
%{_unitdir}/lto-archiverd.socket
%{_sysusersdir}/lto-archiver.conf
%{_tmpfilesdir}/lto-archiver.conf
%{_libexecdir}/lto-archiver/provision-credentials.py
%{_libexecdir}/lto-archiver/configure-device-policy.py
%{_libexecdir}/lto-archiver/relabel-device-aliases.py
%{_libexecdir}/lto-archiver/activate-rhel9.py
%{_libexecdir}/lto-archiver/configure-web-firewall-rhel9.py
%{_libexecdir}/lto-archiver/run-web-rhel9.py
%{_libexecdir}/lto-archiver/preflight-rhel9.sh
%dir %{_datadir}/lto-archiver
%dir %{_datadir}/lto-archiver/deployment
%dir %{_datadir}/lto-archiver/signing
%{_datadir}/lto-archiver/deployment/main-rpm-contract.json
%{_datadir}/lto-archiver/signing/lto-archiver-task9-rpm-public.asc
%{_udevrulesdir}/70-lto-archiver-scsi.rules
%{_datadir}/selinux/packages/lto_archiver.pp
%dir %attr(0750,root,lto-archiver) %{_sysconfdir}/lto-archiver
%dir %attr(0700,root,root) %{_sysconfdir}/lto-archiver/credentials
%dir %attr(0750,root,lto-web) %{_sysconfdir}/lto-archiver/tls
%ghost %dir %attr(0700,root,root) %{_sysconfdir}/lto-archiver/share-credentials
%config(noreplace) %attr(0640,root,lto-archiver) %{_sysconfdir}/lto-archiver/config.toml
%config(noreplace) %attr(0640,root,lto-web) %{_sysconfdir}/lto-archiver/web.toml
%ghost %config(noreplace) %attr(0400,root,root) %{_sysconfdir}/lto-archiver/qualification-artifacts.json

%changelog
* Wed Sep 30 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.28-155
- Prepare a distinct public GitHub release without replacing the existing tag.
- Keep runtime 0.11.27-3, driver 0.1.0-22 and catalog schema 41 unchanged.

* Wed Sep 23 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-155
- Add schema 41 source change-time provenance for future plans and jobs.
- Preserve historical plan identity and report partial metadata coverage.

* Wed Sep 23 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-154
- Defer proven quiescent pre-media failures within the same operation, with bounded backoff.
- Record closed command-release authorization failure categories before abort.

* Tue Sep 22 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-153
- Accept proven aborted identification history with retained process identity during pre-media reset.

* Tue Sep 22 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-152
- Keep Dashboard, Libraries and job reads responsive during scan persistence.
- Display cassette preparation and scan state without duplicate Resume controls.
- Preserve deliberate pause markers when admitting a recovery replacement.
- Reconcile exact stopped ambiguous media probes through authenticated reset.

* Mon Sep 21 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-151
- Bound ordinary catalog backup retention and eliminate repeated pruning scans.
- Activate automatic sequence observation after an authorized critical replacement.

* Mon Sep 21 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-150
- Route Dashboard and job recovery controls to the current protected workflow.

* Mon Sep 21 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-149
- Confirm protected recovery directly at the action, preserving the login destination.

* Mon Sep 21 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-148
- Reconcile exact empty identify reservations without unrelated process reads.

* Mon Sep 21 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-147
- Keep native cassette labels separate from manufacturer MAM serials during recovery.
- Close only old, never-launched empty identify scopes without signalling processes.
- Accept a fresh first-identity reassessment without weakening replacement or resume authority.
- Preserve runtime3, driver21, schema40 and completed cassette layouts.

* Mon Sep 21 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-146
- Distinguish the systemd local bind mount from real FUSE/LTFS mounts during pre-media reset.
- Preserve full-stack FUSE detection and command, process, target and authentication guards.
- Serialize scope creation and reopening through replay-journal commit and cgroup binding.

* Sun Sep 20 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-145
- Reconcile an unacknowledged boundary pause on authenticated Resume after full boundary evidence validation.
- Preserve background pause fences, completed cassette layout, runtime3, driver21 and schema40.

* Sun Sep 13 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-144
- Retire abandoned boundary drafts and keep claim history compact without deleting tape evidence.
- Add cached filesystem and catalog storage reporting to the authenticated WebUI.
- Check deployment and restore capacity by phase and filesystem; preserve atomic restore topology.
- Add guarded rollback-artifact retention primitives and retain application141 as predecessor.
- Keep runtime3, driver21 and schema40; signed application143 was not installed.

* Sat Sep 12 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-143
- Validate a coherent private SQLite backup instead of independently copying live DB/WAL.
- Retain integrity, foreign-key, quiescence and exact application141 predecessor gates.
- Keep runtime3, driver21 and schema40; application142 was refused before installation.

* Sat Sep 12 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-142
- Replace unused boundary manifests atomically before moving files between cassettes.
- Report catalog conflicts with bounded retry; preserve runtime3, driver21 and schema40.
- Require exact application141 predecessor and protected-snapshot rollback.

* Sat Sep 12 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-141
- Refresh native source state automatically at safe cassette boundaries.
- Preserve runtime3, driver21, schema40 and exact application140 rollback.

* Sat Sep 12 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-140
- Preserve frozen NFS-root identity across proven anonymous device renumbering.
- Keep source replacement guards, runtime3, driver21 and schema40 unchanged.
- Require exact application139 predecessor and rollback closure.

* Fri Sep 11 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-139
- Revoke pending preparation permits before exact empty-scope removal.
- Retry transient pre-authorization identification only after proven quiescence.
- Preserve runtime3, driver21, schema40 and exact application138 rollback.

* Thu Sep 10 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-138
- Add bounded quiescence-proven pre-launch probe retries and indexed scope
  lookup while preserving full startup and selected-scope validation.
- Show truthful blocked recovery state and add the protected administrator
  pre-media reset that leaves the job deliberately paused.

* Wed Sep 09 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-137
- Reconcile a proven terminal pre-media pending pause atomically during an
  authenticated native Resume while preserving permission, format-authority,
  and quiescence gates; keep the release136 inline confirmation unchanged.
- Retain exact application136/runtime3/driver21 rollback, schema40, and
  existing signing, admission, snapshot and live-health gates.

* Wed Sep 09 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-136
- Package the tested inline Resume password confirmation for deliberate pauses.
- Retain exact application135/runtime3/driver21 rollback, schema40, and
  existing signing, admission, snapshot and live-health gates.

* Wed Sep 09 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-135
- Bind the coordinated application135/runtime3/driver21 candidate to the
  approved SG close and alignment corrections.
- Retain exact application134/runtime3/driver20 rollback, schema40, and
  existing signing, admission, snapshot and live-health gates.

* Tue Sep 08 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-134
- Bind the coordinated application134/runtime3/driver20 candidate to the
  approved MAM Volume Identifier warning correction.
- Retain exact application133/runtime3/driver19 rollback, schema40, and
  existing signing, admission, snapshot and live-health gates.

* Tue Sep 08 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-133
- Bind the coordinated application133/runtime3/driver19 candidate to the
  native forced-read-only LTFS correction.
- Retain exact application132/runtime3/driver18 rollback, schema40, and
  existing signing, admission, snapshot and live-health gates.

* Sun Sep 06 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-132
- Bind the coordinated application132/runtime3/driver18 candidate to the
  driver's explicitly selected read-only capacity diagnostic.
- Retain exact application131/runtime3/driver17 rollback, schema40, and
  existing signing, admission, snapshot and live-health gates.

* Sun Sep 06 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-131
- Verify frozen next-cassette source metadata before automatic continuation.
- Remove only proven exclusive tape indexes when retiring a managed job.
- Preserve exact application130/runtime3/driver17 rollback and live-health closure.

* Sun Sep 06 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-130
- Require exact LTFS driver 17 while retaining private Python runtime 3.
- Target the release-129/schema-40 and driver-16 predecessor for protected
  rollback; keep candidate and predecessor driver authorities distinct.
- Preserve Linux/WebUI-only distribution and historical signed release identities.

* Sat Sep 05 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-129
- Wait for actual command-broker readiness before daemon preflight on cold start.
- Bind destructive qualification formatting to the exact authorized MAM serial
  in the immutable plan, token, and broker pre-dispatch checks.
- Add internal deterministic capacity-stream preparation with explicit I/O
  failure evidence; physical-capacity qualification remains a separate gate.
- Retain the exact release-127/schema-40 predecessor, runtime 3 and driver 16;
  use a new release identity without replacing the signed release-128 artifact.

* Sat Sep 05 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-128
- Correct media-status evidence, telemetry freshness, bounded request handling,
  and live management controls while retaining catalog schema 40.
- Bind deployment and rollback to the exact release-127/schema-40 predecessor;
  retain Python runtime release 3 and external LTFS driver release 16.

* Fri Sep 04 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-127
- Add the complete bounded operational-log browser across the daemon, WebUI,
  brokers, qualification services, and application-observed LTFS events.
- Install a socket-activated root journal reader behind the dedicated
  lto-log-read boundary while keeping journal and tape authority out of WebUI.
- Correlate redacted LTFS command and phase events, preserve cursor navigation
  and partial-source recovery, and keep the legacy log endpoint unchanged.
- Advance the exact installed-host transition and rollback from release 126
  while migrating its accepted schema-39 catalog to schema 40 and retaining
  Python runtime release 3 and LTFS driver 16.
- Persist hardware-command terminal exit codes and the immutable physical
  qualification readback-release receipt in schema 40.

* Fri Sep 04 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-126
- Identify virgin media through the driver's pre-format mode during normal
  execution and daemon-restart recovery, while retaining exact media binding.
- Keep automatic jobs waiting and polling across bounded missing-media windows
  so inserting the next ordered cassette does not require a manual resume.
- Suppress duplicate Start and Resume controls while the same job already owns
  an active operation, avoiding misleading daemon-rejected WebUI errors.
- Advance the exact installed-host transition and rollback from release 125
  while retaining schema 39, Python runtime release 3, and LTFS driver 16.

* Wed Sep 02 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-125
- Classify invalid admitted restore buffers and copy I/O failures with closed
  diagnostic codes that never persist exception text or paths.
- Keep generic runtime failures at cassette scope instead of misclassifying
  catalog validation or callback failures as copy-layer failures.
- Preserve stale restore fences as operation-ownership failures instead of
  relabeling them as content-copy failures.
- Keep a persisted critical quarantine passive during automatic media polling;
  only the protected administrator action performs a fresh hardware assessment.
- Advance the exact installed-host transition and rollback from release 124
  while retaining schema 39, Python runtime release 3, and LTFS driver 16.

* Wed Sep 02 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-124
- Preserve a waiting-media restore across resume, pause, and resume without
  creating a new cassette operation before media work is admitted.
- Advance the exact installed-host transition and rollback from release 123
  while retaining schema 39, Python runtime release 3, and LTFS driver 16.

* Wed Sep 02 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-123
- Correct restore pause-to-resume catalog selection while preserving schema 39.
- Advance the exact installed-host transition and rollback from release 122
  while retaining Python runtime release 3 and LTFS driver release 16.

* Tue Sep 01 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-122
- Match legacy restore media when the frozen catalog lacks only the optional
  MAM serial while retaining exact LTFS UUID and label checks.
- Recover pre-mount restore failures from an immutable no-mount command ledger
  after physical eject, and preserve one exact retry candidate.
- Resolve restore cassette labels in the recovery ledger and critical recovery
  projection without consulting the automatic-backup cassette namespace.
- Advance the exact installed-host transition and rollback from release 121
  while retaining schema 39, Python runtime release 3, and LTFS driver 16.

* Tue Sep 01 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-121
- Normalize only canonical legacy LTFS UUID values stored in the historical
  volume-serial slot before production restore hardware admission.
- Preserve distinct MAM serial and LTFS UUID identities and continue to reject
  oversized non-UUID serial values without creating a tape operation.
- Advance the exact installed-host transition and rollback from release 120
  while retaining schema 39, Python runtime release 3, and LTFS driver 16.

* Tue Sep 01 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-120
- Cover observed eight-to-ten-second finite SSE reconnect intervals without
  showing the connection warning or enabling fallback polling.
- Extend only the sustained-stream-outage grace to fifteen seconds while
  preserving three-second active refresh and five-second error backoff.
- Advance the exact installed-host transition and rollback from release 119
  while retaining schema 39, Python runtime release 3, and LTFS driver 16.

* Tue Sep 01 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-119
- Prevent transient safety-refresh failures from flashing a false connection
  warning while the authenticated SSE stream remains healthy.
- Keep bounded retry backoff for failed fragments and reserve the reconnect
  warning for a sustained stream outage beyond the five-second grace period.
- Advance the exact installed-host transition and rollback from release 118
  while retaining schema 39, Python runtime release 3, and LTFS driver 16.

* Tue Sep 01 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-118
- Eliminate full-section opacity fades during live WebUI reconciliation so
  adaptive refreshes no longer flash or visually jump.
- Preserve bounded numeric and telemetry-chart interpolation while replacing
  authoritative keyed fragments without a root-level transition.
- Advance the exact installed-host transition and rollback from release 117
  while retaining schema 39, Python runtime release 3, and LTFS driver 16.

* Tue Sep 01 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-117
- Add schema-39 immutable, multi-file, read-only LTFS restore execution through
  the authenticated English WebUI with automatic cassette sequencing.
- Add exact administrator-bound differing-destination recovery and a disabled
  physical restore qualification path without load or long wipe.
- Advance the exact installed-host transition and rollback from release 116
  while retaining Python runtime release 3 and external LTFS driver release 16.

* Mon Aug 31 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-116
- Update the authenticated Dashboard continuously with intra-file bytes and
  current write rate instead of waiting for a complete file.
- Scope effective throughput to the active tape operation and expose POSIX
  copy and close timings, streaming efficiency, and bottleneck diagnostics.
- Advance the exact installed-host transition and rollback from release 115.

* Mon Aug 31 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-115
- Use the authenticated LTFS mount receipt as the Linux volume identity after
  the broker has verified the fuse.ltfs filesystem sourced by ltfs, label, and
  volume UUID.
- Read capacity from the mounted LTFS path while deriving filesystem, label,
  and UUID from the authenticated receipt rather than the generic inspector.
- Require the exact LTFS record to be the effective topmost mount in the daemon
  namespace before the archive writer is admitted.
- Advance the exact installed-host transition and rollback from release 114.

* Mon Aug 31 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-114
- Permit the confined archive daemon to inspect the broker-mounted FUSE
  superblock while retaining all mount and device authority in the broker.
- Reject a foreign FUSE stack immediately during LTFS release and cover the
  exact read-only UID/GID/mask mount contract.
- Advance the exact installed-host transition and rollback from release 113.

* Mon Aug 31 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-113
- Mount LTFS with driver-compatible umask=027 plus the daemon UID/GID so the
  confined archive writer owns a private FUSE presentation.
- Ignore only the persistent non-FUSE systemd bind after exact LTFS release,
  while rejecting an unexpected FUSE filesystem at the tape target.
- Advance the exact installed-host transition and rollback from release 111;
  release 112 was built but rejected before installation.

* Mon Aug 31 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-112
- Mount LTFS with the daemon UID/GID and a closed 0027 mask so the confined
  archive writer can access a broker-created FUSE filesystem.
- Treat only the exact fuse.ltfs mount as pending during release, preserving
  the systemd ReadWritePaths bind mount without a false unmount failure.
- Advance the exact installed-host transition and rollback from release 111.

* Mon Aug 31 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-111
- Apply the paused/waiting-media quiescence contract consistently to deploy,
  successor live verification, and verified predecessor rollback health.
- Preserve deterministic failed-cassette retry and the direct release-108-to-111
  deployment/rollback bridge with schema 38, runtime 3, and driver 16.

* Mon Aug 31 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-110
- Admit persisted paused or waiting-media jobs to the closed deployment gate
  only when no daemon operation, LTFS process, or tape mount exists.
- Preserve the release-109 deterministic failed-cassette retry while supporting
  the direct release-108-to-110 deployment and rollback transition.
- Preserve schema 38, runtime release 3, and external LTFS driver release 16.

* Mon Aug 31 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-109
- Start the deterministic native retry directly after an administrator confirms
  the exact failed cassette, without changing the frozen job layout.
- Advance the closed deployment and rollback transition from release 108.
- Preserve schema 38, runtime release 3, and external LTFS driver release 16.

* Mon Aug 31 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-108
- Add a confirmed, label-bound retry for one uncertain cassette without
  changing the frozen job layout or rescanning sources.
- Admit the confined Web process's read-only NSS, userdb, and certificate
  startup dependencies and include setroubleshoot in the live journal gate.
- Advance the closed deployment and rollback transition from release 107.
- Preserve schema 38, runtime release 3, and external LTFS driver release 16.

* Mon Aug 31 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-107
- Make root-owned LTFS FUSE mounts accessible to the confined non-root daemon.
- Add adaptive live WebUI refresh with bounded fallback and hidden-tab pause.
- Preserve schema 38, runtime release 3, and external LTFS driver release 16.

* Mon Aug 31 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-106
- Keep protected rollback SQLite sources immutable, including WAL-mode databases.
- Admit the exact schema-35 legacy health-check combination used after rollback.
- Preserve the release-105 deadline and trusted-tool-chain hardening.

* Mon Aug 31 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-105
- Bound every daemon readiness socket operation to the total 120-second gate.
- Validate the complete trusted directory chain of rollback symlink targets.
- Align current operator and developer release references.

* Mon Aug 31 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-104
- Wait for the daemon health endpoint before running the installed-host gate.
- Accept the trusted root-owned RHEL restorecon symlink during rollback.
- Support catalog backups below an anchored /proc/self/fd directory descriptor.

* Mon Aug 31 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-103
- Traverse search-only catalog backup ancestors with O_PATH before reopening the
  destination directory for atomic publication and durability synchronization.

* Mon Aug 31 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-102
- Document schema 38 immutable cassette continuation and exact extension grants.
- Preserve the separate LTFS driver and Python 3.11 runtime contracts.
- Publish catalog backups atomically as private mode-0600 regular files.
- Parse root-run firewall configuration against the trusted lto-web group.
- Restore captured predecessor enablement before the rollback health gate.
- Report bounded non-sensitive activation stages in deployment evidence.
- Prevent stale private-runtime application modules from shadowing Release 102.
- Validate the real mount-state share layout during predecessor rollback.
- Verify the RPM-owned schema-38 import before starting any service.

* Sat Aug 29 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-101
- Publish the recoverable private RHEL 9 application release with exact signed
  runtime and external LTFS driver dependencies.
- Bind deploy and rollback to the regular RHEL 9 dnf-3 entrypoint and make
  predecessor-closure rollback idempotent.

* Fri Aug 28 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-100
- Preserve exact source paths while mapping Windows-unsafe names to a distinct
  portable LTFS namespace, and load failed plans without a secondary API error.

* Fri Aug 28 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-99
- Allow a WebUI library to bind an entire managed share when its optional
  relative subdirectory is empty, and preserve share choices after validation.

* Fri Aug 28 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-98
- Make managed-share automatic connection lifecycle-driven: active
  shares connect automatically and disabled shares disconnect safely.

* Fri Aug 28 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-97
- Require the native RHEL NFS and CIFS packages rather than merged-usr helper
  paths that DNF cannot resolve from package metadata.

* Fri Aug 28 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-96
- Guide library creation with source-specific fields and an editable generated
  ID while preserving the no-JavaScript fallback.
- Keep managed-share bindings immutable in the edit UI and translate scan
  states for operators.

* Fri Aug 28 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-95
- Recover a stale broker mount binding after an exact identity mismatch, and
  accept cleanup only after a final signed absence proof.

* Fri Aug 28 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-94
- Allow the confined daemon to traverse the policy-owned GUI share mountpoint
  for its metadata-only post-mount liveness probe.

* Fri Aug 28 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-93
- Admit both manager-level and transient-unit stop checks enforced by the RHEL
  9.8 systemd mount lifecycle.

* Fri Aug 28 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-92
- Admit systemd's manager-level StopUnit check and retain only the unit-level
  status permission required to verify transient mount removal.

* Fri Aug 28 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-91
- Grant the confined share broker systemd's manager-level transient mount start
  and unit-status checks.
- Preserve signed broker failure codes and show actionable redacted share
  errors in the authenticated WebUI.

* Fri Aug 28 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-90
- Replace free-text finite-domain settings with daemon-backed choices in the
  authenticated WebUI and expose the exact copy-buffer bounds.

* Thu Aug 27 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-89
- Show native, LTFS-usable, reserved, effective, allocated, and available
  cassette capacity in the authenticated WebUI planning flow.

* Thu Aug 27 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-88
- Allow preflight with an empty local source allowlist for hosts using only
  GUI-managed read-only NFS/SMB shares.

* Thu Aug 27 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-87
- Add authenticated read-only catalog search through the daemon-backed WebUI
  without media access or catalog migration.

* Thu Aug 27 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-86
- Migrate the exact live ccd55b5 WebUI authentication schema without changing credentials.

* Thu Aug 27 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-85
- Admit only the SELinux metadata and systemd authority observed by share readiness.

* Wed Aug 26 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-84
- add isolated read-only NFS/SMB share broker and authenticated daemon wiring
- preserve root-owned share keys and SMB credentials across package lifecycle

* Tue Aug 25 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-83
- suppress false WebUI reconnect warnings during normal SSE renewal
- improve responsive navigation and dashboard card spacing

* Tue Aug 25 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-82
- add explicit TLS certificate and key support to the confined WebUI launcher

* Tue Aug 25 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-81
- allow the confined WebUI to listen with NoNewPrivileges on labeled HTTP ports

* Tue Aug 25 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-80
- add label-first native reset/create workflow through the authenticated WebUI
- add one-cassette Linux native archive execution and exact post-eject no-media oracle
- preserve planned source mtimes in both frozen and native copy paths

* Tue Aug 25 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-79
- Admit the exact final pre-format media re-probe already required by the
  hardware path when validating imported commit ledgers.

* Tue Aug 25 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-78
- Timestamp the physical ArchiveRunner qualification operation after its
  cutover authorization so the production commit chronology can be proven.

* Tue Aug 25 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-77
- Revalidate immutable tool and device anchors during finalization without
  rejecting the expected FUSE root that covers the pre-mount directory.

* Tue Aug 25 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-76
- Publish manifests from descriptor-anchored host staging so SELinux-confined
  qualification does not depend on anonymous memfd write access.

* Tue Aug 25 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-75
- Publish portable tape manifests with LTFS-supported rename instead of the
  unsupported hard-link operation.

* Tue Aug 25 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-74
- Require LTFS R16, which exposes the exact stable FUSE source admitted by
  broker mount containment.

* Tue Aug 25 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-73
- Pin the kernel-visible LTFS FUSE source independently of the executable FD.

* Tue Aug 25 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-72
- Mount LTFS with the exact kernel-visible FUSE subtype required by the broker.

* Tue Aug 25 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-71
- Cover the full physical LTFS mount and unmount lifecycle timeout.

* Tue Aug 25 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-70
- Supply and continuously drain the mandatory LTFS operation event channel.

* Tue Aug 25 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-69
- Require LTFS R15 with generic-SCSI identity anchoring for the sg backend.

* Tue Aug 25 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-68
- Pass the anchored generic-SCSI endpoint to the LTFS sg mount backend.

* Tue Aug 25 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-67
- Bind format receipts to the final pre-format media continuity probe.

* Tue Aug 25 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-66
- Pass the anchored generic-SCSI endpoint to the LTFS sg format backend.

* Tue Aug 25 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-65
- Force explicitly authorized LTFS reformat operations for already formatted media.

* Tue Aug 25 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-64
- allow the confined ArchiveRunner to execute packaged LTFS lifecycle tools
  only after its broker-fenced hardware command release

* Tue Aug 25 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-63
- require the LTFS release whose read-only device authority is available to
  the confined non-root ArchiveRunner

* Tue Aug 25 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-62
- distinguish bounded probe exit status from terminating signal

* Tue Aug 25 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-61
- persist closed brokered media-probe failure codes

* Tue Aug 25 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-60
- distinguish closed media-field validation rejection codes

* Tue Aug 25 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-59
- persist closed pre-format identity rejection reason codes

* Tue Aug 25 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-58
- consume the attested ltfs-info schema-2 identity envelope

* Tue Aug 25 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-57
- accept the standard indented sg_inq unit-serial field

* Tue Aug 25 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-56
- admit exact metadata and access-mode validation of the release pipe

* Tue Aug 25 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-55
- admit the broker's one-byte blocked-child release pipe write

* Tue Aug 25 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-54
- admit only the blocked-child output limit and broker PID identity probe

* Tue Aug 25 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-53
- admit the broker's exact RHEL DynamicUser socket peer at startup

* Tue Aug 25 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-52
- confine command-capture temporary files to a dedicated SELinux type

* Tue Aug 25 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-51
- Accept the kernel's single terminal NUL on the exact SELinux domain probe.

* Tue Aug 25 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-50
- Run authenticated daemon preflight before device-policy verification.
- Keep systemd's writable bind above the managed LTFS target for mount probes.

* Tue Aug 25 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-49
- Admit only the exact confined broker preflight metadata probes observed on
  RHEL 9 and the daemon's kernel-labeled DynamicUser socket peer.

* Tue Aug 25 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-48
- Re-probe and pin the complete cassette identity immediately before mkltfs.
- Keep standalone qualification media inserted until the single final `mt eject`.

* Tue Aug 25 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-47
- Add label-first cutover authorization and schema-22 frozen-queue repair.
- Install the isolated end-to-end ArchiveRunner physical qualification gate.

* Tue Aug 25 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-46
- Persist ltfsck's corrected repair status through the broker state store.

* Tue Aug 25 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-45
- Accept ltfsck's documented corrected status during the repair precheck.

* Tue Aug 25 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-44
- Wait for the atomic LTFS ready-receipt publication to remove its linked
  temporary before validating the immutable receipt.

* Tue Aug 25 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-43
- Finalize every started LTFS mount cycle and identify the redacted failing
  phase before the content operation.

* Tue Aug 25 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-42
- Finalize mounted LTFS sessions after content-action failures and retain a
  redacted errno diagnostic.

* Tue Aug 25 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-41
- Admit broker traversal of the application-owned LTFS mountpoint.

* Tue Aug 25 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-40
- Admit the raw SCSI capability required by the LTFS tape backend.

* Tue Aug 25 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-39
- Preserve LTFS mount diagnostics in the system journal.

* Tue Aug 25 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-38
- Allow physical LTFS qualification stages to use the lifecycle timeout.

* Tue Aug 25 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-37
- Feed LTFS operation events through the required drained FIFO.

* Tue Aug 25 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-36
- Supply the mandatory LTFS operation event descriptor for qualification
  mounts.

* Tue Aug 25 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-35
- Authenticate the root qualification peer only for its dedicated broker
  methods while retaining the daemon-only boundary for every other method.

* Tue Aug 25 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-34
- Admit the root qualification client to the broker socket through its exact
  systemd-declared supplementary lto-archiver group.

* Tue Aug 25 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-33
- Make archive and qualification identity decisions label-first while retaining
  the legacy tape serial only as catalog lineage.
- Admit the fixed read-only LTFS identity probe on the configured SG endpoint.

* Tue Aug 25 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-32
- Permit the confined qualification domain to resolve the pinned drive through sysfs.

* Tue Aug 25 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-31
- Allow SQLite to map its catalog shared-memory file in the confined domain.

* Tue Aug 25 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-30
- Permit SQLite shared mapping after qualification sidecar ownership handoff.

* Tue Aug 25 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-29
- Preserve private catalog ownership when qualification creates SQLite sidecars.

* Tue Aug 25 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-28
- Allow the confined manual qualification unit to access the private catalog.

* Tue Aug 25 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-27
- Require exact LTFS release 11 for raw physical qualification.

* Tue Aug 25 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-26
- Require exact LTFS release 10 for raw physical qualification.

* Tue Aug 25 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-25
- Require exact LTFS release 9 for raw physical qualification.

* Tue Aug 25 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-24
- Require exact LTFS release 8 with filemark/EOD sense preservation.

* Tue Aug 25 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-23
- Require the exact LTFS release 7 package.
- Align physical token staging with the CLI's 64-byte output without a newline.

* Mon Aug 24 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-22
- Bind compatibility media identity to MAM Medium Serial Number attribute 0x0401.
- Require the exact corrected LTFS release 6 package.

* Mon Aug 24 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-21
- Qualify label-first pre-format identity against LTFS release 5.

* Mon Aug 24 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-20
- Bound SO_PEERSEC reads to Python's supported getsockopt buffer size.

* Mon Aug 24 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-19
- Traverse procfs boot-identity ancestors with O_PATH before reading the final
  file.

* Mon Aug 24 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-18
- Permit only cgroup filesystem identity inspection by the command broker.

* Mon Aug 24 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-17
- Traverse confined state-path ancestors with O_PATH while keeping the final
  directory fsyncable.

* Mon Aug 24 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-16
- Use an explicit search-only root_t rule supported by the RHEL 9 policy SDK.

* Mon Aug 24 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-15
- Admit search-only root traversal for anchored confined state-path opens.

* Mon Aug 24 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-14
- Admit search-only traversal to each confined service state root under var-lib.

* Mon Aug 24 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-13
- Permit ctime-only coordination changes on the isolated private WAL copy.

* Mon Aug 24 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-12
- Read the pre-token catalog only from a verified root-private DB/WAL snapshot.
- Exclude long wipe from the approved physical qualification sequence.

* Mon Aug 24 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-11
- Add a redacted, read-only, pre-token LTFS/blank media probe.
- Reject partially populated LTFS index identity before authorization.

* Mon Aug 24 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-10
- Probe the write-only cgroup v2 kill control with its real kernel access mode.

* Mon Aug 24 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-9
- Match systemd LoadCredential metadata and SELinux tmpfs semantics.
- Enforce role-specific LTFS tool ownership and modes at the broker boundary.

* Mon Aug 24 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-8
- Admit local NSS lookups for the broker and read-only NFS source mounts.
- Canonicalize qualification provenance, plans, and pre-repair LTFS checks.

* Mon Aug 24 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-7
- Admit the exact FUSE2 helper mode and allow confined Python entrypoints.

* Mon Aug 24 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-6
- Allow systemd to read only the managed flat device symlink.

* Mon Aug 24 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-5
- Require flat stable generic-SCSI aliases and LTFS release 4 packaging.

* Mon Aug 24 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-4
- Canonicalize SELinux runtime file contexts and require host-safe LTFS packaging.

* Mon Aug 24 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-3
- Install SELinux policy before relabeling and tolerate an absent device namespace.

* Mon Aug 24 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-2
- Bind isolated application launchers to the private Python runtime.

* Sat Aug 22 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-1
- Initial RHEL 9 native service package.
