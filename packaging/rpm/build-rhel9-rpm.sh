#!/bin/sh
set -eu

if [ "$#" -ne 7 ]; then
    echo "internal usage: build-rhel9-rpm.sh PINNED_BUILDER_PATH OUTPUT_DIRECTORY GNUPGHOME PRIMARY_FINGERPRINT SIGNING_SUBKEY_FINGERPRINT GATE_REPORT GATE_SIGNATURE" >&2
    exit 2
fi

invoked_builder=$1
shift
case $invoked_builder in
    */*) script_parent=${invoked_builder%/*} ;;
    *) echo "RPM builder must be invoked through an explicit path" >&2; exit 2 ;;
esac
if [ -z "$script_parent" ]; then
    script_parent=/
fi
script_directory=$(
    CDPATH=
    cd "$script_parent"
    pwd -P
)
closed_git() {
    /usr/bin/env -i HOME=/ LANG=C LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
        /usr/bin/git "$@"
}
repository=$(closed_git -C "$script_directory/../.." rev-parse --show-toplevel)
canonical_builder=$repository/packaging/rpm/build-rhel9-rpm.sh
if [ ! "$canonical_builder" -ef "$invoked_builder" ]; then
    echo "internal RPM builder is not the committed repository builder" >&2
    exit 2
fi
index_rows=$(closed_git -C "$repository" ls-files -v)
case "$index_rows" in
    [a-zS]' '*|*'
'[a-zS]' '*)
        echo "RPM source has unsafe Git index flags" >&2
        exit 2
        ;;
esac
if [ -n "$(closed_git -C "$repository" status --porcelain)" ]; then
    echo "RPM source tree must be clean" >&2
    exit 2
fi

name=lto-archiver
version=$(/usr/bin/sed -n 's/^Version:[[:space:]]*//p' "$repository/packaging/rpm/lto-archiver.spec")
case "$version" in
    ''|*[!0-9.]*) echo "invalid RPM version" >&2; exit 2 ;;
esac

output=$1
signing_gnupg_home=$2
primary_fingerprint=$3
signing_subkey_fingerprint=$4
gate_report=$5
gate_signature=$6
builder_sha256=$(
    closed_git -C "$repository" show HEAD:packaging/rpm/build-rhel9-rpm.sh |
        /usr/bin/sha256sum
)
builder_sha256=${builder_sha256%% *}
running_builder_sha256=$(/usr/bin/sha256sum "$canonical_builder")
running_builder_sha256=${running_builder_sha256%% *}
if [ "$running_builder_sha256" != "$builder_sha256" ]; then
    echo "internal RPM builder differs from committed HEAD" >&2
    exit 2
fi
gate_verifier=$repository/packaging/rpm/verify-packaging-gate.py
gate_verifier_sha256=$(
    closed_git -C "$repository" show HEAD:packaging/rpm/verify-packaging-gate.py |
        /usr/bin/sha256sum
)
gate_verifier_sha256=${gate_verifier_sha256%% *}
gate_runner_sha256=$(
    closed_git -C "$repository" show HEAD:packaging/rpm/run-packaging-gate.py |
        /usr/bin/sha256sum
)
gate_runner_sha256=${gate_runner_sha256%% *}
gate_python=/usr/bin/python3.11
if [ ! -x "$gate_python" ]; then
    echo "packaging gate requires exact /usr/bin/python3.11" >&2
    exit 2
fi
build_parent=$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/lto-archiver-rpm-builds.XXXXXX")
verified_gate_directory=$build_parent/verified-packaging-gate
/usr/bin/mkdir -m 0700 "$verified_gate_directory"
cleanup() {
    /usr/bin/rm -rf -- "$build_parent"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
"$gate_python" -I -c '
import hashlib
import os
import stat
import sys

if sys.executable != sys.argv[1] or sys.version_info[:2] != (3, 11):
    raise SystemExit(2)
helper = os.open(sys.argv[2], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
status = os.fstat(helper)
if (
    not stat.S_ISREG(status.st_mode)
    or status.st_mode & 0o022
    or status.st_uid not in (0, os.getuid())
):
    raise SystemExit(2)
with os.fdopen(os.dup(helper), "rb") as source:
    digest = hashlib.file_digest(source, "sha256").hexdigest()
if digest != sys.argv[3]:
    raise SystemExit(2)
os.lseek(helper, 0, os.SEEK_SET)
os.set_inheritable(helper, True)
os.execve(
    sys.executable,
    [sys.executable, "-I", f"/proc/self/fd/{helper}", *sys.argv[4:]],
    os.environ,
)
' "$gate_python" "$gate_verifier" "$gate_verifier_sha256" \
    --report "$gate_report" \
    --signature "$gate_signature" \
    --public-key "$repository/packaging/signing/lto-archiver-task9-rpm-public.asc" \
    --verified-output-directory "$verified_gate_directory" \
    --expected-commit "$(closed_git -C "$repository" rev-parse HEAD)" \
    --expected-builder-sha256 "$builder_sha256" \
    --expected-runner-sha256 "$gate_runner_sha256" \
    --primary-fingerprint "$primary_fingerprint" \
    --signing-subkey-fingerprint "$signing_subkey_fingerprint"
gate_report=$verified_gate_directory/packaging-gate.json
gate_signature=$verified_gate_directory/packaging-gate.json.asc
if [ -e "$output" ] || [ -L "$output" ]; then
    echo "RPM output directory must not exist" >&2
    exit 2
fi
source_date_epoch=$(closed_git -C "$repository" show -s --format=%ct HEAD)
case "$source_date_epoch" in
    ''|*[!0-9]*) echo "invalid source date epoch" >&2; exit 2 ;;
esac
export SOURCE_DATE_EPOCH="$source_date_epoch"

first=$build_parent/first
second=$build_parent/second
/usr/bin/mkdir -p "$first" "$second"

build_once() {
    topdir=$1
    /usr/bin/mkdir -p \
        "$topdir/BUILD" \
        "$topdir/BUILDROOT" \
        "$topdir/RPMS" \
        "$topdir/SOURCES" \
        "$topdir/SPECS" \
        "$topdir/SRPMS"
    closed_git -C "$repository" archive \
        --format=tar.gz \
        --prefix="$name-$version/" \
        --output="$topdir/SOURCES/$name-$version.tar.gz" \
        HEAD -- . \
        ':(exclude).superpowers/**' \
        ':(exclude)docs/superpowers/**'
    /usr/bin/install -pm0644 \
        "$repository/packaging/rpm/lto-archiver.spec" \
        "$topdir/SPECS/lto-archiver.spec"
    /usr/bin/rpmbuild -ba \
        --define "_topdir $topdir" \
        "$topdir/SPECS/lto-archiver.spec"
}

stage_deploy() {
    topdir=$1
    /usr/bin/install -d -m0755 "$topdir/DEPLOY"
    /usr/bin/install -pm0644 \
        "$repository/packaging/rpm/verify-main-rpm.py" \
        "$topdir/DEPLOY/verify-main-rpm.py"
    /usr/bin/install -pm0644 \
        "$repository/packaging/rpm/main-rpm-contract.json" \
        "$topdir/DEPLOY/main-rpm-contract.json"
}

stage_gate_evidence() {
    topdir=$1
    /usr/bin/install -d -m0700 "$topdir/VERIFICATION"
    /usr/bin/install -pm0444 \
        "$gate_report" \
        "$topdir/VERIFICATION/packaging-gate.json"
    /usr/bin/install -pm0444 \
        "$gate_signature" \
        "$topdir/VERIFICATION/packaging-gate.json.asc"
}

verify_once() {
    topdir=$1
    set -- "$topdir"/RPMS/noarch/*.rpm
    if [ "$#" -ne 1 ] || [ ! -f "$1" ] || [ -L "$1" ]; then
        echo "main RPM artifact closure mismatch" >&2
        exit 2
    fi
    main_rpm=$1
    /usr/bin/install -d -m0700 "$topdir/VERIFICATION"
    report=$topdir/VERIFICATION/main-rpm.json
    verifier=$repository/packaging/rpm/verify-main-rpm.py
    expected_digest=$(
        closed_git -C "$repository" show HEAD:packaging/rpm/verify-main-rpm.py |
            /usr/bin/sha256sum
    )
    expected_digest=${expected_digest%% *}
    verify_python=/usr/bin/python3.11
    if [ ! -x "$verify_python" ]; then
        echo "main RPM verifier requires exact /usr/bin/python3.11" >&2
        exit 2
    fi
    "$verify_python" -I -c '
import hashlib
import os
import stat
import sys

if sys.executable != sys.argv[1] or sys.version_info[:2] != (3, 11):
    raise SystemExit(2)
helper = os.open(sys.argv[2], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
status = os.fstat(helper)
if (
    not stat.S_ISREG(status.st_mode)
    or status.st_mode & 0o022
    or status.st_uid not in (0, os.getuid())
):
    raise SystemExit(2)
with os.fdopen(os.dup(helper), "rb") as source:
    digest = hashlib.file_digest(source, "sha256").hexdigest()
if digest != sys.argv[3]:
    raise SystemExit(2)
os.lseek(helper, 0, os.SEEK_SET)
os.set_inheritable(helper, True)
os.execve(
    sys.executable,
    [sys.executable, "-I", f"/proc/self/fd/{helper}", *sys.argv[4:]],
    os.environ,
)
' "$verify_python" "$verifier" "$expected_digest" \
        --rpm "$main_rpm" \
        --source-root "$repository" \
        --contract "$repository/packaging/rpm/main-rpm-contract.json" \
        --json-output "$report"
}

artifact_list() {
    topdir=$1
    (
        cd "$topdir"
        /usr/bin/find RPMS SRPMS -type f -name '*.rpm' -print | LC_ALL=C /usr/bin/sort
    )
}

build_once "$first"
stage_deploy "$first"
stage_gate_evidence "$first"
verify_once "$first"
build_once "$second"
stage_deploy "$second"
stage_gate_evidence "$second"
verify_once "$second"
if ! /usr/bin/cmp -s \
        "$first/VERIFICATION/main-rpm.json" \
        "$second/VERIFICATION/main-rpm.json"; then
    echo "main RPM verification reproducibility check failed" >&2
    exit 2
fi
artifact_list "$first" >"$first/artifacts.list"
artifact_list "$second" >"$second/artifacts.list"
if [ ! -s "$first/artifacts.list" ] || \
        ! /usr/bin/cmp -s "$first/artifacts.list" "$second/artifacts.list"; then
    echo "RPM reproducibility check failed" >&2
    exit 2
fi
while IFS= read -r relative; do
    if ! /usr/bin/cmp -s "$first/$relative" "$second/$relative"; then
        echo "RPM reproducibility check failed" >&2
        exit 2
    fi
done <"$first/artifacts.list"

publish_python=/usr/bin/python3.11
if [ ! -x "$publish_python" ]; then
    echo "RPM publisher requires exact /usr/bin/python3.11" >&2
    exit 2
fi
"$publish_python" -I -c '
import hashlib
import os
import stat
import sys

if sys.executable != sys.argv[1] or sys.version_info[:2] != (3, 11):
    raise SystemExit(2)
helper = os.open(
    sys.argv[2], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
)
status = os.fstat(helper)
if (
    not stat.S_ISREG(status.st_mode)
    or status.st_mode & 0o002
    or status.st_uid not in (0, os.getuid())
):
    raise SystemExit(2)
with os.fdopen(os.dup(helper), "rb") as source:
    digest = hashlib.file_digest(source, "sha256").hexdigest()
if digest != "fcc1d8e63df7baee897dbb4042c5944c1f0e557555a6e6c88af586b4a34a28f5":
    raise SystemExit(2)
os.lseek(helper, 0, os.SEEK_SET)
os.set_inheritable(helper, True)
os.execve(
    sys.executable,
    [sys.executable, "-I", f"/proc/self/fd/{helper}", *sys.argv[3:]],
    os.environ,
)
' "$publish_python" "$script_directory/publish-rpm-tree.py" \
    --source-root "$first" \
    --second-source-root "$second" \
    --source-archive "$name-$version.tar.gz" \
    --spec-name lto-archiver.spec \
    --output "$build_parent/unsigned"

signer=$repository/packaging/rpm/sign-rpm-tree.py
signer_digest=$(
    closed_git -C "$repository" show HEAD:packaging/rpm/sign-rpm-tree.py |
        /usr/bin/sha256sum
)
signer_digest=${signer_digest%% *}
"$publish_python" -I -c '
import hashlib
import os
import stat
import sys

if sys.executable != sys.argv[1] or sys.version_info[:2] != (3, 11):
    raise SystemExit(2)
helper = os.open(sys.argv[2], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
status = os.fstat(helper)
if (
    not stat.S_ISREG(status.st_mode)
    or status.st_mode & 0o022
    or status.st_uid not in (0, os.getuid())
):
    raise SystemExit(2)
with os.fdopen(os.dup(helper), "rb") as source:
    digest = hashlib.file_digest(source, "sha256").hexdigest()
if digest != sys.argv[3]:
    raise SystemExit(2)
os.lseek(helper, 0, os.SEEK_SET)
os.set_inheritable(helper, True)
os.execve(
    sys.executable,
    [sys.executable, "-I", f"/proc/self/fd/{helper}", *sys.argv[4:]],
    os.environ,
)
' "$publish_python" "$signer" "$signer_digest" \
    --unsigned-tree "$build_parent/unsigned" \
    --output "$output" \
    --package-name "$name" \
    --gnupg-home "$signing_gnupg_home" \
    --primary-fingerprint "$primary_fingerprint" \
    --signing-subkey-fingerprint "$signing_subkey_fingerprint" \
    --policy "$repository/packaging/deployment/app-runtime-signing-policy.json" \
    --public-key "$repository/packaging/signing/lto-archiver-task9-rpm-public.asc"
