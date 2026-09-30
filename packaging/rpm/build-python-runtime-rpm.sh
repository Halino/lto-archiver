#!/bin/sh
set -eu

if [ "$#" -ne 5 ]; then
    echo "usage: build-python-runtime-rpm.sh SOURCE0_ARCHIVE OUTPUT_DIRECTORY GNUPGHOME PRIMARY_FINGERPRINT SIGNING_SUBKEY_FINGERPRINT" >&2
    exit 2
fi

case $0 in
    */*) script_parent=${0%/*} ;;
    *) echo "runtime RPM builder must be invoked through an explicit path" >&2; exit 2 ;;
esac
if [ -z "$script_parent" ]; then
    script_parent=/
fi
script_directory=$(
    CDPATH=
    cd "$script_parent"
    pwd -P
)
repository=$(/usr/bin/git rev-parse --show-toplevel)
if [ -n "$(/usr/bin/git -C "$repository" status --porcelain)" ]; then
    echo "RPM source tree must be clean" >&2
    exit 2
fi

name=lto-archiver-python-runtime
spec=$repository/packaging/rpm/$name.spec
version=$(/usr/bin/sed -n 's/^Version:[[:space:]]*//p' "$spec")
release=$(/usr/bin/sed -n 's/^Release:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$spec")
case "$version" in
    ''|*[!0-9.]*) echo "invalid runtime RPM version" >&2; exit 2 ;;
esac
case "$release" in
    ''|*[!0-9]*) echo "invalid runtime RPM release" >&2; exit 2 ;;
esac

source0_argument=$1
if [ ! -f "$source0_argument" ] || [ -L "$source0_argument" ]; then
    echo "Source0 must be a regular non-symlink file" >&2
    exit 2
fi
case $source0_argument in
    */*) source0_parent=${source0_argument%/*}; source0_name=${source0_argument##*/} ;;
    *) source0_parent=.; source0_name=$source0_argument ;;
esac
source0_parent=$(
    CDPATH=
    cd "$source0_parent"
    pwd -P
)
source0=$source0_parent/$source0_name
expected_source0_name=$name-$version.tar.gz
if [ "$source0_name" != "$expected_source0_name" ]; then
    echo "unexpected Source0 filename" >&2
    exit 2
fi

digest_file=$repository/packaging/python-runtime/$expected_source0_name.sha256
IFS=' ' read -r expected_digest expected_filename extra <"$digest_file" || {
    echo "cannot read Source0 SHA-256 authority" >&2
    exit 2
}
expected_filename=${expected_filename#\*}
case "$expected_digest" in
    *[!0-9a-f]*|'') echo "malformed Source0 SHA-256 authority" >&2; exit 2 ;;
esac
if [ "${#expected_digest}" -ne 64 ] || [ "$expected_filename" != "$source0_name" ] || [ -n "${extra:-}" ]; then
    echo "malformed Source0 SHA-256 authority" >&2
    exit 2
fi
actual_digest=$(/usr/bin/sha256sum "$source0")
actual_digest=${actual_digest%% *}
if [ "$actual_digest" != "$expected_digest" ]; then
    echo "Source0 SHA-256 mismatch" >&2
    exit 2
fi

inventory=$repository/packaging/python-runtime/wheel-inventory.json
source_date_epoch=$(/usr/bin/sed -n 's/^[[:space:]]*"source_date_epoch":[[:space:]]*\([0-9][0-9]*\),*$/\1/p' "$inventory")
case "$source_date_epoch" in
    ''|*[!0-9]*) echo "invalid runtime SOURCE_DATE_EPOCH" >&2; exit 2 ;;
esac
export SOURCE_DATE_EPOCH="$source_date_epoch"

output=$2
signing_gnupg_home=$3
primary_fingerprint=$4
signing_subkey_fingerprint=$5
if [ -e "$output" ] || [ -L "$output" ]; then
    echo "RPM output directory must not exist" >&2
    exit 2
fi

build_parent=$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/lto-python-runtime-rpm-builds.XXXXXX")
cleanup() {
    /usr/bin/rm -rf -- "$build_parent"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

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
    /usr/bin/install -pm0644 "$source0" "$topdir/SOURCES/$expected_source0_name"
    /usr/bin/install -pm0644 "$digest_file" "$topdir/SOURCES/$expected_source0_name.sha256"
    /usr/bin/install -pm0644 \
        "$repository/packaging/python-runtime/runtime_install.py" \
        "$topdir/SOURCES/runtime_install.py"
    /usr/bin/install -pm0644 \
        "$repository/packaging/python-runtime/runtime-payload-authority.json" \
        "$topdir/SOURCES/runtime-payload-authority.json"
    /usr/bin/install -pm0644 "$spec" "$topdir/SPECS/$name.spec"
    /usr/bin/rpmbuild -ba \
        --define "_topdir $topdir" \
        "$topdir/SPECS/$name.spec"
}

artifact_list() {
    topdir=$1
    (
        cd "$topdir"
        /usr/bin/find RPMS SRPMS -type f -name '*.rpm' -print | LC_ALL=C /usr/bin/sort
    )
}

build_once "$first"
build_once "$second"
artifact_list "$first" >"$first/artifacts.list"
artifact_list "$second" >"$second/artifacts.list"
if [ "$(/usr/bin/wc -l <"$first/artifacts.list")" -ne 2 ] || \
        ! /usr/bin/cmp -s "$first/artifacts.list" "$second/artifacts.list"; then
    echo "runtime RPM reproducibility check failed" >&2
    exit 2
fi
binary_count=0
source_count=0
while IFS= read -r relative; do
    case $relative in
        RPMS/x86_64/$name-$version-$release*.x86_64.rpm) binary_count=$((binary_count + 1)) ;;
        SRPMS/$name-$version-$release*.src.rpm) source_count=$((source_count + 1)) ;;
        *) echo "unexpected runtime RPM artifact: $relative" >&2; exit 2 ;;
    esac
    if ! /usr/bin/cmp -s "$first/$relative" "$second/$relative"; then
        echo "runtime RPM reproducibility check failed" >&2
        exit 2
    fi
done <"$first/artifacts.list"
if [ "$binary_count" -ne 1 ] || [ "$source_count" -ne 1 ]; then
    echo "runtime RPM artifact closure mismatch" >&2
    exit 2
fi

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
helper = os.open(sys.argv[2], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
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
    --source-archive "$expected_source0_name" \
    --spec-name "$name.spec" \
    --output "$build_parent/unsigned"

signer=$repository/packaging/rpm/sign-rpm-tree.py
signer_digest=$(
    /usr/bin/git -C "$repository" show HEAD:packaging/rpm/sign-rpm-tree.py |
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
