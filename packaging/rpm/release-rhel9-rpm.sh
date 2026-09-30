#!/bin/sh
set -eu
umask 077

if [ "$#" -ne 4 ]; then
    echo "usage: release-rhel9-rpm.sh OUTPUT_DIRECTORY GNUPGHOME PRIMARY_FINGERPRINT SIGNING_SUBKEY_FINGERPRINT" >&2
    exit 2
fi

case $0 in
    */*) script_parent=${0%/*} ;;
    *) echo "RPM release builder must be invoked through an explicit path" >&2; exit 2 ;;
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
canonical_wrapper=$repository/packaging/rpm/release-rhel9-rpm.sh
if [ ! "$canonical_wrapper" -ef "$0" ]; then
    echo "RPM release wrapper is not the committed repository wrapper" >&2
    exit 2
fi
wrapper_sha256=$(
    closed_git -C "$repository" show HEAD:packaging/rpm/release-rhel9-rpm.sh |
        /usr/bin/sha256sum
)
wrapper_sha256=${wrapper_sha256%% *}
running_wrapper_sha256=$(/usr/bin/sha256sum "$canonical_wrapper")
running_wrapper_sha256=${running_wrapper_sha256%% *}
if [ "$running_wrapper_sha256" != "$wrapper_sha256" ]; then
    echo "RPM release wrapper differs from committed HEAD" >&2
    exit 2
fi
index_rows=$(closed_git -C "$repository" ls-files -v)
case "$index_rows" in
    [a-zS]' '*|*'
'[a-zS]' '*)
        echo "RPM release source has unsafe Git index flags" >&2
        exit 2
        ;;
esac
if [ -n "$(closed_git -C "$repository" status --porcelain)" ]; then
    echo "RPM release source tree must be clean" >&2
    exit 2
fi
commit_before=$(closed_git -C "$repository" rev-parse HEAD)
case "$commit_before" in
    ''|*[!0-9a-f]*) echo "invalid repository commit" >&2; exit 2 ;;
esac

caller_directory=$(pwd -P)
case $1 in
    /*) output=$1 ;;
    *) output=$caller_directory/$1 ;;
esac
signing_gnupg_home=$2
primary_fingerprint=$3
signing_subkey_fingerprint=$4
gate_directory=$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/lto-packaging-gate.XXXXXX")
gate_report=$gate_directory/packaging-gate.json
gate_signature=$gate_directory/packaging-gate.json.asc
detached_repository=$gate_directory/repository
cleanup() {
    /usr/bin/rm -rf -- "$gate_directory"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

closed_git clone --quiet --no-hardlinks --no-checkout \
    "$repository" "$detached_repository"
closed_git -C "$detached_repository" checkout --quiet --detach "$commit_before"
if [ -n "$(closed_git -C "$detached_repository" status --porcelain)" ] || \
    [ "$(closed_git -C "$detached_repository" rev-parse HEAD)" != "$commit_before" ]; then
    echo "detached RPM release source does not match the clean commit" >&2
    exit 2
fi

builder=$detached_repository/packaging/rpm/build-rhel9-rpm.sh
gate_runner=$detached_repository/packaging/rpm/run-packaging-gate.py
builder_sha256=$(
    closed_git -C "$detached_repository" show HEAD:packaging/rpm/build-rhel9-rpm.sh |
        /usr/bin/sha256sum
)
builder_sha256=${builder_sha256%% *}
gate_runner_sha256=$(
    closed_git -C "$detached_repository" show HEAD:packaging/rpm/run-packaging-gate.py |
        /usr/bin/sha256sum
)
gate_runner_sha256=${gate_runner_sha256%% *}
gate_home=$gate_directory/home
gate_tmp=$gate_directory/tmp
/usr/bin/mkdir -m 0700 "$gate_home" "$gate_tmp"
/usr/bin/env -i \
    HOME="$gate_home" \
    LANG=C \
    LC_ALL=C \
    PATH=/usr/sbin:/usr/bin:/sbin:/bin \
    TMPDIR="$gate_tmp" \
    /usr/bin/python3.11 -I -c '
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
' /usr/bin/python3.11 "$gate_runner" "$gate_runner_sha256" \
    --source-root "$detached_repository" \
    --output "$gate_report" \
    --repository-commit "$commit_before" \
    --builder-sha256 "$builder_sha256" \
    --runner-sha256 "$gate_runner_sha256"

if [ -n "$(closed_git -C "$detached_repository" status --porcelain)" ] || \
    [ "$(closed_git -C "$detached_repository" rev-parse HEAD)" != "$commit_before" ]; then
    echo "detached RPM release source changed during the packaging gate" >&2
    exit 2
fi
/usr/bin/env -i LANG=C LC_ALL=C GNUPGHOME="$signing_gnupg_home" \
    /usr/bin/gpg \
    --homedir "$signing_gnupg_home" \
    --batch \
    --armor \
    --local-user "$signing_subkey_fingerprint!" \
    --output "$gate_signature" \
    --detach-sign "$gate_report"
/usr/bin/chmod 0600 "$gate_signature"

/usr/bin/env -i \
    HOME="$gate_home" \
    LANG=C \
    LC_ALL=C \
    PATH=/usr/sbin:/usr/bin:/sbin:/bin \
    TMPDIR="$gate_tmp" \
    /usr/bin/python3.11 -I -c '
import hashlib
import os
import stat
import subprocess
import sys

if sys.executable != sys.argv[1] or sys.version_info[:2] != (3, 11):
    raise SystemExit(2)
builder_descriptor = os.open(
    sys.argv[2], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
)
path_status = os.lstat(sys.argv[2])
descriptor_status = os.fstat(builder_descriptor)
if (
    not stat.S_ISREG(path_status.st_mode)
    or not stat.S_ISREG(descriptor_status.st_mode)
    or descriptor_status.st_uid != os.getuid()
    or descriptor_status.st_nlink != 1
    or descriptor_status.st_mode & 0o022
    or (path_status.st_dev, path_status.st_ino)
    != (descriptor_status.st_dev, descriptor_status.st_ino)
):
    raise SystemExit(2)
with os.fdopen(os.dup(builder_descriptor), "rb") as source:
    builder_digest = hashlib.file_digest(source, "sha256").hexdigest()
if builder_digest != sys.argv[3]:
    raise SystemExit(2)
os.lseek(builder_descriptor, 0, os.SEEK_SET)
result = subprocess.run(
    ["/bin/sh", "-s", sys.argv[2], *sys.argv[4:]],
    stdin=builder_descriptor,
    env=os.environ,
    close_fds=True,
    check=False,
)
raise SystemExit(result.returncode)
' /usr/bin/python3.11 "$builder" "$builder_sha256" \
    "$output" \
    "$signing_gnupg_home" \
    "$primary_fingerprint" \
    "$signing_subkey_fingerprint" \
    "$gate_report" \
    "$gate_signature"
