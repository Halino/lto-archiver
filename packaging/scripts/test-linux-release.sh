#!/bin/bash
# Exercise the same committed Linux source scope used by release packaging.
set -euo pipefail
umask 022

if [ "$#" -gt 1 ]; then
    printf '%s\n' 'usage: test-linux-release.sh [absolute-python-path]' >&2
    exit 2
fi
lto_test_python=${1:-/usr/bin/python3.11}
if [[ "$lto_test_python" != /* || ! -x "$lto_test_python" ]]; then
    printf '%s\n' 'an absolute executable Python path is required' >&2
    exit 2
fi
lto_test_source=$(git rev-parse --show-toplevel)
lto_test_commit=$(git -C "$lto_test_source" rev-parse --verify HEAD)
if [ -n "${CI_COMMIT_SHA:-}" ] && [ "$CI_COMMIT_SHA" != "$lto_test_commit" ]; then
    printf '%s\n' 'checkout does not match the pipeline commit' >&2
    exit 2
fi
lto_test_dir=$(mktemp -d "${TMPDIR:-/tmp}/lto-linux-test.XXXXXX")
cleanup() { rm -rf -- "$lto_test_dir"; }
trap cleanup EXIT

git -C "$lto_test_source" archive --format=tar \
    --output="$lto_test_dir/source.tar" "$lto_test_commit" -- . \
    ':(exclude).superpowers/**' ':(exclude)docs/superpowers/**'
mkdir "$lto_test_dir/export"
tar --no-same-permissions -xf "$lto_test_dir/source.tar" -C "$lto_test_dir/export"
cd "$lto_test_dir/export"
export PYTHONPATH=src:.
printf 'Linux release test source: %s\n' "$lto_test_commit"
"$lto_test_python" -m unittest discover -s tests -v
