#!/usr/bin/env bash
# Run only from the UUID-bound controller's root-owned private staging directory.
set -euo pipefail
if [[ $# != 3 ]]; then
    echo 'usage: smoke-public-fresh-rhel9.sh APP_CANDIDATE DRIVER_CANDIDATE REPORT_PATH' >&2
    exit 2
fi
runner_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
exec >> "$runner_dir/guest.stdout" 2>> "$runner_dir/guest.stderr"
exec /usr/bin/python3.11 -I "$runner_dir/public_fresh_guest.py" "$1" "$2" "$3"
