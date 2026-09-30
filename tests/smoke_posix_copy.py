from __future__ import annotations

import argparse
import hashlib
import tempfile
from pathlib import Path
from unittest.mock import patch

from ltobackup.tape.copier import CopyRequest, copy_frozen_file


class _CountedHandle:
    def __init__(self, raw, tracker):
        self._raw = raw
        self._tracker = tracker
        self._closed = False

    @property
    def closed(self):
        return self._raw.closed

    def close(self):
        if self._closed:
            return
        try:
            self._raw.close()
        finally:
            self._closed = True
            self._tracker.active -= 1

    def __getattr__(self, name):
        return getattr(self._raw, name)


class _CountedOpen:
    def __init__(self):
        self._open = open
        self.active = 0
        self.maximum = 0

    def __call__(self, *args, **kwargs):
        raw = self._open(*args, **kwargs)
        self.active += 1
        self.maximum = max(self.maximum, self.active)
        return _CountedHandle(raw, self)


def run_smoke(byte_count: int) -> None:
    if byte_count < 0:
        raise ValueError("--bytes must be non-negative")
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        source = root / "source.bin"
        destination = root / "destination.bin"
        digest = hashlib.sha256()
        remaining = byte_count
        pattern = bytes(range(256)) * 4096
        with source.open("wb") as handle:
            while remaining:
                chunk = pattern[: min(remaining, len(pattern))]
                handle.write(chunk)
                digest.update(chunk)
                remaining -= len(chunk)
        source_stat = source.stat()
        tracker = _CountedOpen()
        with patch("builtins.open", tracker):
            result = copy_frozen_file(
                CopyRequest(
                    source=source,
                    destination=destination,
                    expected_size=source_stat.st_size,
                    expected_mtime_ns=source_stat.st_mtime_ns,
                    buffer_bytes=8 * 1024 * 1024,
                    stop_requested=lambda: False,
                    phase_callback=lambda event: None,
                    fence_check=lambda: None,
                )
            )
        if result.sha256 != digest.hexdigest():
            raise AssertionError("inline SHA-256 mismatch")
        if result.bytes_copied != byte_count:
            raise AssertionError("copied byte count mismatch")
        if destination.stat().st_size != byte_count:
            raise AssertionError("destination size mismatch")
        destination_digest = hashlib.sha256()
        with destination.open("rb") as handle:
            while chunk := handle.read(8 * 1024 * 1024):
                destination_digest.update(chunk)
        if destination_digest.hexdigest() != digest.hexdigest():
            raise AssertionError("independently read destination SHA-256 mismatch")
        if tracker.maximum > 2 or tracker.active:
            raise AssertionError(
                f"handle bound violated: maximum={tracker.maximum} active={tracker.active}"
            )
        print(
            f"copied={result.bytes_copied} sha256={result.sha256} "
            f"read_seconds={result.read_seconds:.6f} "
            f"write_seconds={result.write_seconds:.6f} "
            f"close_seconds={result.close_seconds:.6f} "
            f"max_file_handles={tracker.maximum} directory_fds_excluded=true "
            "destination_reference_fd_excluded=true"
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Local sequential POSIX copy smoke")
    parser.add_argument("--bytes", type=int, default=64 * 1024 * 1024)
    args = parser.parse_args()
    run_smoke(args.bytes)


if __name__ == "__main__":
    main()
