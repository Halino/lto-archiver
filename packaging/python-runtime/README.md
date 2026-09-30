# Offline Python runtime source

This directory defines the exact CPython 3.11 / EL9 x86_64 runtime closure used
by the companion RPM. It intentionally commits no wheel and no Source0 binary.
The repository contains the closed hash lock and inventory, copied license
texts, third-party notices, an SPDX 2.3 SBOM, the source verifier, and the
expected Source0 digest. `packaging`, `setuptools`, and `wheel` are build tools
and are deliberately excluded.

The committed `requirements-runtime.lock` is the byte-for-byte authorized
public lock. Its SHA-256 is recorded in `authorized-lock.sha256`,
`wheel-inventory.json` and `runtime-components.json`. Fetch every wheel by
its reviewed hash into a fresh directory; sealing then checks exact filenames,
hashes, wheel metadata and the complete 22-wheel closure. The sealing tool
uses only the Python standard library and performs no network access.

```sh
python3.11 -m pip download --require-hashes --only-binary=:all: --no-deps \
  -r packaging/python-runtime/requirements-runtime.lock \
  -d /tmp/lto-runtime-seal/wheelhouse
python3 packaging/python-runtime/runtime_source.py seal \
  --authority packaging/python-runtime/runtime-components.json \
  --authorized-lock packaging/python-runtime/requirements-runtime.lock \
  --wheelhouse /tmp/lto-runtime-seal/wheelhouse \
  --output /tmp/lto-runtime-seal/source \
  --source-date-epoch 1787523964
```

Verify the committed non-binary authority, seal the external wheels, and build
the canonical Source0 archive only in external staging:

```sh
python3 packaging/python-runtime/runtime_source.py verify-authority \
  --authority-root packaging/python-runtime
python3 packaging/python-runtime/runtime_source.py verify-source \
  --source /tmp/lto-runtime-seal/source \
  --authority-root packaging/python-runtime
python3 packaging/python-runtime/runtime_source.py build-source0 \
  --source /tmp/lto-runtime-seal/source \
  --output /tmp/lto-runtime-seal/lto-archiver-python-runtime-0.11.27.tar.gz \
  --source-date-epoch 1787523964 \
  --authority-root packaging/python-runtime
python3 packaging/python-runtime/runtime_source.py verify-source0 \
  --source /tmp/lto-runtime-seal/source \
  --archive /tmp/lto-runtime-seal/lto-archiver-python-runtime-0.11.27.tar.gz \
  --source-date-epoch 1787523964 \
  --expected-sha256 \
    packaging/python-runtime/lto-archiver-python-runtime-0.11.27.tar.gz.sha256 \
  --authority-root packaging/python-runtime
```

The sealed source tree and Source0 archive are generated externally and are not
committed. The committed digest is the release authority. All Source0 members
have lexical order, numeric owner/group zero, empty owner/group names, mode
`0755` for directories and `0644` for files, and the inventory's
`SOURCE_DATE_EPOCH` as mtime.

Build the companion RPM only from that digest-bound external Source0:

```sh
packaging/rpm/build-python-runtime-rpm.sh \
  /tmp/lto-runtime-seal/lto-archiver-python-runtime-0.11.27.tar.gz \
  /tmp/lto-runtime-rpm
```

The builder requires a clean Git tree, exact `/usr/bin/python3.11`, and local
RPM tooling. It performs two builds in distinct temporary `_topdir` roots and
publishes nothing unless the RPM and SRPM byte streams match. The build does
not run `pip`, access the network, install the resulting package, or execute
service and hardware operations. Exact RHEL 9 metadata and installroot
qualification remain release gates rather than host-portable build steps.
