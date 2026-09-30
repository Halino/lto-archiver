# Third-Party Notices — Linux application

This notice covers the LTO Archiver Linux application source and its
0.11.30-155 packaging contract. It does not describe the separately
versioned Python runtime or LTFS driver as though they were embedded in the
application RPM.

## Included WebUI asset

The WebUI ships `src/ltobackup/web/static/htmx.js`. Its distributed
Zero-Clause BSD license text is
[src/ltobackup/web/static/HTMX-LICENSE.txt](src/ltobackup/web/static/HTMX-LICENSE.txt).
Keep that license with the asset in source and binary distributions.

## Separate Python runtime RPM

The application depends on `lto-archiver-python-runtime-0.11.27-3`.
The runtime's exact package inventory, versions, license identifiers,
copied license texts and hashes are in
[packaging/python-runtime/THIRD_PARTY_NOTICES.md](packaging/python-runtime/THIRD_PARTY_NOTICES.md),
`packaging/python-runtime/wheel-inventory.json`, and
`packaging/python-runtime/runtime.spdx.json`. The runtime source archive
and RPM have their own source and package verification gates.

## Separate LTFS driver RPM

The application depends on `lto-ltfs-0.1.2-22` from the separate
[driver project](https://github.com/Halino/lto-ltfs-driver), which is not embedded in
the application source or RPM. The driver has a separate LGPL-2.1-only
license inventory and seven disclosed conditional, unverified file origins.
That inventory is not proof of authorship or publication rights; its exact
source and history require the owner's separate approval. A local build identity
alone is not sufficient evidence of source lineage.

Vendor firmware, proprietary tools and hardware are not bundled. Product
names in compatibility descriptions do not imply affiliation or endorsement.
The application license and copyright notices are in [LICENSE](LICENSE)
and [NOTICE](NOTICE).
