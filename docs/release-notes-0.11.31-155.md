# LTO Archiver 0.11.31-155

This is a locally prepared application candidate, not an accepted signed RPM
release. Source/tag approval and a new hosted build, comparison and fresh-install
acceptance remain pending. Published application source v0.11.30 is immutable:
its source CI passed, but its artifact comparison gate failed.

The producer now publishes the three mandatory runtime SOURCES alongside its
archive, preserving the verifier's exact allowlist and unsafe-file refusals.
The unsigned builder pins `_buildhost` to `public-build.invalid`; strict RPM
comparison is unchanged. Local seam tests do not prove hosted RPM reproducibility.

Application release 155, Python runtime 0.11.27-3, LTFS driver 0.1.2-22 and
catalog schema 41 remain unchanged. Driver v0.1.2 build, comparison and
no-tape UBI container smoke gates passed; driver signing and release acceptance remain pending.
Previous release notes and published tags remain historical and immutable.
