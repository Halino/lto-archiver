# Security policy

Security reports for the active Linux source target the `linux` branch and
the current `0.11.30` candidate. Include the exact commit and affected package
version. Historical Windows material is archived, not an active supported
distribution; see the [Windows archive](docs/windows-archive.md).

Do not open an ordinary GitHub issue for a suspected vulnerability. Use the
application repository's [private GitHub reporting page](https://github.com/Halino/lto-archiver/security/advisories/new).
For driver vulnerabilities use the [driver's private reporting page](https://github.com/Halino/lto-ltfs-driver/security/advisories/new).
If private reporting is unavailable, do not publish
exploit details or secrets in an issue. Wait for a private reporting path to
be announced.

Include a sanitized description, impact, affected version and safe
reproduction steps. Never disclose credentials, tokens, keys, raw catalogs,
media labels, drive serial numbers, private paths, host addresses or
unsanitized logs in reports, commits or attachments.

Maintainers will investigate private reports and coordinate validation,
remediation and a disclosure timeline with reporters. The WebUI operational
log remains a bounded, redacted view, not a public support bundle. Test
destructive tape scenarios only on disposable media in a safe environment.
