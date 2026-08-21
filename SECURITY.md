# Security Policy

## Supported versions

Security fixes are provided for the current `0.11.x` release line. Reports
against older releases should include the version in use; maintainers will
assess whether a supported-version update or mitigation is available.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability.

After the GitHub repository has been created and private vulnerability reporting has been configured, report vulnerabilities through the repository's private vulnerability-reporting channel. Include a sanitized description, affected version, impact, and safe reproduction steps.

Do not disclose credentials, tokens, private keys, private paths, full catalog
databases, unsanitized logs, media labels, device serial numbers, or HPE support
tickets in public issues, discussions, pull requests, commits, or attachments.

## Coordinated disclosure

Maintainers will acknowledge a private report, investigate it, and coordinate
validation, remediation, and a disclosure timeline with the reporter. Please
allow a fix or mitigation to be prepared before public disclosure. The release
notes or advisory will credit reporters when they request it and when doing so
does not create a privacy or safety risk.

## Security boundaries

LTO Archiver controls destructive tape operations and may interact with
privileged Windows services. Reports should avoid performing destructive actions
on production media. Use a safe, disposable test environment whenever possible.
