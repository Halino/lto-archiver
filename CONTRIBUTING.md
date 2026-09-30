# Contributing to LTO Archiver

Thank you for helping improve LTO Archiver. This project manages backup and
catalog workflows around LTFS tape media, so every change must preserve safe,
explicit handling of destructive and privileged operations.

## Development environment

- Use Python 3.11.
- Develop and run the test suite on Linux. The current source candidate is
  application 0.11.30-155, runtime 0.11.27-3, driver 0.1.2-22 and schema 41.
  Linux-side import of existing legacy catalogs and cross-platform filenames
  are compatibility features. Former Windows builds and operator guidance are
  in the [Windows archive](docs/windows-archive.md).
- Install the pinned development/build dependencies documented by the project
  before running tests.

## Branches, tests, and commits

Create a short-lived branch from the active default branch,
[`linux`](https://github.com/Halino/lto-archiver/tree/linux), and submit pull
requests against `linux`. Use a descriptive
lowercase name with a conventional prefix, for example `feat/catalog-export`,
`fix/ltfs-retry`, or `docs/operator-guide`.

Run focused tests for the behavior you changed while developing. Before opening
a pull request, run the complete suite on Linux with Python 3.11:

```console
PYTHONPATH=src python3.11 -m unittest discover -s tests -v
```

Keep each commit focused on one coherent change. Do not mix refactoring,
formatting, generated files, diagnostic captures, or unrelated documentation
updates into a functional change.

## Documentation and pull requests

Product documentation is maintained in English only. Update the canonical
English page for changes to supported behavior, commands, safety constraints,
or operator workflows; keep command names, options, paths, event names, labels,
and protocol values technically identical.

Pull requests should describe their scope, safety impact, tests run and their
results, documentation changes, and any compatibility or catalog-schema impact.
Use the pull-request template as the review evidence checklist. Never include
credentials, private paths, catalog databases, operational logs, media labels,
or HPE support tickets in a branch, commit, issue, or pull request.

The LTFS driver is maintained in
[Halino/lto-ltfs-driver](https://github.com/Halino/lto-ltfs-driver); submit driver
changes there. Follow [Linux development](docs/en/development.md) and the
[release process](docs/en/release-process.md) for the distinct source,
package, signing and qualification gates. Updating documentation on `linux`
does not move an already published source tag or qualify its RPMs.
