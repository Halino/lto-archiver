# Contributing to LTO Archiver

Thank you for helping improve LTO Archiver. This project manages backup and
catalog workflows around LTFS tape media, so every change must preserve safe,
explicit handling of destructive and privileged operations.

## Development environment

- Use Python 3.11.
- Develop and run the test suite on Windows. The project supports Windows
  workflows and its tests exercise Windows PowerShell wrappers.
- Install the pinned development/build dependencies documented by the project
  before running tests.

## Branches, tests, and commits

Create a short-lived branch from the current default branch. Use a descriptive
lowercase name with a conventional prefix, for example `feat/catalog-export`,
`fix/ltfs-retry`, or `docs/italian-guide`.

Run focused tests for the behavior you changed while developing. Before opening
a pull request, run the complete suite on Windows:

```powershell
$env:PYTHONPATH = 'src'
python -m unittest discover -s tests -v
```

Keep each commit focused on one coherent change. Do not mix refactoring,
formatting, generated files, diagnostic captures, or unrelated documentation
updates into a functional change.

## Documentation and pull requests

Product documentation is maintained in English and Italian. Update both
languages for changes to supported behavior, commands, safety constraints, or
operator workflows; keep command names, options, paths, event names, and safety
terminology technically identical. Community governance files may remain
English-first.

Pull requests should describe their scope, safety impact, tests run and their
results, documentation changes, and any compatibility or catalog-schema impact.
Use the pull-request template as the review evidence checklist. Never include
credentials, private paths, catalog databases, operational logs, media labels,
or HPE support tickets in a branch, commit, issue, or pull request.
