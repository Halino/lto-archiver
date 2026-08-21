# Third-Party Notices

This inventory covers the PyInstaller build environment reviewed for LTO
Archiver 0.11.26. The project itself has no third-party runtime Python package
dependencies. The release executables are produced from the standard-library
application source using PyInstaller. Exact package versions and licensing
claims below were taken from the installed Windows build environment's package
metadata and license files.

## Included in release executables

### PyInstaller bootloader — PyInstaller 6.22.0

- Purpose: builds the Windows executables; its compiled bootloader and related
  files are embedded in the executables.
- License identifier: `GPL-2.0-or-later WITH Bootloader-exception`.
- Source and license: <https://github.com/pyinstaller/pyinstaller/tree/v6.22.0>
  and <https://github.com/pyinstaller/pyinstaller/blob/v6.22.0/COPYING.txt>.
- Inclusion: the PyInstaller package is a build dependency. Its bootloader and related files are included in the generated executable. The PyInstaller Bootloader Exception permits embedding and distributing those compiled bootloader and related files in combinations with other programs.

## Used only for building

The following packages are installed transitive dependencies of PyInstaller.
They support analysis, hook selection, or package construction and are not
included in the LTO Archiver executable.

### altgraph 0.17.5

- Purpose: Python graph utilities used by PyInstaller during analysis.
- License identifier: `MIT`.
- Source and license: <https://github.com/ronaldoussoren/altgraph>.
- Inclusion: used only for building; not included in the executable.

### packaging 26.3

- Purpose: Python package metadata and version utilities used by PyInstaller
  and PyInstaller community hooks.
- License identifier: `Apache-2.0 OR BSD-2-Clause`.
- Source and license: <https://github.com/pypa/packaging/tree/26.3>.
- Inclusion: used only for building; not included in the executable.

### pyinstaller-hooks-contrib 2026.6

- Purpose: community-maintained PyInstaller hooks available during analysis.
- License identifiers: `GPL-2.0-or-later` for standard hooks and `Apache-2.0`
  for runtime hooks; the applicable identifier depends on the hook file.
- Source and license:
  <https://github.com/pyinstaller/pyinstaller-hooks-contrib/tree/v2026.6>.
- Inclusion: used only for building; the project specification uses no
  community runtime hook, so this package is not included in the executable.

### pefile 2024.8.26

- Purpose: Windows Portable Executable parsing used by PyInstaller.
- License identifier: `MIT`.
- Source and license: <https://github.com/erocarrera/pefile>.
- Inclusion: used only for building; not included in the executable.

### pywin32-ctypes 0.2.3

- Purpose: Windows API compatibility helpers used by PyInstaller.
- License identifier: `BSD-3-Clause`.
- Source and license: <https://github.com/enthought/pywin32-ctypes>.
- Inclusion: used only for building; not included in the executable.

### setuptools 65.5.0

- Purpose: Python package-build support required by PyInstaller.
- License identifier: `MIT`.
- Source and license: <https://github.com/pypa/setuptools/tree/v65.5.0>.
- Inclusion: used only for building; not included in the executable.

## External prerequisites

HPE software is not distributed with LTO Archiver. This includes HPE StoreOpen,
drivers, firmware, Library and Tape Tools, and installers. They remain external
prerequisites obtained separately from their respective owners. HPE, StoreOpen,
StoreEver, and related product names are used only to describe compatibility;
LTO Archiver is independent and is not affiliated with or endorsed by Hewlett
Packard Enterprise.
