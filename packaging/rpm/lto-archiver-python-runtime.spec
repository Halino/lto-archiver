%global python3_pkgversion 3.11
%global use_source_date_epoch_as_buildtime 1
%global clamp_mtime_to_source_date_epoch 1
%global __brp_python_bytecompile %{nil}
%global __python_provides %{nil}
%global __python_requires %{nil}
%global debug_package %{nil}
%global runtime_site /usr/lib64/lto-archiver/python-runtime/3.11/site-packages

Name:           lto-archiver-python-runtime
Version:        0.11.27
Release:        3%{?dist}
Summary:        Private offline Python runtime for LTO Archiver
License:        BSD-3-Clause AND MIT AND MIT-0 AND MPL-2.0 AND PSF-2.0
URL:            https://lto-archiver.invalid/private
Source0:        %{name}-%{version}.tar.gz
Source1:        %{name}-%{version}.tar.gz.sha256
Source2:        runtime_install.py
Source3:        runtime-payload-authority.json

BuildArch:      x86_64
ExclusiveArch:  x86_64
BuildRequires:  coreutils
BuildRequires:  python3.11
BuildRequires:  /usr/bin/cmp
BuildRequires:  /usr/bin/find
BuildRequires:  /usr/bin/git
BuildRequires:  /usr/bin/gpg
BuildRequires:  /usr/bin/install
BuildRequires:  /usr/bin/mkdir
BuildRequires:  /usr/bin/mktemp
BuildRequires:  /usr/bin/python3.11
BuildRequires:  /usr/bin/rm
BuildRequires:  /usr/bin/rpm
BuildRequires:  /usr/bin/rpmbuild
BuildRequires:  /usr/bin/rpmkeys
BuildRequires:  /usr/bin/rpmsign
BuildRequires:  /usr/bin/sed
BuildRequires:  /usr/bin/sha256sum
BuildRequires:  /usr/bin/sort
BuildRequires:  /usr/bin/wc
Requires:       python3.11

Provides:       bundled(python3.11dist(annotated-doc)) = 0.0.5
Provides:       bundled(python3.11dist(annotated-types)) = 0.8.0
Provides:       bundled(python3.11dist(anyio)) = 4.14.2
Provides:       bundled(python3.11dist(argon2-cffi)) = 25.1.0
Provides:       bundled(python3.11dist(argon2-cffi-bindings)) = 26.1.0
Provides:       bundled(python3.11dist(certifi)) = 2026.7.22
Provides:       bundled(python3.11dist(cffi)) = 2.1.1
Provides:       bundled(python3.11dist(click)) = 8.4.2
Provides:       bundled(python3.11dist(fastapi)) = 0.141.1
Provides:       bundled(python3.11dist(h11)) = 0.16.0
Provides:       bundled(python3.11dist(httpcore)) = 1.0.9
Provides:       bundled(python3.11dist(httpx)) = 0.28.1
Provides:       bundled(python3.11dist(idna)) = 3.19
Provides:       bundled(python3.11dist(jinja2)) = 3.1.6
Provides:       bundled(python3.11dist(markupsafe)) = 3.0.3
Provides:       bundled(python3.11dist(pycparser)) = 3.0
Provides:       bundled(python3.11dist(pydantic)) = 2.13.4
Provides:       bundled(python3.11dist(pydantic-core)) = 2.46.4
Provides:       bundled(python3.11dist(starlette)) = 1.6.0
Provides:       bundled(python3.11dist(typing-extensions)) = 4.16.0
Provides:       bundled(python3.11dist(typing-inspection)) = 0.4.4
Provides:       bundled(python3.11dist(uvicorn)) = 0.52.4

%description
This architecture-specific companion package installs the exact 22-wheel
CPython 3.11 runtime closure used by LTO Archiver. The payload is private to
LTO Archiver and does not satisfy global Python distribution capabilities.

%prep
(cd %{_sourcedir} && /usr/bin/sha256sum --check --strict %{SOURCE1})
%setup -q

%build
# Extraction and byte compilation are intentionally performed in %%install.

%install
/usr/bin/python3.11 -I %{SOURCE2} install-source0 \
    --archive %{SOURCE0} \
    --expected-sha256 %{SOURCE1} \
    --output %{buildroot}%{runtime_site} \
    --installed-root %{runtime_site} \
    --source-date-epoch "$SOURCE_DATE_EPOCH" \
    --expected-python 3.11 \
    --expected-wheel-count 22 \
    --payload-authority %{SOURCE3}

install -d -m0755 %{buildroot}%{_licensedir}/%{name}/components
cp -a licenses/. %{buildroot}%{_licensedir}/%{name}/components/
find %{buildroot}%{_licensedir}/%{name}/components -type d -exec chmod 0755 {} +
find %{buildroot}%{_licensedir}/%{name}/components -type f -exec chmod 0644 {} +
install -pm0644 THIRD_PARTY_NOTICES.md \
    %{buildroot}%{_licensedir}/%{name}/THIRD_PARTY_NOTICES.md
install -Dpm0644 runtime.spdx.json \
    %{buildroot}%{_docdir}/%{name}/runtime.spdx.json
install -Dpm0644 wheel-inventory.json \
    %{buildroot}%{_docdir}/%{name}/wheel-inventory.json
install -Dpm0644 %{SOURCE3} \
    %{buildroot}%{_docdir}/%{name}/runtime-payload-authority.json

%check
test "$(find %{buildroot}%{runtime_site} -type f | wc -l)" -eq 1031
test "$(find %{buildroot}%{runtime_site} -type f -name '*.pyc' | wc -l)" -eq 443
test "$(find %{buildroot}%{runtime_site} -type f -name '*.so' | wc -l)" -eq 4
test -z "$(find %{buildroot}%{runtime_site} \( -type l -o -name '*.pth' \) -print -quit)"
test "$(find %{buildroot}%{_licensedir}/%{name}/components -type f | wc -l)" -eq 22

%files
%dir /usr/lib64/lto-archiver
%dir /usr/lib64/lto-archiver/python-runtime
%dir /usr/lib64/lto-archiver/python-runtime/3.11
%{runtime_site}
%license %{_licensedir}/%{name}
%doc %{_docdir}/%{name}/runtime.spdx.json
%doc %{_docdir}/%{name}/wheel-inventory.json
%doc %{_docdir}/%{name}/runtime-payload-authority.json

%changelog
* Sat Aug 29 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-3
- Correct the private runtime project metadata without changing Source0 or the
  installed runtime payload.

* Sun Aug 23 2026 LTO Archiver Engineering <noreply@example.invalid> - 0.11.27-2
- Add the sealed private CPython 3.11 runtime for EL9 x86_64.
