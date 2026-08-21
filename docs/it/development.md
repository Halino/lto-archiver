# Sviluppo

Sviluppare su Windows Server 2022 x64 con Python 3.11; hardware non serve ai
test e drive produzione non sono fixture di sviluppo.

```powershell
py -3.11 -m venv .build-venv
& .\.build-venv\Scripts\Activate.ps1
& .\.build-venv\Scripts\python.exe -m pip install --upgrade pip
& .\.build-venv\Scripts\python.exe -m pip install -r requirements-build.txt
$env:PYTHONPATH = 'src'
& .\.build-venv\Scripts\python.exe -m unittest discover -s tests -v
& .\.build-venv\Scripts\python.exe -m unittest tests.test_docs tests.test_cli tests.test_entry -v
```

`requirements-build.txt` fissa PyInstaller. Test focalizzato, stesso runtime:
`-m unittest tests.test_cli.CliTests -v`. Per GUI/CLI:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-release.ps1 -Version 0.11.26
```

I punti versione sono `src/ltobackup/__init__.py`, `pyproject.toml`, entrambi
`packaging/version_info*.txt`. Prima snapshot pubblico controllare LICENSE,
NOTICE, THIRD_PARTY_NOTICES, metadata, README versione/licenza.

## Tool repository release 0.11.26

Applicare l'intero blocco comandi **solo nell'albero pubblico finale 0.11.26
dopo Tasks 7–9** quando i file tool sono presenti. Nel **worktree intermedio
corrente** non sono disponibili: non eseguirli. Sono tool repository, mai
comandi applicazione/produzione.

```powershell
& .\scripts\build-release.ps1 -Version 0.11.26
& .\scripts\verify-release.ps1 -Version 0.11.26 -ReleaseDirectory .\release

& .\.build-venv\Scripts\python.exe scripts\build-public-snapshot.py `
  --root . --manifest public-files.txt --target C:\Temp\lto-archiver-public
& .\.build-venv\Scripts\python.exe scripts\audit-public-content.py `
  --manifest public-files.txt --root .
& .\.build-venv\Scripts\python.exe scripts\audit-public-content.py `
  C:\Temp\lto-archiver-public
& .\.build-venv\Scripts\python.exe scripts\audit-public-content.py `
  'release\LTO-Archiver-0.11.26.zip'
& .\.build-venv\Scripts\python.exe scripts\audit-public-content.py `
  --manifest public-files.txt --root . --git-history
```

`verify-release.ps1` accetta `-Version` obbligatorio e `-ReleaseDirectory`
opzionale, verifica ZIP/checksum, estrae solo in propria directory temporanea,
controlla file/versioni/hash binari, rifiuta stato vietato/eseguibili inattesi,
poi rimuove quella directory. Builder usa `public-files.txt` ordinato/normalizzato,
rifiuta path/target insicuri, copia solo allow-list, non scrive Git. Auditor
accetta directory/ZIP e `--git-history`, redige finding, esce 0 solo pulito;
ogni finding esce nonzero e blocca pubblicazione.

GitHub Actions Task 9 usa `actions/checkout@v4`, `actions/setup-python@v5`,
`windows-latest`, Python 3.11, `pip check`, unittest completo, audit su push/PR
`main` con `contents: read`. Release tag `v*.*.*` verifica versione, build,
verifica, audit, poi `gh release create` con solo `contents: write`; `GH_TOKEN`
solo step release. Test prima comportamento, registrare RED, fixture sintetiche,
poi controlli focalizzati/completi. Mai committare ZIP/build/stato/log/cataloghi/segreti.
