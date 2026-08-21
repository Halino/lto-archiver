# Processo release

Questo e lavoro repository, mai procedura server produzione. Tag 0.11.26:
`v0.11.26`; titolo `LTO Archiver 0.11.26`.

1. Su workstation build inattiva allineare punti versione, lanciare unittest
   completo in [sviluppo](development.md), poi controllare file legali/notices.
2. Builder Task 7 finale testa salvo skip, build GUI/CLI, firma opzionale solo
   con entrambi parametri, SHA-256, ZIP. Produce `release/LTO-Archiver-0.11.26.zip` e
   `release/LTO-Archiver-0.11.26.zip.sha256`. Checksum non significa firmato.
3. Verificare presenza/versione eseguibili, installer/CFA, docs/licenza/notice,
   hash ZIP, assenza stato/log/database/segreti/path privati/software HPE. Mai
   pubblicare artefatto incerto. Mismatch verifier, contenuto vietato o
   eseguibile inatteso e nonzero e blocca pubblicazione.
4. **Precondizione:** applicare l'intero blocco comandi solo nell'**albero
   pubblico finale 0.11.26 dopo Tasks 7–9** quando file tool/workflow sono
   presenti. Nel **worktree intermedio corrente**, non eseguirlo. Sono tool
   repository, mai comandi applicazione/produzione. Su Windows ogni comando
   riuscito sotto restituisce uscita 0; failure verifier/auditor esce nonzero e
   blocca pubblicazione:

   ```powershell
   & '.\scripts\build-release.ps1' -Version 0.11.26
   & .\scripts\verify-release.ps1 -Version 0.11.26 -ReleaseDirectory .\release
   & .\.build-venv\Scripts\python.exe scripts\build-public-snapshot.py `
     --root . --manifest public-files.txt --target C:\Temp\lto-archiver-public
   & .\.build-venv\Scripts\python.exe scripts\audit-public-content.py `
     --manifest public-files.txt --root .
   & .\.build-venv\Scripts\python.exe scripts\audit-public-content.py `
     'release\LTO-Archiver-0.11.26.zip'
   & .\.build-venv\Scripts\python.exe scripts\audit-public-content.py `
     --manifest public-files.txt --root . --git-history
   ```

   Verifier controlla checksum archivio, estrazione temporanea, file esatti,
   versioni/hash binari, contenuto vietato. Builder consuma `public-files.txt`
   ordinato/normalizzato, rifiuta path insicuri, copia solo allow-list, non scrive
   Git. Auditor scansiona directory/ZIP/history, redige valori nei finding, esce
   0 solo senza finding; ogni finding esce nonzero e blocca pubblicazione.
5. Creare tag dopo controlli. Task 9 CI esegue `actions/checkout@v4` e
   `actions/setup-python@v5` su `windows-latest`, Python 3.11, `pip check`,
   unittest completo/audit su push/PR `main` con `contents: read`. Workflow
   `v*.*.*` valida tag/versione, build, verifica, audit, poi `gh release create`
   con solo `contents: write` e `GH_TOKEN` solo step release. Il job release usa:

   ```powershell
   gh release create $env:GITHUB_REF_NAME `
     "release/LTO-Archiver-$version.zip" `
     "release/LTO-Archiver-$version.zip.sha256" `
     --title "LTO Archiver $version" `
     --notes-file "docs/release-notes-$version.md" `
     --verify-tag
   ```

   Se parser YAML locale disponibile, analizzare entrambi workflow. Altrimenti
   sintassi YAML locale non e confermata: usare parser workflow GitHub dopo primo
   push e non dichiarare validazione locale. Verificare stato remoto incerto sola
   lettura prima retry.

Rollback finisce al confine release: non sovrascrivere install live, alterare
history/remote GitLab privato, eliminare repo pubblico parziale, operare server.
Build/verifier/audit/CI falliti o mismatch tag/versione non creano release
approvata. Non sovrascrivere install live, eliminare repo pubblico parziale,
ritentare pubblicazione alla cieca; riportare stato esatto per riparazione.
