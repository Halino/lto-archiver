# Sviluppo, test e rilascio

## Ambiente

Il runtime applicativo usa la libreria standard Python. La build Windows usa PyInstaller nell'ambiente `.build-venv`.

## Test

```powershell
$env:PYTHONPATH = 'src'
& '.\.build-venv\Scripts\python.exe' -m unittest discover -s tests -v
```

I test simulano catalogo, SMB e LTFS in directory temporanee. Non richiedono un drive. Le modifiche al percorso di copia devono includere almeno:

- test del comportamento prima e dopo una scrittura bloccante;
- propagazione dell'evento dal motore;
- rappresentazione GUI senza avanzamento fittizio;
- regressione su interruzione, cancellazione del file incompleto e commit dopo unmount.

## Build

Aggiornare coerentemente versione Python, `pyproject.toml` e risorse Windows, quindi eseguire:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
  '.\scripts\build-release.ps1' -Version 0.11.26
```

Lo script esegue i test, genera GUI e CLI, calcola gli SHA-256, aggiunge installer/configuratore/documentazione e produce `release\LTO-Archiver-0.11.26.zip`.

## Verifica del rilascio

Controllare:

1. esito dell'intera suite;
2. `FileVersion` e `ProductVersion` di entrambi gli eseguibili;
3. corrispondenza degli hash nel pacchetto;
4. presenza di installer, configuratore CFA e `INSTALLAZIONE.md`;
5. installazione su server inattivo;
6. `--version`, `catalog check` e avvio GUI;
7. prova funzionale con heartbeat pendente e successivo avanzamento confermato.

## Distribuzione sicura

Non sostituire gli eseguibili se un job e in `formatting`, `mounting`, `writing` o `unmounting`. Attendere la chiusura di StoreOpen e la scomparsa del volume LTFS. L'installer deve essere eseguito elevato e deve conservare lo stato sotto `C:\ProgramData\LtoBackupManager`.

La firma Authenticode e supportata da `build-release.ps1` tramite `-SignTool` e `-CertificateSha1`. Senza certificato il pacchetto rimane verificabile tramite SHA-256, ma puo ricevere una reputazione inferiore dai sistemi endpoint.
