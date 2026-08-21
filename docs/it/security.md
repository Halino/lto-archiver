# Sicurezza e privacy

LTO Archiver controlla confini distruttivi nastro e Windows/StoreOpen; non
sostituisce sicurezza OS, SMB, retention o fisica.

## Privilegi e stato sensibile

Installazione/StoreOpen richiedono Administrator; operatori backup diritti SMB
lettura e LTFS scrittura necessari. Limitare `C:\ProgramData\LtoBackupManager`
a SYSTEM/Administrators: config, catalogo, backup, checkpoint, log, `run.lock`
sono sensibili. Export/log richiedono stessa cura. Usare account SMB minimo
privilegio; mai credenziali in argomenti, config, script, issue, history. Non
disabilitare Defender: CFA permette solo percorsi GUI/CLI installati, anche con
GPO/Intune, mai esclusioni ampie cartella/device/processo.

## Controlli distruttivi, identita e percorsi

`NUOVA` e distruttivo e richiede consenso esplicito; `APPEND` conserva dati
committed. L'etichetta del volume LTFS registrata identifica il supporto e un
mismatch blocca l'uso. Il seriale Win32 di StoreOpen/FUSE è diagnostico e può
ripetersi tra cassette. Mai aggirare i controlli o scrivere un nastro errato per
diagnosi. `run.lock`
impedisce mutazione concorrente catalogo/drive, non autorizza uccidere owner.
Trattare sorgente SMB, mount, destinazione restore, output export come non
fidati: verificare posizione/ACL e non seguire redirezioni sorprendenti.

## Release e segnalazioni

SHA-256 confronta download con checksum pubblicato; non prova fiducia/provenienza
ne sostituisce policy endpoint. Binari non firmati sono avviso: validare versione,
checksum, policy publisher/firma, origine release. Authenticode e opzionale,
non implicato dal checksum. Redigere issue pubbliche: mai credenziali, chiavi/
token, cataloghi, log completi, ticket, account, host/IP, path SMB, job ID,
label/seriali, export registro, catture. Segnalare vulnerabilita privatamente
con [`SECURITY.md`](../../SECURITY.md), non issue pubblica prima di triage.
