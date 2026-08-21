# LTO Archiver 0.11.24

## Copia e chiusura LTFS

- I file dati su Windows usano `CopyFileEx`, la stessa classe di copia usata da Explorer.
- SHA-256 viene calcolato in parallelo leggendo la sorgente SMB, senza una seconda lettura dal nastro.
- Ogni file viene chiuso realmente prima di iniziare il successivo. Non esistono handle differiti o una coda di consolidamento a fine lotto.
- La GUI distingue `write.pending`, `close.pending` e `close.complete`, mostra subito i byte pendenti reali e consente di interrompere anche prima del primo callback nativo.
- Un errore del percorso Windows ferma il job esplicitamente: non viene eseguito un secondo tentativo con il writer precedente.

## Creazione, conflitti e avvio dei job

- **Salva job** registra il piano ma non avvia il drive.
- L'avvio o la ripresa richiedono il comando esplicito **Avvia / riprendi job selezionato** e una conferma che mostra drive, prossima cassetta e altri job non conclusi.
- Possono essere salvati piu job indipendenti, ma non esiste una coda FIFO automatica: viene eseguito un solo job alla volta.
- Una libreria gia inclusa in un job non concluso non puo essere aggiunta a un secondo job concorrente; la GUI indica quale job deve essere ripreso, completato o eliminato.

## Compatibilita e aggiornamento

- Versione catalogo: schema 12.
- Versione applicazione e pacchetto: 0.11.24.
- L'aggiornamento conserva catalogo, librerie, cassette e job esistenti. Un tentativo interrotto va reimpostato prima della ripresa della relativa cassetta.
