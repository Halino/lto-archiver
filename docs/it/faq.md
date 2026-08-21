# FAQ

**Perche close LTFS puo essere lungo?** `CopyFileEx` puo attendere provider;
StoreOpen puo ancora flushare cache/metadata. Attendere `close.complete`.

**Explorer chiude diversamente?** App usa `CopyFileEx` Windows, stesso percorso
copia sistema, ma Explorer non e strumento operatore su nastro montato.

**Si possono differire handle?** No. App possiede/chiude handle, non lo
trasferisce a StoreOpen; un file per volta, nessuna coda finale handle.

**Perche unmount non ha timeout?** StoreOpen possiede sync indice LTFS, rilascio
lettera/eject. Timeout forzato non completa sicuro; attendere `unmount.progress`.

**Linee/assi grafico?** Media nastro effettiva include tempo. Cache LTFS e
separata, puo superare velocita nastro. Cinque minuti: campioni 1 secondo, buchi
cache mancanti, scale sinistra/destra 0/50/100%.

**Quando pulire testina?** Solo LED Clean lampeggiante o TapeAlert/supporto
`Clean Now`, `Clean Periodic`, `Clean requested`; `C7978A`, mai tamponi/preventiva.

**Disabilitare Defender?** No: solo allow-list CFA stretta eseguibili.

**Job sono FIFO?** No. Salvato richiede avvio esplicito; `run.lock` non scheduler.

**File puo attraversare nastri?** No; piano lo mantiene in un blocco nastro.

**Software HPE incluso?** No: StoreOpen, driver, firmware, L&TT/installer sono
prerequisiti esterni, non redistribuiti.
