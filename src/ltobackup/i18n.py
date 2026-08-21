from __future__ import annotations

import json
import os
from pathlib import Path


LANGUAGES = {
    "it": "Italiano",
    "en": "English",
    "fr": "Français",
    "de": "Deutsch",
    "es": "Español",
}

ENGLISH = {
    "Panoramica": "Overview",
    "Librerie": "Libraries",
    "Piano cassette": "Tape plan",
    "Job automatici": "Saved jobs",
    "Backup manuale": "Manual backup",
    "Ripristina": "Restore",
    "Esplora backup": "Browse backups",
    "Catalogo": "Catalog",
    "Centro operativo": "Operations center",
    "Librerie sorgente": "Source libraries",
    "Piano del job": "Job tape plan",
    "Job salvati e ripartenza": "Saved jobs and resume",
    "Backup manuale su LTFS": "Manual LTFS backup",
    "Ripristino libreria": "Library restore",
    "Esplora backup offline": "Offline backup browser",
    "Catalogo e cassette": "Catalog and tapes",
    "ARCHIVIO LTO / PANORAMICA": "LTO ARCHIVE / OVERVIEW",
    "Stato dell'archivio e ultime attivita": "Archive status and recent activity",
    "Crea un nuovo job salvato": "Create a saved job",
    "Nessuna libreria selezionata": "No library selected",
    "Librerie cumulative": "Combined libraries",
    "Seleziona...": "Select...",
    "Drive": "Drive",
    "Lettera LTFS": "LTFS drive letter",
    "Automatica (L: o prima libera)": "Automatic (L: or first available)",
    "Prima calcola il Piano cassette, oppure seleziona qui le librerie del job.":
        "Calculate the tape plan first, or select the job libraries here.",
    "Etichette cassette, una per riga (ABC123 oppure ABC123L6). Quelle eccedenti resteranno in riserva futura.":
        "Tape labels, one per line (ABC123 or ABC123L6). Extra tapes remain reserved for future growth.",
    "Confermo: ogni cassetta inserita sara riformattata LTFS e tutti i dati presenti saranno cancellati.":
        "I confirm: every inserted tape will be reformatted as LTFS and its existing data erased.",
    "Il drive non legge l'etichetta adesiva: inserire sempre la cassetta fisica richiesta. Sono accettati supporti nuovi o gia LTFS; le cassette gia catalogate restano protette.":
        "The drive cannot read the adhesive label: always insert the requested physical tape. New or existing LTFS media are accepted; cataloged tapes remain protected.",
    "Salva e avvia il job": "Save and start job",
    "Continuita del job": "Job continuity",
    "Puoi salvare piu job indipendenti. Il drive esegue un job selezionato alla volta; ognuno resta nel catalogo e ricompare a ogni avvio.":
        "You can save multiple independent jobs. The drive runs one selected job at a time; every job stays in the catalog across restarts.",
    "SALVATO": "SAVED",
    "Librerie, etichette e ordine cassette": "Libraries, labels and tape order",
    "CHECKPOINT": "CHECKPOINT",
    "Dopo ogni cassetta completata ed espulsa": "After every completed and ejected tape",
    "CONTINUA": "RESUME",
    "Dal primo supporto non completato": "From the first incomplete tape",
    "Nessun job in esecuzione.": "No job is running.",
    "Velocita nastro: in attesa": "Tape speed: waiting",
    "Telemetria LTFS: in attesa": "LTFS telemetry: waiting",
    "Telemetria LTFS: ferma": "LTFS telemetry: stopped",
    "FINALIZZAZIONE CASSETTA LTFS": "LTFS TAPE FINALIZATION",
    "Inattivo": "Idle",
    "Nessuna finalizzazione in corso": "No finalization in progress",
    "AVANZAMENTO": "PROGRESS",
    "TRASCORSO FASE": "PHASE ELAPSED",
    "ETA FASE": "PHASE ETA",
    "CASSETTA CORRENTE  |  capacita disponibile dopo il mount":
        "CURRENT TAPE  |  capacity available after mount",
    "Disponibile per la scrittura: -": "Available for writing: -",
    "Libero rilevato da LTFS: -": "Free space reported by LTFS: -",
    "Limite applicativo: -  |  Margine operativo: -":
        "Application limit: -  |  Operating margin: -",
    "AZIONI SUL JOB SELEZIONATO": "SELECTED JOB ACTIONS",
    "Riprendi job / aggiungi cassette": "Resume job / add tapes",
    "Lascia vuoto il riquadro etichette per riprendere. Inserisci nuove etichette per accodarle allo stesso job.":
        "Leave the label box empty to resume. Enter new labels to append them to the same job.",
    "Interrompi ora": "Stop now",
    "Interrompi ora ferma la copia al prossimo buffer, elimina dal catalogo l'intero tentativo della cassetta, chiude LTFS e la espelle. Alla ripresa la stessa cassetta viene riformattata e ricomincia da zero.":
        "Stop now halts at the next buffer, discards the current tape attempt, closes LTFS and ejects. On resume, that tape is reformatted and restarted from zero.",
    "Job salvati e checkpoint cassette": "Saved jobs and tape checkpoints",
    "0 job salvati | seleziona il job da gestire": "0 saved jobs | select a job to manage",
    "NESSUN JOB SELEZIONATO": "NO JOB SELECTED",
    "CATALOGO PRONTO": "CATALOG READY",
    "In attesa di una pianificazione": "Waiting for a plan",
    "STATO": "STATUS",
    "CASSETTE": "TAPES",
    "DATI PREVISTI": "PLANNED DATA",
    "DATI COPIATI": "WRITTEN DATA",
    "JOB SALVATI - SELEZIONA QUELLO DA GESTIRE": "SAVED JOBS - SELECT ONE TO MANAGE",
    "Job": "Job",
    "Stato": "Status",
    "Prossima": "Next",
    "Creato": "Created",
    "PERCORSO CASSETTE": "TAPE SEQUENCE",
    "[OK] conclusa   [ORA] intervento richiesto   [ ] successiva   [R] riserva":
        "[OK] done   [NOW] action required   [ ] next   [R] reserve",
    "Passo": "Step",
    "Etichetta fisica": "Physical label",
    "Stato operativo": "Operational status",
    "Previsti": "Planned",
    "Copiati": "Written",
    "Blocco": "Block",
    "FLUSSO OPERATIVO": "WORKFLOW",
    "STRUMENTI": "TOOLS",
    "FILE DIRETTI ¶ú NO TAR": "DIRECT FILES · NO TAR",
}

FRENCH = {
    "Panoramica": "Vue d’ensemble", "Librerie": "Bibliothèques",
    "Piano cassette": "Plan des bandes", "Job automatici": "Tâches enregistrées",
    "Backup manuale": "Sauvegarde manuelle", "Ripristina": "Restaurer",
    "Esplora backup": "Explorer les sauvegardes", "Catalogo": "Catalogue",
    "Centro operativo": "Centre opérationnel", "Librerie sorgente": "Bibliothèques sources",
    "Piano del job": "Plan des bandes de la tâche",
    "Job salvati e ripartenza": "Tâches enregistrées et reprise",
    "Backup manuale su LTFS": "Sauvegarde LTFS manuelle",
    "Ripristino libreria": "Restauration d’une bibliothèque",
    "Esplora backup offline": "Explorateur de sauvegardes hors ligne",
    "Catalogo e cassette": "Catalogue et bandes",
    "Crea un nuovo job salvato": "Créer une tâche enregistrée",
    "Nessuna libreria selezionata": "Aucune bibliothèque sélectionnée",
    "Librerie cumulative": "Bibliothèques combinées", "Seleziona...": "Sélectionner...",
    "Drive": "Lecteur", "Lettera LTFS": "Lettre du lecteur LTFS",
    "Automatica (L: o prima libera)": "Automatique (L: ou première disponible)",
    "Prima calcola il Piano cassette, oppure seleziona qui le librerie del job.":
        "Calculez d’abord le plan des bandes ou sélectionnez ici les bibliothèques.",
    "Etichette cassette, una per riga (ABC123 oppure ABC123L6). Quelle eccedenti resteranno in riserva futura.":
        "Étiquettes des bandes, une par ligne. Les bandes en excès restent en réserve.",
    "Salva e avvia il job": "Enregistrer et démarrer",
    "Continuita del job": "Continuité de la tâche",
    "Nessun job in esecuzione.": "Aucune tâche en cours.",
    "Velocita nastro: in attesa": "Vitesse de la bande : en attente",
    "Telemetria LTFS: in attesa": "Telemetrie LTFS : en attente",
    "Telemetria LTFS: ferma": "Telemetrie LTFS : arretee",
    "FINALIZZAZIONE CASSETTA LTFS": "FINALISATION DE LA BANDE LTFS",
    "Inattivo": "Inactif",
    "Nessuna finalizzazione in corso": "Aucune finalisation en cours",
    "AVANZAMENTO": "AVANCEMENT",
    "TRASCORSO FASE": "TEMPS DE PHASE",
    "ETA FASE": "ETA DE PHASE",
    "CASSETTA CORRENTE  |  capacita disponibile dopo il mount":
        "BANDE ACTUELLE  |  capacité disponible après montage",
    "Disponibile per la scrittura: -": "Disponible pour l’écriture : -",
    "Libero rilevato da LTFS: -": "Espace libre signalé par LTFS : -",
    "Limite applicativo: -  |  Margine operativo: -":
        "Limite applicative : -  |  Marge opérationnelle : -",
    "Riprendi job / aggiungi cassette": "Reprendre / ajouter des bandes",
    "Interrompi ora": "Arrêter maintenant",
    "Job salvati e checkpoint cassette": "Tâches enregistrées et points de reprise",
    "NESSUN JOB SELEZIONATO": "AUCUNE TÂCHE SÉLECTIONNÉE", "STATO": "ÉTAT",
    "CASSETTE": "BANDES", "DATI PREVISTI": "DONNÉES PRÉVUES",
    "DATI COPIATI": "DONNÉES ÉCRITES", "PERCORSO CASSETTE": "SÉQUENCE DES BANDES",
    "Etichetta fisica": "Étiquette physique", "Stato operativo": "État opérationnel",
    "Previsti": "Prévus", "Copiati": "Écrits", "Blocco": "Bloc",
    "FLUSSO OPERATIVO": "FLUX DE TRAVAIL", "STRUMENTI": "OUTILS",
}

GERMAN = {
    "Panoramica": "Übersicht", "Librerie": "Bibliotheken",
    "Piano cassette": "Bandplanung", "Job automatici": "Gespeicherte Jobs",
    "Backup manuale": "Manuelle Sicherung", "Ripristina": "Wiederherstellen",
    "Esplora backup": "Sicherungen durchsuchen", "Catalogo": "Katalog",
    "Centro operativo": "Betriebszentrale", "Librerie sorgente": "Quellbibliotheken",
    "Piano del job": "Bandplanung des Jobs",
    "Job salvati e ripartenza": "Gespeicherte Jobs und Fortsetzung",
    "Backup manuale su LTFS": "Manuelle LTFS-Sicherung",
    "Ripristino libreria": "Bibliothek wiederherstellen",
    "Esplora backup offline": "Offline-Sicherungsbrowser",
    "Catalogo e cassette": "Katalog und Bänder",
    "Crea un nuovo job salvato": "Neuen gespeicherten Job erstellen",
    "Nessuna libreria selezionata": "Keine Bibliothek ausgewählt",
    "Librerie cumulative": "Kombinierte Bibliotheken", "Seleziona...": "Auswählen...",
    "Drive": "Laufwerk", "Lettera LTFS": "LTFS-Laufwerksbuchstabe",
    "Automatica (L: o prima libera)": "Automatisch (L: oder erster freier)",
    "Prima calcola il Piano cassette, oppure seleziona qui le librerie del job.":
        "Zuerst die Bandplanung berechnen oder hier die Bibliotheken auswählen.",
    "Etichette cassette, una per riga (ABC123 oppure ABC123L6). Quelle eccedenti resteranno in riserva futura.":
        "Bandetiketten, eine pro Zeile. Zusätzliche Bänder bleiben als Reserve.",
    "Salva e avvia il job": "Job speichern und starten",
    "Continuita del job": "Job-Fortsetzung", "Nessun job in esecuzione.": "Kein Job aktiv.",
    "Velocita nastro: in attesa": "Bandgeschwindigkeit: wartet",
    "Telemetria LTFS: in attesa": "LTFS-Telemetrie: wartet",
    "Telemetria LTFS: ferma": "LTFS-Telemetrie: gestoppt",
    "FINALIZZAZIONE CASSETTA LTFS": "LTFS-BANDFINALISIERUNG",
    "Inattivo": "Inaktiv",
    "Nessuna finalizzazione in corso": "Keine Finalisierung aktiv",
    "AVANZAMENTO": "FORTSCHRITT",
    "TRASCORSO FASE": "PHASENZEIT",
    "ETA FASE": "PHASEN-ETA",
    "CASSETTA CORRENTE  |  capacita disponibile dopo il mount":
        "AKTUELLES BAND  |  verfügbare Kapazität nach dem Mount",
    "Disponibile per la scrittura: -": "Zum Schreiben verfügbar: -",
    "Libero rilevato da LTFS: -": "Von LTFS gemeldeter freier Speicher: -",
    "Limite applicativo: -  |  Margine operativo: -":
        "Anwendungslimit: -  |  Betriebsreserve: -",
    "Riprendi job / aggiungi cassette": "Job fortsetzen / Bänder hinzufügen",
    "Interrompi ora": "Jetzt stoppen",
    "Job salvati e checkpoint cassette": "Gespeicherte Jobs und Band-Checkpoints",
    "NESSUN JOB SELEZIONATO": "KEIN JOB AUSGEWÄHLT", "STATO": "STATUS",
    "CASSETTE": "BÄNDER", "DATI PREVISTI": "GEPLANTE DATEN",
    "DATI COPIATI": "GESCHRIEBENE DATEN", "PERCORSO CASSETTE": "BANDFOLGE",
    "Etichetta fisica": "Physisches Etikett", "Stato operativo": "Betriebsstatus",
    "Previsti": "Geplant", "Copiati": "Geschrieben", "Blocco": "Block",
    "FLUSSO OPERATIVO": "ARBEITSABLAUF", "STRUMENTI": "WERKZEUGE",
}

SPANISH = {
    "Panoramica": "Resumen", "Librerie": "Bibliotecas",
    "Piano cassette": "Plan de cintas", "Job automatici": "Trabajos guardados",
    "Backup manuale": "Copia manual", "Ripristina": "Restaurar",
    "Esplora backup": "Explorar copias", "Catalogo": "Catálogo",
    "Centro operativo": "Centro de operaciones", "Librerie sorgente": "Bibliotecas de origen",
    "Piano del job": "Plan de cintas del trabajo",
    "Job salvati e ripartenza": "Trabajos guardados y reanudación",
    "Backup manuale su LTFS": "Copia LTFS manual",
    "Ripristino libreria": "Restauración de biblioteca",
    "Esplora backup offline": "Explorador de copias sin conexión",
    "Catalogo e cassette": "Catálogo y cintas",
    "Crea un nuovo job salvato": "Crear un trabajo guardado",
    "Nessuna libreria selezionata": "Ninguna biblioteca seleccionada",
    "Librerie cumulative": "Bibliotecas combinadas", "Seleziona...": "Seleccionar...",
    "Drive": "Unidad", "Lettera LTFS": "Letra de unidad LTFS",
    "Automatica (L: o prima libera)": "Automática (L: o primera disponible)",
    "Prima calcola il Piano cassette, oppure seleziona qui le librerie del job.":
        "Calcula primero el plan de cintas o selecciona aquí las bibliotecas.",
    "Etichette cassette, una per riga (ABC123 oppure ABC123L6). Quelle eccedenti resteranno in riserva futura.":
        "Etiquetas de cinta, una por línea. Las cintas adicionales quedan en reserva.",
    "Salva e avvia il job": "Guardar e iniciar trabajo",
    "Continuita del job": "Continuidad del trabajo",
    "Nessun job in esecuzione.": "No hay ningún trabajo en ejecución.",
    "Velocita nastro: in attesa": "Velocidad de cinta: en espera",
    "Telemetria LTFS: in attesa": "Telemetria LTFS: en espera",
    "Telemetria LTFS: ferma": "Telemetria LTFS: detenida",
    "FINALIZZAZIONE CASSETTA LTFS": "FINALIZACION DE CINTA LTFS",
    "Inattivo": "Inactivo",
    "Nessuna finalizzazione in corso": "No hay finalizacion en curso",
    "AVANZAMENTO": "PROGRESO",
    "TRASCORSO FASE": "TIEMPO DE FASE",
    "ETA FASE": "ETA DE FASE",
    "CASSETTA CORRENTE  |  capacita disponibile dopo il mount":
        "CINTA ACTUAL  |  capacidad disponible tras montar",
    "Disponibile per la scrittura: -": "Disponible para escritura: -",
    "Libero rilevato da LTFS: -": "Espacio libre indicado por LTFS: -",
    "Limite applicativo: -  |  Margine operativo: -":
        "Límite de aplicación: -  |  Margen operativo: -",
    "Riprendi job / aggiungi cassette": "Reanudar / añadir cintas",
    "Interrompi ora": "Detener ahora",
    "Job salvati e checkpoint cassette": "Trabajos guardados y puntos de control",
    "NESSUN JOB SELEZIONATO": "NINGÚN TRABAJO SELECCIONADO", "STATO": "ESTADO",
    "CASSETTE": "CINTAS", "DATI PREVISTI": "DATOS PREVISTOS",
    "DATI COPIATI": "DATOS ESCRITOS", "PERCORSO CASSETTE": "SECUENCIA DE CINTAS",
    "Etichetta fisica": "Etiqueta física", "Stato operativo": "Estado operativo",
    "Previsti": "Previstos", "Copiati": "Escritos", "Blocco": "Bloque",
    "FLUSSO OPERATIVO": "FLUJO DE TRABAJO", "STRUMENTI": "HERRAMIENTAS",
}

FRENCH.update({
    "ARCHIVIO LTO / PANORAMICA": "ARCHIVE LTO / VUE D’ENSEMBLE",
    "Stato dell'archivio e ultime attivita": "État de l’archive et activité récente",
    "Confermo: ogni cassetta inserita sara riformattata LTFS e tutti i dati presenti saranno cancellati.":
        "Je confirme : chaque bande insérée sera reformatée en LTFS et ses données seront effacées.",
    "Il drive non legge l'etichetta adesiva: inserire sempre la cassetta fisica richiesta. Sono accettati supporti nuovi o gia LTFS; le cassette gia catalogate restano protette.":
        "Le lecteur ne lit pas l’étiquette adhésive : insérez toujours la bande demandée. Les médias neufs ou LTFS sont acceptés ; les bandes cataloguées restent protégées.",
    "Puoi salvare piu job indipendenti. Il drive esegue un job selezionato alla volta; ognuno resta nel catalogo e ricompare a ogni avvio.":
        "Plusieurs tâches indépendantes peuvent être enregistrées. Le lecteur en exécute une à la fois et chacune reste dans le catalogue.",
    "SALVATO": "ENREGISTRÉ", "Librerie, etichette e ordine cassette": "Bibliothèques, étiquettes et ordre des bandes",
    "CHECKPOINT": "POINT DE REPRISE", "Dopo ogni cassetta completata ed espulsa": "Après chaque bande terminée et éjectée",
    "CONTINUA": "REPRENDRE", "Dal primo supporto non completato": "À partir de la première bande inachevée",
    "AZIONI SUL JOB SELEZIONATO": "ACTIONS DE LA TÂCHE SÉLECTIONNÉE",
    "Lascia vuoto il riquadro etichette per riprendere. Inserisci nuove etichette per accodarle allo stesso job.":
        "Laissez les étiquettes vides pour reprendre. Saisissez-en de nouvelles pour les ajouter à cette tâche.",
    "Interrompi ora ferma la copia al prossimo buffer, elimina dal catalogo l'intero tentativo della cassetta, chiude LTFS e la espelle. Alla ripresa la stessa cassetta viene riformattata e ricomincia da zero.":
        "L’arrêt intervient au prochain tampon, annule la tentative, ferme LTFS et éjecte la bande. La reprise reformate cette bande et repart de zéro.",
    "0 job salvati | seleziona il job da gestire": "0 tâche enregistrée | sélectionnez une tâche",
    "CATALOGO PRONTO": "CATALOGUE PRÊT", "In attesa di una pianificazione": "En attente d’un plan",
    "JOB SALVATI - SELEZIONA QUELLO DA GESTIRE": "TÂCHES ENREGISTRÉES — SÉLECTIONNEZ-EN UNE",
    "Job": "Tâche", "Stato": "État", "Prossima": "Suivante", "Creato": "Créée", "Passo": "Étape",
    "[OK] conclusa   [ORA] intervento richiesto   [ ] successiva   [R] riserva":
        "[OK] terminée   [MAINT.] action requise   [ ] suivante   [R] réserve",
})

GERMAN.update({
    "ARCHIVIO LTO / PANORAMICA": "LTO-ARCHIV / ÜBERSICHT",
    "Stato dell'archivio e ultime attivita": "Archivstatus und letzte Aktivitäten",
    "Confermo: ogni cassetta inserita sara riformattata LTFS e tutti i dati presenti saranno cancellati.":
        "Ich bestätige: Jedes eingelegte Band wird als LTFS neu formatiert und vorhandene Daten werden gelöscht.",
    "Il drive non legge l'etichetta adesiva: inserire sempre la cassetta fisica richiesta. Sono accettati supporti nuovi o gia LTFS; le cassette gia catalogate restano protette.":
        "Das Laufwerk liest den Aufkleber nicht: Immer das angeforderte Band einlegen. Neue und vorhandene LTFS-Medien werden akzeptiert; katalogisierte Bänder bleiben geschützt.",
    "Puoi salvare piu job indipendenti. Il drive esegue un job selezionato alla volta; ognuno resta nel catalogo e ricompare a ogni avvio.":
        "Mehrere unabhängige Jobs können gespeichert werden. Das Laufwerk führt jeweils einen aus; alle bleiben dauerhaft im Katalog.",
    "SALVATO": "GESPEICHERT", "Librerie, etichette e ordine cassette": "Bibliotheken, Etiketten und Bandreihenfolge",
    "CHECKPOINT": "CHECKPOINT", "Dopo ogni cassetta completata ed espulsa": "Nach jedem abgeschlossenen und ausgeworfenen Band",
    "CONTINUA": "FORTSETZEN", "Dal primo supporto non completato": "Ab dem ersten unvollständigen Band",
    "AZIONI SUL JOB SELEZIONATO": "AKTIONEN FÜR DEN AUSGEWÄHLTEN JOB",
    "Lascia vuoto il riquadro etichette per riprendere. Inserisci nuove etichette per accodarle allo stesso job.":
        "Zum Fortsetzen das Etikettenfeld leer lassen. Neue Etiketten werden an denselben Job angehängt.",
    "Interrompi ora ferma la copia al prossimo buffer, elimina dal catalogo l'intero tentativo della cassetta, chiude LTFS e la espelle. Alla ripresa la stessa cassetta viene riformattata e ricomincia da zero.":
        "Der Stopp erfolgt am nächsten Puffer, verwirft den Bandversuch, schließt LTFS und wirft aus. Beim Fortsetzen wird dieses Band neu formatiert und beginnt bei null.",
    "0 job salvati | seleziona il job da gestire": "0 gespeicherte Jobs | Job auswählen",
    "CATALOGO PRONTO": "KATALOG BEREIT", "In attesa di una pianificazione": "Warten auf eine Planung",
    "JOB SALVATI - SELEZIONA QUELLO DA GESTIRE": "GESPEICHERTE JOBS — JOB AUSWÄHLEN",
    "Job": "Job", "Stato": "Status", "Prossima": "Nächstes", "Creato": "Erstellt", "Passo": "Schritt",
    "[OK] conclusa   [ORA] intervento richiesto   [ ] successiva   [R] riserva":
        "[OK] fertig   [JETZT] Aktion erforderlich   [ ] nächstes   [R] Reserve",
})

SPANISH.update({
    "ARCHIVIO LTO / PANORAMICA": "ARCHIVO LTO / RESUMEN",
    "Stato dell'archivio e ultime attivita": "Estado del archivo y actividad reciente",
    "Confermo: ogni cassetta inserita sara riformattata LTFS e tutti i dati presenti saranno cancellati.":
        "Confirmo: cada cinta insertada se reformateará como LTFS y se borrarán sus datos existentes.",
    "Il drive non legge l'etichetta adesiva: inserire sempre la cassetta fisica richiesta. Sono accettati supporti nuovi o gia LTFS; le cassette gia catalogate restano protette.":
        "La unidad no lee la etiqueta adhesiva: inserta siempre la cinta solicitada. Se aceptan medios nuevos o LTFS; las cintas catalogadas permanecen protegidas.",
    "Puoi salvare piu job indipendenti. Il drive esegue un job selezionato alla volta; ognuno resta nel catalogo e ricompare a ogni avvio.":
        "Puedes guardar varios trabajos independientes. La unidad ejecuta uno cada vez y todos permanecen en el catálogo.",
    "SALVATO": "GUARDADO", "Librerie, etichette e ordine cassette": "Bibliotecas, etiquetas y orden de cintas",
    "CHECKPOINT": "PUNTO DE CONTROL", "Dopo ogni cassetta completata ed espulsa": "Después de cada cinta completada y expulsada",
    "CONTINUA": "REANUDAR", "Dal primo supporto non completato": "Desde la primera cinta incompleta",
    "AZIONI SUL JOB SELEZIONATO": "ACCIONES DEL TRABAJO SELECCIONADO",
    "Lascia vuoto il riquadro etichette per riprendere. Inserisci nuove etichette per accodarle allo stesso job.":
        "Deja las etiquetas vacías para reanudar. Introduce nuevas etiquetas para añadirlas al mismo trabajo.",
    "Interrompi ora ferma la copia al prossimo buffer, elimina dal catalogo l'intero tentativo della cassetta, chiude LTFS e la espelle. Alla ripresa la stessa cassetta viene riformattata e ricomincia da zero.":
        "La parada ocurre en el siguiente búfer, descarta el intento, cierra LTFS y expulsa. Al reanudar, esa cinta se reformatea y empieza desde cero.",
    "0 job salvati | seleziona il job da gestire": "0 trabajos guardados | selecciona un trabajo",
    "CATALOGO PRONTO": "CATÁLOGO LISTO", "In attesa di una pianificazione": "Esperando una planificación",
    "JOB SALVATI - SELEZIONA QUELLO DA GESTIRE": "TRABAJOS GUARDADOS — SELECCIONA UNO",
    "Job": "Trabajo", "Stato": "Estado", "Prossima": "Siguiente", "Creato": "Creado", "Passo": "Paso",
    "[OK] conclusa   [ORA] intervento richiesto   [ ] successiva   [R] riserva":
        "[OK] terminada   [AHORA] requiere acción   [ ] siguiente   [R] reserva",
})

ENGLISH.update({
    "Verifica SHA-256 degli invariati": "Verify unchanged files with SHA-256",
    "Verifica SHA-256 completa attiva: le scansioni possono richiedere molte ore.":
        "Full SHA-256 verification enabled: scans may take many hours.",
    "Verifica rapida attiva: i file invariati sono riconosciuti da dimensione e data.":
        "Fast verification enabled: unchanged files are identified by size and date.",
    "Tipo cassetta": "Tape type", "Capacita LTO": "LTO capacity",
    "Nativa": "Native", "Utilizzabile LTFS": "Usable LTFS",
    "Compressa teorica": "Theoretical compressed", "Barcode": "Barcode",
    "Note": "Notes", "Non supportato": "Not supported",
})
FRENCH.update({
    "Verifica SHA-256 degli invariati": "Vérifier les fichiers inchangés avec SHA-256",
    "Verifica SHA-256 completa attiva: le scansioni possono richiedere molte ore.":
        "Vérification SHA-256 complète activée : l’analyse peut durer plusieurs heures.",
    "Verifica rapida attiva: i file invariati sono riconosciuti da dimensione e data.":
        "Vérification rapide activée : taille et date identifient les fichiers inchangés.",
    "Tipo cassetta": "Type de bande", "Capacita LTO": "Capacite LTO",
    "Nativa": "Native", "Utilizzabile LTFS": "Utilisable LTFS",
    "Compressa teorica": "Compressee theorique", "Barcode": "Code-barres",
    "Note": "Notes", "Non supportato": "Non pris en charge",
})
GERMAN.update({
    "Verifica SHA-256 degli invariati": "Unveränderte Dateien mit SHA-256 prüfen",
    "Verifica SHA-256 completa attiva: le scansioni possono richiedere molte ore.":
        "Vollständige SHA-256-Prüfung aktiv: Scans können viele Stunden dauern.",
    "Verifica rapida attiva: i file invariati sono riconosciuti da dimensione e data.":
        "Schnellprüfung aktiv: unveränderte Dateien werden anhand Größe und Datum erkannt.",
    "Tipo cassetta": "Bandtyp", "Capacita LTO": "LTO-Kapazitat",
    "Nativa": "Nativ", "Utilizzabile LTFS": "Nutzbar mit LTFS",
    "Compressa teorica": "Theoretisch komprimiert", "Barcode": "Barcode",
    "Note": "Hinweise", "Non supportato": "Nicht unterstutzt",
})
SPANISH.update({
    "Verifica SHA-256 degli invariati": "Verificar archivos sin cambios con SHA-256",
    "Verifica SHA-256 completa attiva: le scansioni possono richiedere molte ore.":
        "Verificación SHA-256 completa activada: los análisis pueden tardar muchas horas.",
    "Verifica rapida attiva: i file invariati sono riconosciuti da dimensione e data.":
        "Verificación rápida activada: se usan tamaño y fecha para detectar archivos sin cambios.",
    "Tipo cassetta": "Tipo de cinta", "Capacita LTO": "Capacidad LTO",
    "Nativa": "Nativa", "Utilizzabile LTFS": "Utilizable con LTFS",
    "Compressa teorica": "Comprimida teorica", "Barcode": "Codigo de barras",
    "Note": "Notas", "Non supportato": "No compatible",
})

ENGLISH.update({
    "Rinomina job": "Rename job",
    "Nuovo nome del job:": "New job name:",
    "Nome job": "Job name",
})
FRENCH.update({
    "Rinomina job": "Renommer la tâche",
    "Nuovo nome del job:": "Nouveau nom de la tâche :",
    "Nome job": "Nom de la tâche",
})
GERMAN.update({
    "Rinomina job": "Job umbenennen",
    "Nuovo nome del job:": "Neuer Jobname:",
    "Nome job": "Jobname",
})
SPANISH.update({
    "Rinomina job": "Cambiar nombre",
    "Nuovo nome del job:": "Nuevo nombre del trabajo:",
    "Nome job": "Nombre del trabajo",
})

ENGLISH.update({
    "Reimposta e riprova cassetta": "Reset and retry failed tape",
    "Elimina job": "Delete job",
    "Eliminare il job selezionato?": "Delete the selected job?",
    "Job eliminato": "Job deleted",
    "Il job selezionato non esiste piu nel catalogo.":
        "The selected job no longer exists in the catalog.",
    "Job eliminato dal catalogo; librerie, nastri e backup sono invariati.":
        "Job deleted from the catalog; libraries, tapes and backups are unchanged.",
    "Verranno eliminate soltanto la definizione del job e la sua coda cassette. Librerie, file catalogati, blocchi completati, cassette registrate e dati LTFS non saranno modificati. L'operazione non puo essere annullata.":
        "Only the job definition and its tape queue will be deleted. Libraries, cataloged files, completed blocks, registered tapes and LTFS data will not be changed. This action cannot be undone.",
    "Definizione e coda eliminate. Nessun file, blocco completato, nastro o dato LTFS e stato cancellato.":
        "Definition and queue deleted. No file, completed block, tape or LTFS data was deleted.",
})
FRENCH.update({
    "Reimposta e riprova cassetta": "Reinitialiser et reessayer la bande",
    "Elimina job": "Supprimer la tache",
    "Eliminare il job selezionato?": "Supprimer la tache selectionnee ?",
    "Job eliminato": "Tache supprimee",
    "Il job selezionato non esiste piu nel catalogo.":
        "La tache selectionnee n'existe plus dans le catalogue.",
    "Job eliminato dal catalogo; librerie, nastri e backup sono invariati.":
        "Tache supprimee du catalogue ; bibliotheques, bandes et sauvegardes inchangees.",
    "Verranno eliminate soltanto la definizione del job e la sua coda cassette. Librerie, file catalogati, blocchi completati, cassette registrate e dati LTFS non saranno modificati. L'operazione non puo essere annullata.":
        "Seules la definition de la tache et sa file de bandes seront supprimees. Les bibliotheques, fichiers catalogues, blocs termines, bandes enregistrees et donnees LTFS resteront inchanges. Cette action est irreversible.",
    "Definizione e coda eliminate. Nessun file, blocco completato, nastro o dato LTFS e stato cancellato.":
        "Definition et file supprimees. Aucun fichier, bloc termine, bande ou donnee LTFS n'a ete supprime.",
})
GERMAN.update({
    "Reimposta e riprova cassetta": "Fehlerband zurucksetzen und erneut versuchen",
    "Elimina job": "Job loschen",
    "Eliminare il job selezionato?": "Ausgewahlten Job loschen?",
    "Job eliminato": "Job geloscht",
    "Il job selezionato non esiste piu nel catalogo.":
        "Der ausgewahlte Job ist nicht mehr im Katalog vorhanden.",
    "Job eliminato dal catalogo; librerie, nastri e backup sono invariati.":
        "Job aus dem Katalog geloscht; Bibliotheken, Bander und Backups bleiben unverandert.",
    "Verranno eliminate soltanto la definizione del job e la sua coda cassette. Librerie, file catalogati, blocchi completati, cassette registrate e dati LTFS non saranno modificati. L'operazione non puo essere annullata.":
        "Nur die Jobdefinition und ihre Bandwarteschlange werden geloscht. Bibliotheken, katalogisierte Dateien, abgeschlossene Blocke, registrierte Bander und LTFS-Daten bleiben unverandert. Dies kann nicht ruckgangig gemacht werden.",
    "Definizione e coda eliminate. Nessun file, blocco completato, nastro o dato LTFS e stato cancellato.":
        "Definition und Warteschlange geloscht. Keine Datei, kein abgeschlossener Block, Band oder LTFS-Datum wurde geloscht.",
})
SPANISH.update({
    "Reimposta e riprova cassetta": "Restablecer y reintentar cinta",
    "Elimina job": "Eliminar trabajo",
    "Eliminare il job selezionato?": "Eliminar el trabajo seleccionado?",
    "Job eliminato": "Trabajo eliminado",
    "Il job selezionato non esiste piu nel catalogo.":
        "El trabajo seleccionado ya no existe en el catalogo.",
    "Job eliminato dal catalogo; librerie, nastri e backup sono invariati.":
        "Trabajo eliminado del catalogo; bibliotecas, cintas y copias sin cambios.",
    "Verranno eliminate soltanto la definizione del job e la sua coda cassette. Librerie, file catalogati, blocchi completati, cassette registrate e dati LTFS non saranno modificati. L'operazione non puo essere annullata.":
        "Solo se eliminaran la definicion del trabajo y su cola de cintas. Las bibliotecas, archivos catalogados, bloques completados, cintas registradas y datos LTFS no cambiaran. Esta accion no se puede deshacer.",
    "Definizione e coda eliminate. Nessun file, blocco completato, nastro o dato LTFS e stato cancellato.":
        "Definicion y cola eliminadas. No se elimino ningun archivo, bloque completado, cinta o dato LTFS.",
})

# Complete the labels used by the static desktop workflow. Technical tokens
# such as LTO, AUTO, TAPE0 and drive letters intentionally remain unchanged.
ENGLISH.update({
    " Avvio...": " Starting...", " Catalogo pronto": " Catalog ready",
    "Aggiungi": "Add", "Annulla": "Cancel", "Archivio catalogato": "Cataloged archive",
    "Attività recente": "Recent activity", "Avvio...": "Starting...", "Blocchi": "Blocks",
    "Caricamento...": "Loading...", "Cassetta": "Tape",
    "Catalogo locale  /  OFFLINE": "Local catalog  /  OFFLINE", "Conferma": "Confirm",
    "Copiato": "Written", "Destinazione": "Destination", "Dimensione": "Size",
    "Esempio: \\\\nas\\archivio\\media": "Example: \\\\nas\\archive\\media",
    "FILE DIRETTI · NO TAR": "DIRECT FILES · NO TAR",
    "Il numero cassetta deve coincidere con l'etichetta fisica.": "The tape number must match the physical label.",
    "Il piano usa 2,41 TB, la capacita dati LTFS documentata per LTO-6, e non divide mai un file.":
        "The plan uses the documented 2.41 TB LTO-6 LTFS data capacity and never splits a file.",
    "Includi versioni storiche e record rimossi logicamente": "Include historical versions and logically removed records",
    "Libreria": "Library", "Libreria / cartella / file": "Library / folder / file",
    "Librerie SMB": "SMB libraries", "Librerie incluse nel nuovo job": "Libraries in the new job",
    "Nastri": "Tapes", "Nastri e blocchi": "Tapes and blocks", "Nastri richiesti": "Required tapes",
    "Nessun file catalogato": "No cataloged files",
    "Nessun job salvato. Il primo job creato restera disponibile dopo la chiusura.":
        "No saved jobs. The first job you create remains available after closing the application.",
    "Nessuna": "None", "Nome o parte del percorso": "Name or part of the path",
    "Nuovo blocco di backup": "New backup block", "Percorso SMB o cartella": "SMB path or folder",
    "Percorso consigliato": "Recommended workflow",
    "Pronto. La scrittura usa lo spazio libero reale comunicato dal volume LTFS.":
        "Ready. Writing uses the actual free space reported by the LTFS volume.",
    "Registra": "Register", "Riepilogo librerie": "Library summary",
    "Ripartizione per libreria": "Distribution by library", "Ripristina una libreria": "Restore a library",
    "Scegli una o piu librerie: il calcolo le trattera come un unico job di backup.":
        "Choose one or more libraries: they will be treated as one backup job.",
    "Scheda del file": "File details", "Seleziona tutte": "Select all",
    "Seleziona un file nell'albero o nei risultati.": "Select a file in the tree or results.",
    "Seleziona una libreria e premi Scansiona.": "Select a library and click Scan.",
    "Selezionare una o piu librerie. Il piano cassette sara calcolato sul loro contenuto cumulativo.":
        "Select one or more libraries. The tape plan will use their combined content.",
    "Sequenza cassette": "Tape sequence", "Sfoglia…": "Browse…",
    "Sovrascrivi file diversi già presenti": "Overwrite different existing files",
    "Struttura e posizioni sono disponibili senza inserire alcuna cassetta.":
        "Structure and locations are available without inserting a tape.",
    "Tutte": "All", "apri le cartelle con il triangolo": "open folders with the triangle",
})

FRENCH.update({
    " Avvio...": " Démarrage...", " Catalogo pronto": " Catalogue prêt",
    "Aggiungi": "Ajouter", "Annulla": "Annuler", "Archivio catalogato": "Archive cataloguée",
    "Attività recente": "Activité récente", "Avvio...": "Démarrage...", "Blocchi": "Blocs",
    "Caricamento...": "Chargement...", "Cassetta": "Bande",
    "Catalogo locale  /  OFFLINE": "Catalogue local  /  HORS LIGNE", "Conferma": "Confirmer",
    "Copiato": "Écrit", "Destinazione": "Destination", "Dimensione": "Taille",
    "Esempio: \\\\nas\\archivio\\media": "Exemple : \\\\nas\\archives\\media",
    "FILE DIRETTI · NO TAR": "FICHIERS DIRECTS · SANS TAR",
    "Il numero cassetta deve coincidere con l'etichetta fisica.": "Le numéro doit correspondre à l’étiquette physique.",
    "Il piano usa 2,41 TB, la capacita dati LTFS documentata per LTO-6, e non divide mai un file.":
        "Le plan utilise les 2,41 To LTFS documentés pour LTO-6 et ne fractionne jamais un fichier.",
    "Includi versioni storiche e record rimossi logicamente": "Inclure les versions historiques et les entrées supprimées logiquement",
    "Libreria": "Bibliothèque", "Libreria / cartella / file": "Bibliothèque / dossier / fichier",
    "Librerie SMB": "Bibliothèques SMB", "Librerie incluse nel nuovo job": "Bibliothèques de la nouvelle tâche",
    "Nastri": "Bandes", "Nastri e blocchi": "Bandes et blocs", "Nastri richiesti": "Bandes requises",
    "Nessun file catalogato": "Aucun fichier catalogué",
    "Nessun job salvato. Il primo job creato restera disponibile dopo la chiusura.":
        "Aucune tâche enregistrée. La première tâche créée restera disponible après la fermeture.",
    "Nessuna": "Aucune", "Nome o parte del percorso": "Nom ou partie du chemin",
    "Nuovo blocco di backup": "Nouveau bloc de sauvegarde", "Percorso SMB o cartella": "Chemin SMB ou dossier",
    "Percorso consigliato": "Parcours recommandé",
    "Pronto. La scrittura usa lo spazio libero reale comunicato dal volume LTFS.":
        "Prêt. L’écriture utilise l’espace libre réel signalé par le volume LTFS.",
    "Registra": "Enregistrer", "Riepilogo librerie": "Résumé des bibliothèques",
    "Ripartizione per libreria": "Répartition par bibliothèque", "Ripristina una libreria": "Restaurer une bibliothèque",
    "Scegli una o piu librerie: il calcolo le trattera come un unico job di backup.":
        "Choisissez une ou plusieurs bibliothèques : elles formeront une seule tâche.",
    "Scheda del file": "Détails du fichier", "Seleziona tutte": "Tout sélectionner",
    "Seleziona un file nell'albero o nei risultati.": "Sélectionnez un fichier dans l’arborescence ou les résultats.",
    "Seleziona una libreria e premi Scansiona.": "Sélectionnez une bibliothèque puis cliquez sur Analyser.",
    "Selezionare una o piu librerie. Il piano cassette sara calcolato sul loro contenuto cumulativo.":
        "Sélectionnez une ou plusieurs bibliothèques. Le plan utilisera leur contenu cumulé.",
    "Sequenza cassette": "Séquence des bandes", "Sfoglia…": "Parcourir…",
    "Sovrascrivi file diversi già presenti": "Écraser les fichiers existants différents",
    "Struttura e posizioni sono disponibili senza inserire alcuna cassetta.":
        "La structure et les emplacements sont disponibles sans insérer de bande.",
    "Tutte": "Toutes", "apri le cartelle con il triangolo": "ouvrez les dossiers avec le triangle",
})

GERMAN.update({
    " Avvio...": " Start...", " Catalogo pronto": " Katalog bereit",
    "Aggiungi": "Hinzufügen", "Annulla": "Abbrechen", "Archivio catalogato": "Katalogisiertes Archiv",
    "Attività recente": "Letzte Aktivitäten", "Avvio...": "Start...", "Blocchi": "Blöcke",
    "Caricamento...": "Laden...", "Cassetta": "Band",
    "Catalogo locale  /  OFFLINE": "Lokaler Katalog  /  OFFLINE", "Conferma": "Bestätigen",
    "Copiato": "Geschrieben", "Destinazione": "Ziel", "Dimensione": "Größe",
    "Esempio: \\\\nas\\archivio\\media": "Beispiel: \\\\nas\\archiv\\media",
    "FILE DIRETTI · NO TAR": "DIREKTE DATEIEN · KEIN TAR",
    "Il numero cassetta deve coincidere con l'etichetta fisica.": "Die Bandnummer muss mit dem physischen Etikett übereinstimmen.",
    "Il piano usa 2,41 TB, la capacita dati LTFS documentata per LTO-6, e non divide mai un file.":
        "Der Plan nutzt 2,41 TB LTFS für LTO-6 und teilt keine Datei.",
    "Includi versioni storiche e record rimossi logicamente": "Historische Versionen und logisch entfernte Einträge einbeziehen",
    "Libreria": "Bibliothek", "Libreria / cartella / file": "Bibliothek / Ordner / Datei",
    "Librerie SMB": "SMB-Bibliotheken", "Librerie incluse nel nuovo job": "Bibliotheken im neuen Job",
    "Nastri": "Bänder", "Nastri e blocchi": "Bänder und Blöcke", "Nastri richiesti": "Benötigte Bänder",
    "Nessun file catalogato": "Keine katalogisierten Dateien",
    "Nessun job salvato. Il primo job creato restera disponibile dopo la chiusura.":
        "Keine gespeicherten Jobs. Der erste erstellte Job bleibt nach dem Schließen verfügbar.",
    "Nessuna": "Keine", "Nome o parte del percorso": "Name oder Teil des Pfads",
    "Nuovo blocco di backup": "Neuer Sicherungsblock", "Percorso SMB o cartella": "SMB-Pfad oder Ordner",
    "Percorso consigliato": "Empfohlener Ablauf",
    "Pronto. La scrittura usa lo spazio libero reale comunicato dal volume LTFS.":
        "Bereit. Verwendet wird der tatsächlich vom LTFS-Volume gemeldete freie Speicher.",
    "Registra": "Registrieren", "Riepilogo librerie": "Bibliotheksübersicht",
    "Ripartizione per libreria": "Verteilung nach Bibliothek", "Ripristina una libreria": "Bibliothek wiederherstellen",
    "Scegli una o piu librerie: il calcolo le trattera come un unico job di backup.":
        "Wählen Sie eine oder mehrere Bibliotheken; sie bilden einen Sicherungsjob.",
    "Scheda del file": "Dateidetails", "Seleziona tutte": "Alle auswählen",
    "Seleziona un file nell'albero o nei risultati.": "Wählen Sie eine Datei im Baum oder in den Ergebnissen.",
    "Seleziona una libreria e premi Scansiona.": "Wählen Sie eine Bibliothek und klicken Sie auf Scannen.",
    "Selezionare una o piu librerie. Il piano cassette sara calcolato sul loro contenuto cumulativo.":
        "Wählen Sie eine oder mehrere Bibliotheken. Der Bandplan nutzt deren gesamten Inhalt.",
    "Sequenza cassette": "Bandreihenfolge", "Sfoglia…": "Durchsuchen…",
    "Sovrascrivi file diversi già presenti": "Abweichende vorhandene Dateien überschreiben",
    "Struttura e posizioni sono disponibili senza inserire alcuna cassetta.":
        "Struktur und Speicherorte sind verfügbar, ohne ein Band einzulegen.",
    "Tutte": "Alle", "apri le cartelle con il triangolo": "Ordner mit dem Dreieck öffnen",
})

SPANISH.update({
    " Avvio...": " Iniciando...", " Catalogo pronto": " Catálogo listo",
    "Aggiungi": "Añadir", "Annulla": "Cancelar", "Archivio catalogato": "Archivo catalogado",
    "Attività recente": "Actividad reciente", "Avvio...": "Iniciando...", "Blocchi": "Bloques",
    "Caricamento...": "Cargando...", "Cassetta": "Cinta",
    "Catalogo locale  /  OFFLINE": "Catálogo local  /  SIN CONEXIÓN", "Conferma": "Confirmar",
    "Copiato": "Escrito", "Destinazione": "Destino", "Dimensione": "Tamaño",
    "Esempio: \\\\nas\\archivio\\media": "Ejemplo: \\\\nas\\archivo\\media",
    "FILE DIRETTI · NO TAR": "ARCHIVOS DIRECTOS · SIN TAR",
    "Il numero cassetta deve coincidere con l'etichetta fisica.": "El número debe coincidir con la etiqueta física.",
    "Il piano usa 2,41 TB, la capacita dati LTFS documentata per LTO-6, e non divide mai un file.":
        "El plan usa los 2,41 TB LTFS documentados para LTO-6 y nunca divide un archivo.",
    "Includi versioni storiche e record rimossi logicamente": "Incluir versiones históricas y registros eliminados lógicamente",
    "Libreria": "Biblioteca", "Libreria / cartella / file": "Biblioteca / carpeta / archivo",
    "Librerie SMB": "Bibliotecas SMB", "Librerie incluse nel nuovo job": "Bibliotecas del nuevo trabajo",
    "Nastri": "Cintas", "Nastri e blocchi": "Cintas y bloques", "Nastri richiesti": "Cintas necesarias",
    "Nessun file catalogato": "No hay archivos catalogados",
    "Nessun job salvato. Il primo job creato restera disponibile dopo la chiusura.":
        "No hay trabajos guardados. El primero seguirá disponible al cerrar la aplicación.",
    "Nessuna": "Ninguna", "Nome o parte del percorso": "Nombre o parte de la ruta",
    "Nuovo blocco di backup": "Nuevo bloque de copia", "Percorso SMB o cartella": "Ruta SMB o carpeta",
    "Percorso consigliato": "Flujo recomendado",
    "Pronto. La scrittura usa lo spazio libero reale comunicato dal volume LTFS.":
        "Listo. La escritura usa el espacio libre real indicado por el volumen LTFS.",
    "Registra": "Registrar", "Riepilogo librerie": "Resumen de bibliotecas",
    "Ripartizione per libreria": "Distribución por biblioteca", "Ripristina una libreria": "Restaurar una biblioteca",
    "Scegli una o piu librerie: il calcolo le trattera come un unico job di backup.":
        "Elija una o más bibliotecas: formarán un único trabajo de copia.",
    "Scheda del file": "Detalles del archivo", "Seleziona tutte": "Seleccionar todas",
    "Seleziona un file nell'albero o nei risultati.": "Seleccione un archivo en el árbol o en los resultados.",
    "Seleziona una libreria e premi Scansiona.": "Seleccione una biblioteca y pulse Escanear.",
    "Selezionare una o piu librerie. Il piano cassette sara calcolato sul loro contenuto cumulativo.":
        "Seleccione una o más bibliotecas. El plan usará su contenido combinado.",
    "Sequenza cassette": "Secuencia de cintas", "Sfoglia…": "Examinar…",
    "Sovrascrivi file diversi già presenti": "Sobrescribir archivos existentes diferentes",
    "Struttura e posizioni sono disponibili senza inserire alcuna cassetta.":
        "La estructura y las ubicaciones están disponibles sin insertar ninguna cinta.",
    "Tutte": "Todas", "apri le cartelle con il triangolo": "abra las carpetas con el triángulo",
})

ENGLISH.update({
    "Operazione": "Operation",
    "APPEND - conserva i dati": "APPEND - preserve data",
    "NUOVA - formatta LTFS": "NEW - format LTFS",
    "RISERVA - non formattata": "RESERVE - not formatted",
    "Interrompi ora ferma la copia al prossimo buffer, chiude LTFS e la espelle. Una cassetta NUOVA riparte con formattazione da zero; una cassetta APPEND conserva i blocchi precedenti e riprova soltanto il nuovo ciclo.":
        "Stop now halts at the next buffer, closes LTFS and ejects. A NEW tape restarts with formatting; an APPEND tape preserves previous blocks and retries only the new cycle.",
})
FRENCH.update({
    "Operazione": "Opération",
    "APPEND - conserva i dati": "AJOUT - conserve les données",
    "NUOVA - formatta LTFS": "NOUVELLE - formate LTFS",
    "RISERVA - non formattata": "RÉSERVE - non formatée",
    "Interrompi ora ferma la copia al prossimo buffer, chiude LTFS e la espelle. Una cassetta NUOVA riparte con formattazione da zero; una cassetta APPEND conserva i blocchi precedenti e riprova soltanto il nuovo ciclo.":
        "Arrêter interrompt au prochain tampon, ferme LTFS et éjecte. Une NOUVELLE bande repart après formatage ; une bande en AJOUT conserve les blocs précédents et reprend seulement le nouveau cycle.",
})
GERMAN.update({
    "Operazione": "Vorgang",
    "APPEND - conserva i dati": "ANHÄNGEN - Daten behalten",
    "NUOVA - formatta LTFS": "NEU - LTFS formatieren",
    "RISERVA - non formattata": "RESERVE - nicht formatiert",
    "Interrompi ora ferma la copia al prossimo buffer, chiude LTFS e la espelle. Una cassetta NUOVA riparte con formattazione da zero; una cassetta APPEND conserva i blocchi precedenti e riprova soltanto il nuovo ciclo.":
        "Jetzt stoppen hält am nächsten Puffer an, schließt LTFS und wirft das Band aus. Ein NEUES Band beginnt nach Formatierung neu; beim ANHÄNGEN bleiben frühere Blöcke erhalten und nur der neue Zyklus wird wiederholt.",
})
SPANISH.update({
    "Operazione": "Operación",
    "APPEND - conserva i dati": "ANEXAR - conserva datos",
    "NUOVA - formatta LTFS": "NUEVA - formatea LTFS",
    "RISERVA - non formattata": "RESERVA - sin formatear",
    "Interrompi ora ferma la copia al prossimo buffer, chiude LTFS e la espelle. Una cassetta NUOVA riparte con formattazione da zero; una cassetta APPEND conserva i blocchi precedenti e riprova soltanto il nuovo ciclo.":
        "Detener ahora para en el siguiente búfer, cierra LTFS y expulsa. Una cinta NUEVA reinicia con formateo; una cinta ANEXAR conserva los bloques anteriores y repite solo el ciclo nuevo.",
})

ENGLISH.update({
    "Consento anche di riformattare cassette gia registrate: dopo la formattazione i relativi file e blocchi saranno rimossi dal catalogo.":
        "Also allow reformatting registered tapes: after formatting, their files and blocks will be removed from the catalog.",
    "Il drive non legge l'etichetta adesiva: inserire sempre la cassetta fisica richiesta. Sono accettati supporti nuovi o gia LTFS; le cassette gia catalogate restano protette salvo autorizzazione esplicita.":
        "The drive cannot read the adhesive label: always insert the requested physical tape. New or existing LTFS media are accepted; cataloged tapes remain protected unless explicitly authorized.",
})
FRENCH.update({
    "Consento anche di riformattare cassette gia registrate: dopo la formattazione i relativi file e blocchi saranno rimossi dal catalogo.":
        "Autoriser aussi le reformatage des bandes deja enregistrees : apres le formatage, leurs fichiers et blocs seront supprimes du catalogue.",
    "Il drive non legge l'etichetta adesiva: inserire sempre la cassetta fisica richiesta. Sono accettati supporti nuovi o gia LTFS; le cassette gia catalogate restano protette salvo autorizzazione esplicita.":
        "Le lecteur ne lit pas l'etiquette adhesive : inserez toujours la bande demandee. Les medias neufs ou LTFS sont acceptes ; les bandes catalogues restent protegees sauf autorisation explicite.",
})
GERMAN.update({
    "Consento anche di riformattare cassette gia registrate: dopo la formattazione i relativi file e blocchi saranno rimossi dal catalogo.":
        "Auch das Neuformatieren registrierter Baender zulassen: Nach der Formatierung werden deren Dateien und Bloecke aus dem Katalog entfernt.",
    "Il drive non legge l'etichetta adesiva: inserire sempre la cassetta fisica richiesta. Sono accettati supporti nuovi o gia LTFS; le cassette gia catalogate restano protette salvo autorizzazione esplicita.":
        "Das Laufwerk liest den Aufkleber nicht: Immer das angeforderte Band einlegen. Neue und vorhandene LTFS-Medien werden akzeptiert; katalogisierte Baender bleiben ohne ausdrueckliche Freigabe geschuetzt.",
})
SPANISH.update({
    "Consento anche di riformattare cassette gia registrate: dopo la formattazione i relativi file e blocchi saranno rimossi dal catalogo.":
        "Permitir tambien reformatear cintas registradas: tras el formateo, sus archivos y bloques se eliminaran del catalogo.",
    "Il drive non legge l'etichetta adesiva: inserire sempre la cassetta fisica richiesta. Sono accettati supporti nuovi o gia LTFS; le cassette gia catalogate restano protette salvo autorizzazione esplicita.":
        "La unidad no lee la etiqueta adhesiva: inserta siempre la cinta solicitada. Se aceptan medios nuevos o LTFS; las cintas catalogadas siguen protegidas salvo autorizacion explicita.",
})

ENGLISH.update({
    "Salva il piano, poi avvia esplicitamente il job selezionato":
        "Save the plan, then explicitly start the selected job",
    "Salva job": "Save job",
    "Puoi salvare piu job indipendenti, ma non esiste un avvio FIFO automatico. Il drive esegue soltanto il job che selezioni e avvii esplicitamente.":
        "You can save multiple independent jobs, but there is no automatic FIFO start. The drive runs only the job you explicitly select and start.",
    "SALVA": "SAVE",
    "Il piano resta nel catalogo senza avviare il drive":
        "The plan stays in the catalog without starting the drive",
    "AVVIA": "START",
    "Parte solo il job selezionato dall'operatore":
        "Only the operator-selected job starts",
    "Riprende dal primo supporto non completato":
        "Resumes from the first incomplete tape",
    "Avvia / riprendi job selezionato": "Start / resume selected job",
    "Lascia vuoto il riquadro etichette per avviare o riprendere. Se inserisci etichette, vengono aggiunte allo stesso job prima dell'avvio.":
        "Leave the label box empty to start or resume. Entered labels are added to the same job before it starts.",
})
FRENCH.update({
    "Salva il piano, poi avvia esplicitamente il job selezionato":
        "Enregistrez le plan, puis demarrez explicitement la tache selectionnee",
    "Salva job": "Enregistrer la tache",
    "Puoi salvare piu job indipendenti, ma non esiste un avvio FIFO automatico. Il drive esegue soltanto il job che selezioni e avvii esplicitamente.":
        "Vous pouvez enregistrer plusieurs taches independantes, mais aucun demarrage FIFO n'est automatique. Le lecteur execute uniquement la tache selectionnee et demarree explicitement.",
    "SALVA": "ENREGISTRER",
    "Il piano resta nel catalogo senza avviare il drive":
        "Le plan reste dans le catalogue sans demarrer le lecteur",
    "AVVIA": "DEMARRER",
    "Parte solo il job selezionato dall'operatore":
        "Seule la tache selectionnee par l'operateur demarre",
    "Riprende dal primo supporto non completato":
        "Reprend a partir de la premiere bande incomplete",
    "Avvia / riprendi job selezionato": "Demarrer / reprendre la tache selectionnee",
    "Lascia vuoto il riquadro etichette per avviare o riprendere. Se inserisci etichette, vengono aggiunte allo stesso job prima dell'avvio.":
        "Laissez les etiquettes vides pour demarrer ou reprendre. Les nouvelles etiquettes sont ajoutees a la meme tache avant le demarrage.",
})
GERMAN.update({
    "Salva il piano, poi avvia esplicitamente il job selezionato":
        "Plan speichern und den ausgewaehlten Job danach ausdruecklich starten",
    "Salva job": "Job speichern",
    "Puoi salvare piu job indipendenti, ma non esiste un avvio FIFO automatico. Il drive esegue soltanto il job che selezioni e avvii esplicitamente.":
        "Mehrere unabhaengige Jobs koennen gespeichert werden, aber es gibt keinen automatischen FIFO-Start. Das Laufwerk fuehrt nur den ausdruecklich ausgewaehlten und gestarteten Job aus.",
    "SALVA": "SPEICHERN",
    "Il piano resta nel catalogo senza avviare il drive":
        "Der Plan bleibt im Katalog, ohne das Laufwerk zu starten",
    "AVVIA": "STARTEN",
    "Parte solo il job selezionato dall'operatore":
        "Nur der vom Bediener ausgewaehlte Job startet",
    "Riprende dal primo supporto non completato":
        "Setzt beim ersten unvollstaendigen Band fort",
    "Avvia / riprendi job selezionato": "Ausgewaehlten Job starten / fortsetzen",
    "Lascia vuoto il riquadro etichette per avviare o riprendere. Se inserisci etichette, vengono aggiunte allo stesso job prima dell'avvio.":
        "Das Etikettenfeld zum Starten oder Fortsetzen leer lassen. Neue Etiketten werden vor dem Start demselben Job hinzugefuegt.",
})
SPANISH.update({
    "Salva il piano, poi avvia esplicitamente il job selezionato":
        "Guarda el plan y luego inicia explicitamente el trabajo seleccionado",
    "Salva job": "Guardar trabajo",
    "Puoi salvare piu job indipendenti, ma non esiste un avvio FIFO automatico. Il drive esegue soltanto il job che selezioni e avvii esplicitamente.":
        "Puedes guardar varios trabajos independientes, pero no hay inicio FIFO automatico. La unidad ejecuta solo el trabajo que selecciones e inicies explicitamente.",
    "SALVA": "GUARDAR",
    "Il piano resta nel catalogo senza avviare il drive":
        "El plan permanece en el catalogo sin iniciar la unidad",
    "AVVIA": "INICIAR",
    "Parte solo il job selezionato dall'operatore":
        "Solo inicia el trabajo seleccionado por el operador",
    "Riprende dal primo supporto non completato":
        "Reanuda desde la primera cinta incompleta",
    "Avvia / riprendi job selezionato": "Iniciar / reanudar trabajo seleccionado",
    "Lascia vuoto il riquadro etichette per avviare o riprendere. Se inserisci etichette, vengono aggiunte allo stesso job prima dell'avvio.":
        "Deja las etiquetas vacias para iniciar o reanudar. Las nuevas etiquetas se agregan al mismo trabajo antes de iniciarlo.",
})

TRANSLATIONS = {
    "en": ENGLISH,
    "fr": FRENCH,
    "de": GERMAN,
    "es": SPANISH,
}


class Translator:
    def __init__(self, language: str):
        self.language = language if language in LANGUAGES else "it"

    def __call__(self, text: str) -> str:
        return TRANSLATIONS.get(self.language, {}).get(text, text)


def _preference_file(state_dir: Path) -> Path:
    return Path(state_dir) / "ui-preferences.json"


def load_language(state_dir: Path) -> str:
    try:
        value = json.loads(_preference_file(state_dir).read_text(encoding="utf-8"))
        language = str(value.get("language") or "it")
    except (OSError, ValueError, TypeError, AttributeError):
        return "it"
    return language if language in LANGUAGES else "it"


def save_language(state_dir: Path, language: str) -> None:
    if language not in LANGUAGES:
        raise ValueError(f"Unsupported language: {language}")
    state = Path(state_dir)
    state.mkdir(parents=True, exist_ok=True)
    target = _preference_file(state)
    temporary = target.with_suffix(".json.tmp")
    temporary.write_text(
        json.dumps({"language": language}, indent=2) + "\n", encoding="utf-8"
    )
    os.replace(temporary, target)
