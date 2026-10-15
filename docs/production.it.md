# Produzione e deployment

*[English](production.md) · Italiano*

Sphragis è il **motore di verifica generico e open**. Un deployment reale ci
costruisce sopra il proprio prodotto (provisioning, logica di business, UI) in
un codebase separato. Questo documento riguarda l'indurimento del motore stesso.

## Floor anti-replay atomico

Il floor del contatore di letture è il meccanismo anti-replay / anti-rollback, e
deve essere corretto sotto concorrenza. `SqliteCounterStore` impone la monotonìa
dentro una transazione serializzata:

- `BEGIN IMMEDIATE` prende subito il write lock, così la sequenza
  leggi-poi-scrivi-condizionale non può interleavarsi (niente TOCTOU) tra thread
  **e** processi.
- WAL mantiene i lettori non bloccanti; `busy_timeout` fa attendere i writer.
- Una connessione per thread (una singola connessione non deve eseguire
  statement interleaved da più thread).
- `synchronous=FULL`: un avanzamento del floor confermato sopravvive a un calo
  di corrente (con `NORMAL` le ultime transazioni del WAL potrebbero tornare
  indietro e i loro tap verificare di nuovo). Il file del database viene creato
  leggibile solo dal proprietario.

Il `CounterStore` JSON usato dagli strumenti da riga di comando è sicuro per
pochi processi su un host: ogni modifica rilegge il file sotto un `flock`
esclusivo, viene sincronizzata su disco (file e cartella) prima che cambi la
memoria, e un file vuoto o corrotto viene rifiutato invece di essere letto
come "nessun floor". Non è pensato per un servizio: lì usa SQLite o Postgres.

```python
from sphragis import Verifier, SqliteCounterStore, build_diversified_keys, EnvSecretsBackend
verifier = Verifier(build_diversified_keys(EnvSecretsBackend()),
                    SqliteCounterStore("counters.db"))
```

Qualsiasi oggetto che implementa il protocollo `CounterBackend` (`last_counter`,
`check_and_advance`) è un drop-in.

## Scalare a Postgres

Più host hanno bisogno di un unico database condiviso. `sphragis.pgstore`
(extra opzionale: `pip install "sphragis[pg]"`, psycopg 3) implementa gli
stessi contratti su Postgres:

- **`PostgresCounterStore`**: `check_and_advance` è un'unica istruzione
  atomica; l'upsert blocca la riga in conflitto, quindi due host in gara sullo
  stesso UID non possono accettare entrambi un contatore. Nessuna riga
  restituita significa replay o rollback:

  ```sql
  INSERT INTO sphragis_counters AS c (uid, counter, updated_at) VALUES ($1, $2, $3)
  ON CONFLICT (uid) DO UPDATE SET counter = EXCLUDED.counter, updated_at = EXCLUDED.updated_at
  WHERE c.counter < EXCLUDED.counter
  RETURNING c.counter;
  ```

  È anche il registro dei tap dell'analyzer: `record_tap` aggiunge il
  contatore a `sphragis_tap_counters` e fa avanzare il floor in un'unica
  transazione, serializzata per UID con un advisory lock (vedi
  [clone detection](clone-detection.it.md#il-registro-dei-tap)).

- **`PostgresObservationStore`**: `observe` legge la cronologia precedente,
  aggiunge il tap e la accorcia in un'unica transazione, serializzata per UID
  con un advisory lock a livello di transazione.
- **`PostgresAlertSink`**: l'audit trail degli alert, condiviso da tutte le
  repliche.

Le tabelle (`sphragis_counters`, `sphragis_tap_counters`,
`sphragis_tap_ledgers`, `sphragis_observations`, `sphragis_alerts`) sono create
al primo uso. Il registro dei tap cresce di una piccola riga per ogni tap
accettato; i floor esistenti continuano a funzionare (i contatori sotto il
floor che un UID aveva quando è iniziato il suo registro risultano `REPLAY`). Ogni thread ha la sua connessione; una connessione
interrotta viene sostituita alla chiamata successiva e gli errori si
propagano, quindi una verifica fallisce in modo chiuso invece di saltare il
floor.

```python
from sphragis import PostgresCounterStore, Verifier, build_diversified_keys, EnvSecretsBackend
verifier = Verifier(build_diversified_keys(EnvSecretsBackend()),
                    PostgresCounterStore("postgresql://sphragis@db.internal/sphragis"))
```

L'API REST passa a questi backend quando è impostata `SPHRAGIS_DB_URL` (vedi
[API](api.it.md#configurazione)). Tieni la password fuori dall'URL: libpq legge
`PGPASSWORD` o `~/.pgpass`.

La suite di test esegue un'unica suite di conformità su SQLite e Postgres,
compresi molti thread e più processi in gara sullo stesso UID
(`tests/test_backends.py`; imposta `SPHRAGIS_TEST_PG_DSN`, la CI avvia un
servizio Postgres).

## Chiavi

Carica le chiavi da un KMS/HSM gestito tramite un `SecretsBackend` (vedi
[gestione chiavi](key-management.it.md)). Mai committare materiale chiave; mai
hardcodarlo.

## Osservabilità

Un backend anti-contraffazione di produzione non dovrebbe restituire un booleano
silenzioso. L'[API REST](api.it.md) include:

- un evento di log JSON strutturato per ogni verifica (classe, punteggio,
  segnali, UID pseudonimizzato, event id), mai `picc_data` o `cmac`;
- **alert su `CLONE_LIKELY`** tramite `AlertSink` intercambiabili (log CRITICAL,
  webhook firmato HMAC);
- un audit trail durevole degli eventi segnalati (`SqliteAlertSink`) per le
  indagini.

Le metriche si possono ricavare dal flusso di log (conteggio per
`classification`).

## Cronologia condivisa del rilevatore

La cronologia per UID del rilevatore passa da un `ObservationStore`.
`SqliteObservationStore` la rende durevole e condivisa da tutti i processi
dell'host, con un `observe()` atomico, così più worker valutano un unico flusso
coerente. Vedi [la documentazione API](api.it.md#scalabilità-orizzontale-cronologia-condivisa-del-rilevatore).

## Checklist di indurimento

- [ ] Chiavi in KMS/HSM, non in env su host a lunga vita
- [x] Floor Postgres con update condizionale atomico, cronologia e audit trail condivisi
- [x] Rate limiting sull'endpoint di verifica (per IP + per UID autentico; in-process, vedi [API](api.it.md#rate-limiting))
- [x] Log strutturati + alert su `CLONE_LIKELY`
- [ ] Rate limiter condiviso (es. Redis) per deployment multi-replica
- [ ] Gestione del rollover del `SDMReadCtr` a 24 bit
- [x] Verifica e provisioning `SDMENCFileData` (validati su un tag fisico)
- [x] Validazione end-to-end su tag fisici
