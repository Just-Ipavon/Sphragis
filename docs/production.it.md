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

```python
from sphragis import Verifier, SqliteCounterStore, build_diversified_keys, EnvSecretsBackend
verifier = Verifier(build_diversified_keys(EnvSecretsBackend()),
                    SqliteCounterStore("counters.db"))
```

Qualsiasi oggetto che implementa il protocollo `CounterBackend` (`last_counter`,
`check_and_advance`) è un drop-in.

## Scalare a Postgres

La stessa logica è un singolo statement atomico:

```sql
INSERT INTO counters (uid, counter) VALUES ($1, $2)
ON CONFLICT (uid) DO UPDATE SET counter = excluded.counter
WHERE excluded.counter > counters.counter;
```

Tratta "0 righe modificate" come un replay. Questo dà scalabilità orizzontale
con la stessa garanzia anti-rollback.

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
- [ ] Floor Postgres (o equivalente) con update condizionale atomico
- [x] Rate limiting sull'endpoint di verifica (per IP + per UID autentico; in-process, vedi [API](api.it.md#rate-limiting))
- [x] Log strutturati + alert su `CLONE_LIKELY`
- [ ] Rate limiter condiviso (es. Redis) per deployment multi-replica
- [ ] Gestione del rollover del `SDMReadCtr` a 24 bit
- [ ] Decidere il supporto a `SDMENCFileData` dalla configurazione reale del tag
- [ ] Validazione end-to-end su tag fisici
