# API REST di verifica

*[English](api.md) · Italiano*

Front-end HTTP opzionale per il motore: riceve l'URL di un tap e restituisce un
verdetto con punteggio. Scrive anche un evento di log strutturato per ogni
verifica, genera un alert su `CLONE_LIKELY` e applica il rate limiting.

```bash
pip install "sphragis[api]"
export SPHRAGIS_MASTER_FILE=<hex>  SPHRAGIS_META_READ=<hex>  SPHRAGIS_LOG_PSEUDONYM=<hex>
uvicorn --factory sphragis.api:create_app_from_env --host 0.0.0.0 --port 8000 --no-access-log
```

Il pacchetto core continua a dipendere solo da `pycryptodome`. FastAPI e uvicorn
vengono installati solo con l'extra `api`.

**Log di accesso.** Un URL di tap contiene `picc_data` e `cmac`, e un tap mai
verificato resta riutilizzabile da ovunque venga scritto. L'app toglie la query
string dalle righe del log di accesso di uvicorn (`QueryRedactingFilter` su
`uvicorn.access`); `--no-access-log` è ancora più restrittivo. Configura allo
stesso modo l'eventuale reverse proxy davanti (logga il percorso, non la
query).

## Architettura

```
 HTTP ─▶ rate limit IP ─▶ auth lettore ─▶ VerificationService ─▶ livello risposta
                                               │
                     TagAnalyzer (crypto SDM + clone detection)
                     │  ammissione per UID (rate limit, dopo il MAC)
                     │  orologio del server, mai quello del client
                     ├─▶ evento di log JSON (UID pseudonimizzato)
                     └─▶ AlertSink su CLONE_LIKELY (log · SQLite/Postgres · webhook)
```

`VerificationService` (`sphragis/service.py`) non dipende da alcun framework,
quindi si può testare senza HTTP. `sphragis/api/` è un adattatore sottile sopra
di esso.

## Endpoint

| Metodo | Path | Uso |
|--------|------|-----|
| `GET`  | `/t?picc_data=…&cmac=…` | L'URL a cui punta il tag: il telefono lo apre al tap |
| `POST` | `/v1/verify` `{"url": "…"}` | Un'app o un backend inoltra l'URL letto |
| `GET`  | `/healthz` | Sonda di liveness (senza rate limit) |

I verdetti tornano sempre con `200`. Gli altri codici sono `401` (credenziali
non valide), `422` (body malformato o campi sconosciuti) e `429` (rate limit,
con `Retry-After`). Le risposte hanno `Cache-Control: no-store`. La
documentazione interattiva (`/docs`, `/openapi.json`) è disattivata di default.

## Due livelli di risposta

**Pubblico**: chiunque faccia tap sul tag riceve:

```json
{"event_id": "…", "verdict": "GENUINE", "risk_score": 0, "message": "Authentic tag."}
```

`verdict` ∈ `GENUINE`, `SUSPICIOUS`, `REPLAY`, `CLONE_LIKELY`, `INVALID`. Gli
input malformati **e** quelli forgiati diventano entrambi `INVALID` con
punteggio 100. Il livello pubblico non restituisce mai UID, contatore o
dettagli dei segnali. Senza questa regola l'endpoint diventerebbe un oracolo
che dice all'attaccante quale byte del tap forgiato o clonato è sbagliato. Per
lo stesso motivo `risk_score` è fisso per verdetto (`GENUINE` 0, `SUSPICIOUS`
50, gli altri 100); i lettori ricevono il punteggio dell'analizzatore.

Le anteprime dei link (WhatsApp, Telegram, Slack, Discord, Facebook e simili,
riconosciute dallo `User-Agent`) ricevono `{"message": ...}` senza verifica,
così condividere il link in una chat non consuma il tap e la successiva
apertura del proprietario non è un `REPLAY`. Uno `User-Agent` falsificato
ottiene solo la stessa risposta neutra.

**Dettagliato**: con `Authorization: Bearer <token lettore>` la risposta
include anche `classification`, `uid`, `read_counter`, `backend`, `reader_id`, `signals`
(nome, peso, dettaglio), `detail` e `alerted`. I tap forgiati e quelli
malformati ricevono anche qui la stessa risposta (`classification: INVALID`,
niente UID né contatore): distinguerli sarebbe un oracolo sul PICCData
decifrato. Il log conserva la classificazione reale.

Un token errato o malformato viene rifiutato con `401`. La richiesta non viene
declassata in silenzio al livello pubblico.

## Lettori e `reader_id`

Il controllo di velocità impossibile ha bisogno di sapere *dove* è avvenuto il
tap. Il `reader_id` si ricava **solo** dal token autenticato e non viene mai
letto dalla richiesta. Un campo `reader_id` nel body viene rifiutato (`422`);
uno nella query string viene ignorato. Se il client potesse scegliersi il
reader id, un attaccante potrebbe simulare alert di velocità contro un tag
autentico, oppure evitarli per un clone.

I lettori si configurano come coppie `reader-id=sha256(token)`. Vengono salvati
solo gli hash, quindi una configurazione trapelata non espone credenziali:

```bash
python -c "import secrets,hashlib;t=secrets.token_urlsafe(32);print(t, hashlib.sha256(t.encode()).hexdigest())"
export SPHRAGIS_READER_TOKENS="gate-A=<sha256>,gate-B=<sha256>"
```

I tap pubblici dai telefoni non hanno reader id. Alimentano comunque il floor
del contatore e lo scoring di divergenza del contatore, ma non il controllo di
velocità.

## Log strutturati

Viene scritta una riga JSON per verifica su stdout, con il modulo `logging`
della stdlib (`sphragis.logs.JsonFormatter`):

```json
{"ts":"…","level":"WARNING","logger":"sphragis.verify","event":"verification",
 "event_id":"…","classification":"CLONE_LIKELY","risk_score":100,
 "signals":["counter_regression","impossible_velocity"],
 "uid_ref":"h:3f…","read_counter":3,"reader_id":"gate-B","alerted":true}
```

- `uid_ref` è `HMAC-SHA256(log_pseudonym, UID)`. È stabile per ogni tag, quindi
  gli eventi si possono correlare, ma non è reversibile senza la chiave. Usa
  `SPHRAGIS_LOG_UID=plain` solo se nel tuo deployment l'UID non è un dato
  sensibile.
- `picc_data`, `cmac` e il materiale chiave non vengono mai loggati.
- `event_id` viene restituito anche al client, così il supporto può collegare
  la segnalazione di un utente alla riga di log.

## Alert

`CLONE_LIKELY` (configurabile con `SPHRAGIS_ALERT_ON`, es. `CLONE_LIKELY,REPLAY`)
viene inviato a ogni `AlertSink` configurato:

| Sink | Scopo |
|------|-------|
| `LogAlertSink` | Evento `CRITICAL` sul logger `sphragis.alert`. Instradalo verso il sistema di paging |
| `SqliteAlertSink` | Audit trail durevole (tabella `alerts`, `recent(uid_ref=…)`) per le indagini |
| `WebhookAlertSink` | POST HTTPS firmato `X-Sphragis-Signature: sha256=HMAC(secret, ts + "." + body)` |

Chi riceve il webhook deve verificare la firma a tempo costante e rifiutare i
valori di `X-Sphragis-Timestamp` troppo vecchi: `sphragis.alerts.verify_webhook(
secret, timestamp, signature, body)` fa entrambe le cose. Un sink che fallisce
viene loggato e saltato: non blocca mai la verifica né gli altri sink.
`create_app_from_env` esegue il webhook su un worker in background
(`BackgroundAlertSink`, coda limitata), quindi un endpoint lento non ritarda
mai un tap; la consegna ha timeout 2 s e nessun retry, conta solo una risposta
2xx e i redirect sono rifiutati (rigiocherebbero l'alert firmato altrove).
Tieni il sink SQLite o Postgres come archivio di riferimento.

## Rate limiting

- **Per IP del client**, prima di qualsiasi operazione crittografica (default:
  5/s, burst 20).
- **Per UID del tag**, solo per i tap il cui SDMMAC è stato verificato
  (default: 0.2/s, burst 10). Un tap limitato riceve `429` e **non** modifica
  alcuno stato, quindi un tap autentico non consuma il suo valore di
  contatore. Input forgiati non possono esaurire il budget di un tag specifico.
- `X-Forwarded-For` viene considerato solo se il peer diretto è elencato in
  `SPHRAGIS_TRUSTED_PROXIES` (indirizzi o reti CIDR). Si leggono tutte le righe
  dell'header, in ordine, e il client è l'hop non fidato più a destra, quindi
  un proxy che aggiunge la propria riga (HAProxy `option forwardfor`) non può
  essere scavalcato da una riga inviata dal client. I client IPv6 sono limitati
  per /64.
- Il limite per IP e un tetto al body (`SPHRAGIS_MAX_BODY_BYTES`, 8 KiB) si
  applicano prima di interpretare la richiesta: i body troppo grandi ricevono
  `413` senza essere letti per intero, e un JSON non valido conta nel limite
  come ogni altra richiesta.

`TokenBucketLimiter` lavora all'interno di un singolo processo. Con N repliche
il limite effettivo diventa N volte più alto. Per un limite globale, implementa
il protocollo `RateLimiter` su uno store condiviso come Redis.

## Scalabilità orizzontale: cronologia condivisa del rilevatore

Il rilevatore di cloni valuta ogni tap rispetto alla *cronologia* del tag. Se
la cronologia restasse in memoria, ogni worker vedrebbe solo una parte dei tap.
Per questo `create_app_from_env` la salva in `SqliteObservationStore`, nello
stesso database del floor del contatore e degli alert. La chiamata `observe()`
è atomica (legge la cronologia precedente e aggiunge il nuovo tap in un unico
passo), quindi i tap concorrenti vengono valutati l'uno rispetto all'altro. Più
worker uvicorn sullo stesso host condividono la stessa vista. Per più host
imposta `SPHRAGIS_DB_URL`: floor, cronologia e audit trail degli alert stanno
allora in un unico database Postgres condiviso da tutte le repliche (vedi
[produzione](production.it.md#scalare-a-postgres)).

## Configurazione

| Variabile | Default | Significato |
|-----------|---------|-------------|
| `SPHRAGIS_DB_PATH` | `sphragis.db` | File SQLite: floor, cronologia, alert |
| `SPHRAGIS_DB_URL` | nessuno | URL `postgresql://`; sostituisce SQLite per più host (richiede `sphragis[pg]`) |
| `SPHRAGIS_KEY_CONTEXT` | vuoto | Contesto di diversificazione AN10922 |
| `SPHRAGIS_READER_TOKENS` | nessuno | `lettore=sha256hex,…` |
| `SPHRAGIS_TRUSTED_PROXIES` | nessuno | IP o CIDR dei proxy autorizzati a impostare `X-Forwarded-For` |
| `SPHRAGIS_IP_RATE` / `_IP_BURST` | `5` / `20` | bucket per IP |
| `SPHRAGIS_UID_RATE` / `_UID_BURST` | `0.2` / `10` | bucket per tag |
| `SPHRAGIS_MIN_TRAVEL_SECONDS` | `60` | soglia di velocità impossibile |
| `SPHRAGIS_ALERT_ON` | `CLONE_LIKELY` | classificazioni che generano un alert |
| `SPHRAGIS_MAX_BODY_BYTES` | `8192` | body di richiesta più grande accettato |
| `SPHRAGIS_WEBHOOK_URL` | nessuno | webhook degli alert (solo https) |
| `SPHRAGIS_LOG_UID` | `hmac` | `hmac` o `plain` |
| `SPHRAGIS_LOG_LEVEL` | `INFO` | livello di log |
| `SPHRAGIS_BACKENDS` | `ntag424-sun` | backend di verifica da abilitare (`ntag424-sun`, `ntag424-sun-enc`), vedi [backend](backends.it.md) |

Ogni valore viene validato all'avvio: rate, burst e tempo di viaggio devono
essere finiti e positivi, `SPHRAGIS_ALERT_ON` deve elencare classificazioni
note. Un errore di battitura ferma il servizio invece di disattivare in
silenzio un limite o un alert.

I segreti si leggono tramite un `SecretsBackend` (di default
`EnvSecretsBackend`, che si aspetta `SPHRAGIS_<NOME>` in esadecimale):
`master_file` e `meta_read` sono obbligatori, `log_pseudonym` è obbligatorio
in modalità `hmac` e `webhook` è obbligatorio se è impostato l'URL del webhook.
Per usare un KMS, passa il tuo backend a `create_app_from_env(secrets=…)`.

## Limiti noti

- `REPLAY` è anche ciò che vede un utente che **ricarica** la pagina di
  verifica: l'URL è già stato usato. Il messaggio pubblico gli chiede di
  rifare il tap sul tag.
- Solo i contatori sopra il floor consumano il budget per UID di un tag, quindi
  rigiocare un URL catturato non può bloccare la tag autentica; chi ha in mano
  la tag può comunque consumarlo con tap nuovi.
- I tap pubblici non portano informazioni di posizione, quindi il rilevamento
  di velocità richiede lettori autenticati.
