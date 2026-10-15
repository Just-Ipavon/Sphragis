# Threat model

*[English](THREAT_MODEL.md) · Italiano*

Cosa difende il sistema, come, e — altrettanto importante — cosa **non**
difende. Ogni affermazione qui è supportata da un attacco eseguibile in
`tests/test_adversarial.py`.

## Asset

- **Autenticità di una lettura**: prova che un URL letto è stato prodotto da un
  tag autentico che possiede le chiavi segrete.
- **Unicità del tag fisico**: garanzia che esista **un solo** tag fisico per una
  data identità (l'obiettivo anti-contraffazione).

## Assunzioni di fiducia

- Il backend di verifica è fidato e la sua gestione delle chiavi è sicura.
- `K_SDMMetaReadKey` e `K_SDMFileReadKey` (o la master key da cui sono
  diversificate) sono segrete. La diversificazione per UID (AN10922) limita il
  raggio d'azione se un singolo tag viene compromesso.
- AES-128 e AES-CMAC sono solidi. Ci affidiamo alle primitive, non alla
  segretezza dello schema (che è lo standard pubblico NXP SDM/SUN).

## Avversari e mitigazioni

| # | Capacità dell'avversario | Attacco | Mitigazione | Test |
|---|--------------------------|---------|-------------|------|
| 1 | Osservare e rinviare URL | **Replay** di una lettura catturata | Contatore di letture: già visto → `REPLAY` | `test_replay_attack_is_caught` |
| 2 | Manomettere i byte | **Forgiare** l'SDMMAC (flip di bit) | La verifica CMAC fallisce → `FORGED` | `test_forged_mac_is_caught` |
| 3 | Manomettere i byte | Inviare un MAC **troncato** | Rifiuto strutturale prima di ogni calcolo → `ERROR` (pubblico `INVALID`) | `test_truncated_mac_is_rejected` |
| 4 | Conservare vecchi URL | **Rollback del contatore**: rinviare una lettura più vecchia | Contatore non fresco → `REPLAY`/`CLONE_LIKELY` | `test_counter_rollback_is_caught` |
| 5 | **Estrarre le chiavi**, clone perfetto | Il clone usa il proprio flusso di contatore | **Divergenza** del contatore (valore sotto il massimo mai visto) → `CLONE_LIKELY` | `test_key_clone_caught_by_counter_divergence` |
| 6 | **Estrarre le chiavi**, clone altrove | Clone letto lontano, pochi secondi dopo | **Velocità impossibile** tra lettori → `CLONE_LIKELY` | `test_key_clone_caught_by_impossible_velocity` |
| 7 | Osservazione dei tempi locale | Side-channel sul confronto MAC | Confronto a tempo costante via `hmac.compare_digest` | `test_mac_comparison_correctness`, `test_mac_comparison_uses_non_short_circuiting_primitive` |
| 8 | Interrogare l'API pubblica | Usare il verdetto come **oracolo** per affinare una contraffazione | Il livello pubblico mappa input malformati *e* forgiati su un'unica risposta `INVALID`; niente UID, contatore o dettagli dei segnali | `test_forged_and_malformed_are_indistinguishable_publicly` |
| 9 | Inviare richieste arbitrarie | **Falsificare il `reader_id`** per simulare o eludere la velocità impossibile | `reader_id` ricavato solo dal token autenticato del lettore; campo nel body rifiutato, parametro in query ignorato; tempo dall'orologio del server | `test_query_reader_id_cannot_fake_velocity`, `test_post_rejects_client_supplied_reader_and_oversized_url`, `test_service_uses_server_clock_not_client_time` |
| 10 | Inondare l'endpoint | **Esaurimento risorse** / flooding dei log | Token bucket per IP prima della crypto; bucket per UID dopo il MAC (i tap limitati non toccano lo stato); `X-Forwarded-For` solo da proxy fidati | `test_ip_rate_limit_returns_429_with_retry_after`, `test_uid_rate_limit_throttles_authentic_taps`, `test_forwarded_for_ignored_unless_peer_is_trusted_proxy` |
| 11 | Usare cloni su worker diversi | Spezzare il flusso di osservazioni così che nessun worker veda la divergenza | `ObservationStore` condiviso e atomico (SQLite) tra processi | `test_clone_caught_across_workers_sharing_history`, `test_sqlite_observe_is_atomic_under_concurrency` |

L'intuizione chiave per #5–#7: una volta che l'attaccante ha le chiavi, il MAC
non distingue più un clone dall'originale — **solo il comportamento del
contatore nel tempo può**. Per questo il progetto tratta l'analisi del contatore
come un rilevatore con punteggio di prima classe, non un semplice flag di
freschezza.

## Limiti noti (ambito onesto)

- **Un singolo clone usato al posto di un originale perso.** Se il tag autentico
  è distrutto e si legge sempre solo il clone, il suo contatore può sembrare
  perfettamente monotòno. La detection richiede di vedere *entrambi* i tag, o
  informazioni collaterali (posizione/velocità). È un limite fondamentale degli
  schemi basati solo sul contatore, non un bug.
- **Un clone che prima osserva il contatore dell'originale** e resta sempre
  avanti eviterà i segnali di regressione; viene allora preso solo da
  velocità/posizione o dall'eventuale collisione col flusso dell'originale.
- **Attacchi relay / NFC-forwarding** al momento della lettura sono fuori
  ambito — attaccano il canale lettore-tag, non il messaggio SDM.
- **Chiavi di fabbrica sui tag configurati.** `tools/provision.py` da solo
  lascia le chiavi di fabbrica tutte a zero. Con chiavi note chiunque può
  calcolare PICCData e SDMMAC validi, quindi un tag così non prova nulla finché
  `tools/rekey.py` non ha sostituito le sue chiavi con chiavi segrete per UID
  (vedi [gestione chiavi](docs/key-management.it.md#scrivere-le-chiavi-sulle-tag);
  validato su hardware in entrambe le direzioni). Chi possiede `master_admin` può
  riconfigurare tutti i tag: deve stare solo sulla postazione di provisioning.
- **Riscrittura dell'URL della tag.** Il MAC del SUN semplice non copre dati
  statici, quindi un file NDEF liberamente scrivibile permetterebbe a chiunque
  con un telefono di puntare una tag autentica verso un altro sito, mentre
  continua a emettere tap validi. Il provisioning blocca le scritture NDEF in
  ogni layout, sulla chiave 0, 3 o 4 (mai sulle chiavi FileRead o MetaRead che
  hanno i server di verifica). Il blocco ha senso solo dopo che
  `tools/rekey.py` ha sostituito le chiavi a zero.
- **Impersonificazione al cambio chiavi.** Una tag riceve le prime chiavi con
  la chiave di fabbrica pubblica, quindi un dispositivo che si finge una tag
  di fabbrica riceverebbe le chiavi dell'UID che dichiara. `rekey_tag`
  verifica la firma di originalità NXP, rifiuta un UID già nel suo inventario
  che mostra chiavi di fabbrica e richiede che le chiavi dichiarate si
  autentichino (vedi
  [cambiare le chiavi in sicurezza](docs/key-management.it.md#cambiare-le-chiavi-in-sicurezza)).
  Una cattura radio passiva di un cambio chiavi da fabbrica ne rivela comunque
  le chiavi: cambia le chiavi in un luogo schermato, con una fornitura
  controllata.
- **Esaurimento del contatore**: `SDMReadCtr` è a 24 bit. La gestione del
  rollover è una questione di deployment e non è modellata qui.
- `TagAnalyzer` mantiene un floor anti-replay persistente (`CounterBackend`)
  *e* un rilevatore a punteggio la cui cronologia vive in un `ObservationStore`.
  Con lo store in memoria di default lo scoring si ricostruisce dal flusso dal
  vivo dopo un riavvio; `SqliteObservationStore` (usato dall'API) lo rende
  durevole e condiviso tra i processi di un host; con `SPHRAGIS_DB_URL` i
  backend Postgres condividono floor, cronologia e alert tra più host.
- **Budget per UID**: solo i contatori sopra il floor, che richiedono la tag
  fisica, consumano il rate limit per UID; i rinvii di un URL catturato
  ricevono `REPLAY` senza toccarlo, quindi non possono bloccare la tag
  autentica. Chi ha in mano la tag può comunque consumarne il budget con tap
  nuovi.
- **URL trattenuti (pre-play)**: chi legge una tag senza inviare gli URL può
  presentarli più tardi, una volta ciascuno. Sopra il floor verificano come
  autentici (una finestra monouso che chiude solo una sfida del verificatore);
  sotto il floor ognuno genera un `CLONE_LIKELY`, mai di più, perché il
  registro dei tap ricorda ogni contatore inviato.
- **I tap pubblici non portano posizione**: la velocità impossibile richiede
  lettori autenticati; i tap anonimi da telefono alimentano solo i segnali
  basati sul contatore.
- Il rate limiter in-process vale per singola replica; un limite globale
  richiede un backend `RateLimiter` condiviso.

## Rischio residuo

La detection anti-clone è **probabilistica e osservazionale**: aumenta la
confidenza su letture ripetute, non fornisce una garanzia da singola lettura
dell'unicità fisica. L'output con punteggio (`risk_score`, `signals`) è pensato
per alimentare un flusso di revisione/escalation, non per essere un booleano
silenzioso.
