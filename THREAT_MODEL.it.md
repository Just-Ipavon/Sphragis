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
| 3 | Manomettere i byte | Inviare un MAC **troncato** | Rifiuto strutturale + CMAC → `FORGED` | `test_truncated_mac_is_rejected` |
| 4 | Conservare vecchi URL | **Rollback del contatore**: rinviare una lettura più vecchia | Contatore non fresco → `REPLAY`/`CLONE_LIKELY` | `test_counter_rollback_is_caught` |
| 5 | **Estrarre le chiavi**, clone perfetto | Il clone usa il proprio flusso di contatore | **Divergenza** del contatore (valore sotto il massimo mai visto) → `CLONE_LIKELY` | `test_key_clone_caught_by_counter_divergence` |
| 6 | **Estrarre le chiavi**, clone altrove | Clone letto lontano, pochi secondi dopo | **Velocità impossibile** tra lettori → `CLONE_LIKELY` | `test_key_clone_caught_by_impossible_velocity` |
| 7 | Osservazione dei tempi locale | Side-channel sul confronto MAC | Confronto a tempo costante via `hmac.compare_digest` | `test_mac_comparison_correctness`, `test_mac_comparison_uses_non_short_circuiting_primitive` |

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
- **Esaurimento del contatore**: `SDMReadCtr` è a 24 bit. La gestione del
  rollover è una questione di deployment e non è modellata qui.
- `TagAnalyzer` mantiene un floor anti-replay persistente (`CounterStore`) *e*
  un rilevatore a punteggio in memoria: replay/rollback sopravvivono a un
  riavvio, mentre lo scoring di divergenza/velocità si ricostruisce dal flusso
  dal vivo. Lo store di riferimento è JSON con un lock in-process; un deployment
  multi-processo richiede un database con update condizionale atomico
  (anti-rollback).

## Rischio residuo

La detection anti-clone è **probabilistica e osservazionale**: aumenta la
confidenza su letture ripetute, non fornisce una garanzia da singola lettura
dell'unicità fisica. L'output con punteggio (`risk_score`, `signals`) è pensato
per alimentare un flusso di revisione/escalation, non per essere un booleano
silenzioso.
