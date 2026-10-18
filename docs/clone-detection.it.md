# Clone detection

*[English](clone-detection.md) · Italiano*

Un SDMMAC valido prova il **possesso della chiave**, non l'**unicità fisica**.
Un attaccante che estrae le chiavi di un tag può coniare un clone perfetto i cui
MAC sono tutti validi. L'unica cosa che un clone non può falsificare è un
contatore di letture monotòno e globalmente coerente. Sphragis trasforma questo
in un verdetto *con punteggio* invece che in un booleano.

## Il registro dei tap

Ogni tap autentico viene prima confrontato con il **registro dei tap**: il
floor anti-replay più ogni valore di contatore mai inviato per quell'UID,
tenuti nello stesso storage durevole e aggiornati in un solo passo atomico
(`record_tap`). Decide i tap vecchi in modo esatto, qualunque cosa sia
successa nel frattempo:

- un valore di contatore **già inviato** → `REPLAY`;
- un contatore **sotto il floor, mai inviato** → `CLONE_LIKELY`, **una volta
  sola**: inviare di nuovo lo stesso URL è un `REPLAY` e non genera un nuovo
  alert. L'unica eccezione è un contatore al massimo `reorder_counters` (2)
  sotto il floor, dallo stesso lettore autenticato che ha fissato il floor meno
  di `reorder_seconds` (2 s) prima: due tap rapidi le cui richieste sono
  arrivate in ordine inverso, segnalati come `SUSPICIOUS` (`counter_reordered`);
- un contatore **sopra il floor** → nuovo: il floor avanza e il rilevatore gli
  dà un punteggio.

I replay non toccano nient'altro: non entrano mai nella cronologia del
rilevatore, e nessun tap vecchio consuma il rate limit per UID, quindi
rigiocare un URL catturato non può né nascondere un clone né bloccare la tag
autentica. Una regressione invece entra nella cronologia, come prova che il
flusso del contatore dell'UID si è biforcato (vedi sotto). Due
copie dello stesso tap inviate insieme danno un `GENUINE` e un `REPLAY`. Uno
storage aggiornato da un floor semplice registra dove è iniziato il registro di
ogni UID; i contatori fino a quel punto sono segnalati come `REPLAY`
(`stale_counter`), perché non si sa se siano già stati inviati.

## Segnali

| Segnale | Peso | Significato |
|---------|------|-------------|
| `exact_replay` | 65 | il valore del contatore era già stato inviato → si sta rigiocando un URL catturato |
| `counter_regression` | 70 | sotto il floor e mai inviato → un secondo dispositivo con il proprio flusso di contatore (clone), o un tap autentico letto e trattenuto (pre-play) |
| `impossible_velocity` | 60 | un tap nuovo a un lettore mentre un altro lettore ha visto la tag meno di `min_travel_seconds` prima → due tag. Conta ogni osservazione di un lettore autenticato in quella finestra, quindi un tap anonimo in mezzo non nasconde nulla |
| `large_counter_gap` | 15 | un salto insolitamente grande sopra il floor; debole / informativo |
| `stale_counter` | 65 | sotto il floor che l'UID aveva quando è iniziato il suo registro (storage aggiornati) |
| `counter_rate` | 40 | più letture non viste dal momento del floor di quante una tag possa produrne (`max_tap_rate`, 25/s, dopo una tolleranza di `rate_slack_seconds`, 2 s, per il jitter): es. +500 in 10 s. Un emulatore o un clone con il contatore impostato, o un URL consegnato molto dopo il suo tap |
| `prior_divergence` | 35 | un tap nuovo su un UID la cui cronologia contiene già una regressione: il flusso del contatore si è biforcato, quindi può toccare l'uno o l'altro dispositivo |
| `counter_reordered` | 30 | appena sotto il floor, stesso lettore, pochi istanti dopo: consegna in ordine inverso di due tap rapidi |

## Un UID biforcato resta sospetto

Dopo una regressione, un controllo senza stato vedrebbe il tap successivo del
clone (ad esempio 16 dopo un floor di 15) come monotòno e `GENUINE`. Per questo
la regressione resta nella cronologia del rilevatore e ogni tap nuovo
successivo porta `prior_divergence`: `CLONE_LIKELY` non significa *questo tap
è il falso*, significa *il flusso del contatore di questo UID si è biforcato*.
Da solo il segnale è debole, perché chiunque legga una tag senza inviare l'URL
e lo invii dopo il tap successivo del proprietario può provocare una
regressione; combinato con un altro segnale (velocità, ritmo) arriva a
`CLONE_LIKELY`. Svanisce quando il contatore sotto cui è scesa la regressione
esce dalla finestra `history_limit`.

## Esaurimento del contatore

Leggere una tag molte volte senza inviare gli URL ne porta il contatore molto
avanti. Al proprietario non costa nulla: il tap autentico successivo è nuovo, e
il salto genera al massimo `large_counter_gap` e, se rapido, `counter_rate` —
`SUSPICIOUS`, mai un blocco duraturo.

## Punteggio

I pesi si aggregano in un punteggio di rischio 0–100 mappato su una classe:

- **≥ 60** → `CLONE_LIKELY` (o `REPLAY` quando l'unico segnale forte è un replay esatto)
- **25–59** → `SUSPICIOUS`
- **> 0** → `SUSPICIOUS`
- **0** → `GENUINE`

Il risultato porta con sé il punteggio e i segnali leggibili, così può alimentare
un flusso di revisione/escalation invece di consentire o negare in silenzio.

## I casi limite, onestamente

- Un contatore più basso mai inviato è o il flusso proprio di un clone o un URL
  autentico che qualcuno ha letto e tenuto (pre-play). I due sono
  crittograficamente indistinguibili; entrambi significano che la tag è stata
  duplicata o letta senza il proprietario, quindi l'alert è giustificato, e
  ogni URL di questo tipo genera un solo alert. Un clone che riemette solo
  valori già inviati viene segnalato come `REPLAY`.
- Un singolo clone usato al posto di un originale distrutto può apparire
  perfettamente monotòno. La detection basata solo sul contatore ha bisogno di
  vedere **entrambi** i tag, o di informazioni collaterali (posizione/velocità).
  Vedi il [threat model](../THREAT_MODEL.it.md).

La detection è **probabilistica e osservazionale**: aumenta la confidenza su
letture ripetute, non è una garanzia di unicità fisica da singola lettura.
