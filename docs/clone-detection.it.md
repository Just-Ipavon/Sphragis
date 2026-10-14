# Clone detection

*[English](clone-detection.md) · Italiano*

Un SDMMAC valido prova il **possesso della chiave**, non l'**unicità fisica**.
Un attaccante che estrae le chiavi di un tag può coniare un clone perfetto i cui
MAC sono tutti validi. L'unica cosa che un clone non può falsificare è un
contatore di letture monotòno e globalmente coerente. Sphragis trasforma questo
in un verdetto *con punteggio* invece che in un booleano.

## Segnali

`detection.CloneDetector` consuma osservazioni crittograficamente autentiche
(UID, contatore, timestamp, id lettore) ed emette segnali pesati:

| Segnale | Peso | Significato |
|---------|------|-------------|
| `exact_replay` | 65 | il valore esatto del contatore era già stato visto → si sta rigiocando un URL catturato |
| `counter_regression` | 70 | un contatore sotto il massimo mai visto → un secondo dispositivo con il proprio flusso di contatore (clone) |
| `impossible_velocity` | 60 | due tap a lettori diversi più vicini di quanto un oggetto possa viaggiare → due tag |
| `large_counter_gap` | 15 | un salto insolitamente grande; debole / informativo |

## Punteggio

I pesi si aggregano in un punteggio di rischio 0–100 mappato su una classe:

- **≥ 60** → `CLONE_LIKELY` (o `REPLAY` quando l'unico segnale forte è un replay esatto)
- **25–59** → `SUSPICIOUS`
- **> 0** → `SUSPICIOUS`
- **0** → `GENUINE`

Il risultato porta con sé il punteggio e i segnali leggibili, così può alimentare
un flusso di revisione/escalation invece di consentire o negare in silenzio.

## I casi limite, onestamente

- Un clone che riparte da un contatore basso riemette valori che anche un replay
  produrrebbe — Sphragis segnala `REPLAY`, che è l'etichetta veritiera (i due
  sono crittograficamente indistinguibili).
- Un singolo clone usato al posto di un originale distrutto può apparire
  perfettamente monotòno. La detection basata solo sul contatore ha bisogno di
  vedere **entrambi** i tag, o di informazioni collaterali (posizione/velocità).
  Vedi il [threat model](../THREAT_MODEL.it.md).

La detection è **probabilistica e osservazionale**: aumenta la confidenza su
letture ripetute, non è una garanzia di unicità fisica da singola lettura.
