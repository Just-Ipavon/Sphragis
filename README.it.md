# Sphragis — un sigillo crittografico di autenticità per NTAG 424 DNA

[![CI](https://github.com/Just-Ipavon/Sphragis/actions/workflows/ci.yml/badge.svg)](https://github.com/Just-Ipavon/Sphragis/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%E2%80%933.13-blue)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)

[English](README.md) · **Italiano**

> *sphragís* (σφραγίς) — il sigillo (signet) dell'antica Grecia che attestava
> la genuinità di una cosa. Qui è il sigillo crittografico che prova che un tag
> NFC — e l'oggetto a cui è applicato — è autentico e unico.

Un toolkit essenziale e ben testato che fa una cosa sola, ma in profondità:
stabilire se una lettura NFC proviene da un tag NXP **NTAG 424 DNA**
**autentico e unico** — oppure da un **clone**.

> ⚠️ **Stato: progetto di studio / portfolio.** La crittografia è validata
> contro i test vector ufficiali NXP e il codice è stato sottoposto a un
> auto-audit avversariale (vedi il [threat model](THREAT_MODEL.it.md)), ma
> **non** è stato verificato in modo indipendente, né ancora validato su tag
> fisici. Non usarlo come unica linea di difesa in produzione senza quel lavoro.

Chiunque sa verificare un AES-CMAC. La parte difficile e interessante
dell'anti-contraffazione è ciò che succede *dopo* che il MAC è valido: provare
che esiste **un solo** tag fisico. Questo progetto tratta quel problema come
centrale e misurabile.

Tre pilastri:

1. **Crittografia corretta** — verifica SDM/SUN standard NXP, validata contro il
   **test vector ufficiale NXP AN10922/AN12196**.
2. **Intelligenza di clone-detection** — un motore con punteggio (replay,
   divergenza del contatore, velocità impossibile) che smaschera anche un clone
   costruito con le chiavi estratte.
3. **Rigore avversariale** — un [threat model](THREAT_MODEL.it.md) documentato e
   un harness che monta attacchi reali e dimostra che vengono bloccati.

## Perché il contatore di letture è tutto

Un SDMMAC valido prova solo che *chi ha prodotto questa lettura possiede la
chiave segreta*. Non prova che esista un solo tag fisico. Un attaccante che
estrae le chiavi può fare un clone perfetto i cui MAC sono tutti validi. Quello
che **non** può falsificare è un contatore di letture monotòno e globalmente
coerente su ogni lettore del mondo. Perciò Sphragis valuta il comportamento del
contatore nel tempo:

```
$ python examples/clone_demo.py

Genuine tag in the field (reader = gate-A):
  authentic tap              GENUINE       score=  0  [-]
  authentic tap              GENUINE       score=  0  [-]

Attacker extracts the keys and builds a perfect clone.
The clone's MACs are all cryptographically VALID — yet:

  clone, divergent counter   CLONE_LIKELY  score= 70  [counter_regression]
  clone, far away seconds later CLONE_LIKELY  score= 60  [impossible_velocity]
```

## Come funziona la verifica

A ogni tap il tag aggiunge parametri dinamici a un URL:

```
https://example.com/t?picc_data=EF963FF7828658A599F3041510671E88&cmac=94EED9EE65337086
```

- **`picc_data`** — blocco cifrato AES-128-CBC con UID e contatore di letture.
- **`cmac`** — AES-CMAC troncato (SDMMAC) che autentica la lettura.

Pipeline:

```
 URL letto ─▶ parse ─▶ decifra PICCData ─▶ verifica CMAC ─▶ valuta contatore ─▶ verdetto
                              │                   │                  │
                           UID + ctr        autenticità       clone / replay
```

Classificazioni: `GENUINE`, `SUSPICIOUS`, `REPLAY`, `CLONE_LIKELY`, `FORGED`, `ERROR`.

## Installazione

```bash
pip install -r requirements.txt   # pycryptodome
```

## Avvio rapido (nessun hardware necessario)

```python
import os
from sphragis import TagAnalyzer, DiversifiedKeys
from sphragis.emulator import tag_from_provider

# Chiavi diversificate per UID (AN10922) — il pattern di gestione chiavi di produzione.
master, meta = os.urandom(16), os.urandom(16)
keys = DiversifiedKeys(master_file_key=master, meta_read_key=meta, context=b"ART")

tag = tag_from_provider(keys, uid=bytes.fromhex("04DE5F1EACC040"))
analyzer = TagAnalyzer(keys)

r = analyzer.analyze(tag.tap(), reader_id="gate-A")
print(r.classification, r.risk_score)   # GENUINE 0
```

Esegui le demo:

```bash
python examples/demo.py         # autentico / replay / contraffazione
python examples/clone_demo.py   # clone con chiavi estratte, smascherato dal contatore
```

## Riga di comando

```bash
# Verifica il vettore ufficiale NXP (chiavi a zero)
python -m sphragis.cli verify \
  --meta-key 00000000000000000000000000000000 \
  --file-key 00000000000000000000000000000000 \
  "https://example.com/t?picc_data=EF963FF7828658A599F3041510671E88&cmac=94EED9EE65337086"

# Decodifica cosa emette un tag: PICCDataTag, UID, SDMReadCtr (LE), offset NDEF.
# Solo diagnostica, nessun verdetto; chiavi di default a zero (fabbrica).
python -m sphragis.cli inspect \
  "https://example.com/t?picc_data=EF963FF7828658A599F3041510671E88&cmac=94EED9EE65337086"
```

## API REST

Front-end FastAPI opzionale (`pip install "sphragis[api]"`). Riceve l'URL del
tap e restituisce il verdetto con punteggio, scrive un evento di log JSON
strutturato per ogni verifica, genera alert su `CLONE_LIKELY` e applica il rate
limiting:

```bash
uvicorn --factory sphragis.api:create_app_from_env
curl "http://localhost:8000/t?picc_data=…&cmac=…"
# {"event_id":"…","verdict":"GENUINE","risk_score":0,"message":"Authentic tag."}
```

La risposta pubblica è volutamente minima: input forgiati e malformati
ricevono la stessa risposta `INVALID`, così l'endpoint non fa da oracolo per un
attaccante. I lettori autenticati ricevono la valutazione completa, e il loro
`reader_id` deriva solo dal token. Vedi [docs/api.it.md](docs/api.it.md).

## Test

```bash
pip install -e ".[api,test]"
python -m pytest -q      # 144 test
```

- **Known-answer**: riproduce il vettore SDM ufficiale NXP.
- **Avversariali**: replay, MAC forgiato, MAC troncato, rollback del contatore,
  divergenza da clone, velocità impossibile, confronto MAC a tempo costante.
- **Produzione**: floor atomico su DB sotto concorrenza, secrets backend.
- **Servizio e API**: cronologia del rilevatore condivisa tra worker, livello
  pubblico senza oracolo, `reader_id` falsificato, alert su un vero key-clone,
  rate limiting.

## Indurimento per la produzione

Questo repository è il **motore di verifica generico e open** — indurito verso
la produzione, ma volutamente indipendente dall'applicazione. Un deployment
reale ci costruisce sopra il proprio prodotto (provisioning, logica di business)
in un codebase separato; il motore pubblico resta riusabile e pulito.

- **Floor anti-replay atomico** — `SqliteCounterStore` impone la monotonìa del
  contatore dentro una transazione serializzata (niente TOCTOU tra thread o
  processi).
- **Nessuna chiave nel codice** — `secrets.py` astrae il materiale chiave dietro
  un `SecretsBackend` (env / file / punto di estensione KMS).
- **Confronto MAC a tempo costante**, validazione input fail-closed, threat
  model documentato.

```python
from sphragis import Verifier, SqliteCounterStore, EnvSecretsBackend, build_diversified_keys

keys = build_diversified_keys(EnvSecretsBackend())            # chiavi da env/KMS
verifier = Verifier(keys, SqliteCounterStore("counters.db"))  # durevole, atomico
```

## Documentazione

| Argomento | English | Italiano |
|-----------|---------|----------|
| Protocollo (SDM/SUN) | [protocol.md](docs/protocol.md) | [protocol.it.md](docs/protocol.it.md) |
| Clone detection | [clone-detection.md](docs/clone-detection.md) | [clone-detection.it.md](docs/clone-detection.it.md) |
| Gestione chiavi | [key-management.md](docs/key-management.md) | [key-management.it.md](docs/key-management.it.md) |
| API REST | [api.md](docs/api.md) | [api.it.md](docs/api.it.md) |
| Produzione e deployment | [production.md](docs/production.md) | [production.it.md](docs/production.it.md) |
| Tag fisici (banco) | [hardware.md](docs/hardware.md) | [hardware.it.md](docs/hardware.it.md) |
| Threat model | [THREAT_MODEL.md](THREAT_MODEL.md) | [THREAT_MODEL.it.md](THREAT_MODEL.it.md) |
| Politica di sicurezza | [SECURITY.md](SECURITY.md) | [SECURITY.md](SECURITY.md) |

## Struttura del progetto

```
sphragis/
  sdm.py           primitive crittografiche SDM (decifra PICCData, chiave di sessione, SDMMAC)
  verifier.py      pipeline semplice URL -> verdetto
  counterstore.py  store contatore JSON + protocollo CounterBackend
  sqlstore.py      floor anti-replay SQLite con check-and-advance atomico
  secrets.py       backend per il materiale chiave (env / file / estensione KMS)
  diversify.py     diversificazione chiavi per UID AN10922
  detection.py     motore di clone-detection con punteggio (segnali + rischio)
  observations.py  store della cronologia del rilevatore (memoria / SQLite, observe atomico)
  analyzer.py      pipeline completa: crypto + detection -> valutazione con punteggio
  service.py       servizio di verifica indipendente dal framework (log, alert)
  alerts.py        sink degli alert (log / audit trail SQLite / webhook firmato)
  logs.py          formatter JSON per i log + pseudonimizzazione UID
  ratelimit.py     rate limiter token bucket
  api/             app FastAPI (extra opzionale `sphragis[api]`)
  adversary.py     toolkit dell'attaccante (replay, forge, rollback, key-clone)
  emulator.py      tag NTAG 424 DNA software (genera URL SUN validi)
  diagnostics.py   ispezione del tap (layout byte del PICCData, offset NDEF)
  ndef.py          codifica file NDEF URI + calcolo offset SDM
  apdu.py          helper APDU ISO 7816-4
  transport/       ApduTransport: scriptato / emulato / ISO-DEP / Chameleon Ultra / PN532
  ev2.py           AuthenticateEV2First + secure messaging (vettori AN12196)
  sdmconfig.py     impostazioni file SDM: build / parse di ChangeFileSettings
  provision.py     provisioning SUN idempotente a chiavi zero
  cli.py           verify / inspect / emulate da riga di comando
tools/             sdm_probe / provision / tap_verify (da eseguire sull'host con hardware)
tests/             suite known-answer + avversariale + produzione + servizio/API
examples/          demo.py, clone_demo.py
docs/              documentazione tecnica bilingue
```

## Roadmap

- [x] Verifica SDM/SUN validata (vettore NXP)
- [x] Diversificazione chiavi per UID AN10922
- [x] Motore di clone-detection con punteggio
- [x] Threat model + harness avversariale
- [x] Floor anti-replay atomico su DB (SQLite)
- [x] Astrazione del materiale chiave (env / file / estensione KMS)
- [x] API REST di verifica (log strutturati, alert, rate limiting)
- [ ] Backend Postgres + scalabilità orizzontale
- [ ] Supporto dati file cifrati (SDMENCFileData)
- [ ] Verifica su tag fisici

## Riferimenti

- NXP **AN12196** — *NTAG 424 DNA features and hints (SDM).*
- NXP **AN10922** — *Symmetric key diversifications.*

## Licenza

GPL-3.0-or-later — vedi [LICENSE](LICENSE).
