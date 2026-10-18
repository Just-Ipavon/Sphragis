# Eventi di verifica firmati

*[English](events.md) · Italiano*

I sistemi a valle conservano registri append-only e verificabili da terzi di
ciò che il motore ha deciso: IETF SCITT, log in stile Certificate
Transparency, un archivio di audit. Sphragis può firmare una dichiarazione per
ogni verifica come messaggio **COSE_Sign1** (RFC 9052) e passarla a uno o più
**event sink**.

## Il messaggio

```
COSE_Sign1 (tag CBOR 18)
  protected    {1 (alg): -8 (EdDSA),
                3 (content type): "application/vnd.sphragis.verification-event+cbor",
                4 (kid): "event_signing:v<N>" (bytes)}
  unprotected  {}
  payload      mappa CBOR deterministica (RFC 8949 §4.2.1), sotto
  signature    Ed25519 su ["Signature1", protected, h'', payload]
```

| Chiave | Campo | Valore |
|--------|-------|--------|
| `v` | versione dello schema | `1` |
| `id` | id dell'evento | l'`event_id` della riga di log e della risposta API |
| `t` | tempo | millisecondi dall'epoch, orologio del server |
| `cls` | classificazione | `GENUINE`, `SUSPICIOUS`, `REPLAY`, `CLONE_LIKELY`, `FORGED`, `ERROR`, `THROTTLED` |
| `rs` | punteggio di rischio | 0–100 |
| `tag` | riferimento alla tag | lo pseudonimo dei log (`h:…`), o `null` se il tap non si è autenticato |
| `ctr` | contatore di lettura | o `null` |
| `rdr` | id del lettore | o `null` per i tap pubblici |
| `sig` | nomi dei segnali | es. `["counter_regression"]` |
| `al` | alert generato | `true` / `false` |
| `be` / `alg` / `kv` | backend, algoritmo, versione della chiave | vedi [backend](backends.it.md) e [versioni delle chiavi](key-management.it.md#versioni-delle-chiavi-e-rotazione) |

Il payload non contiene mai materiale di chiave, l'URL del tap o l'UID in
chiaro; anche i dettagli dei segnali restano fuori (ripetono i contatori in
forma testuale).

## La chiave

La chiave di firma è un segreto di 16 byte chiamato `event_signing` nel
`SecretsBackend`, con versioni come ogni altra chiave (`event_signing_v2`, …).
Il seed Ed25519 ne deriva con HKDF-SHA256 sotto l'etichetta
`sphragis/event-signing/ed25519/v1`, quindi il segreto non serve ad altro.
L'id `event_signing:v<N>` indica la versione; ai verificatori serve solo la
chiave pubblica di 32 byte:

```python
from sphragis import EventSigner, EnvSecretsBackend
signer = EventSigner(EnvSecretsBackend(), version=1)
signer.public_key.hex()      # da pubblicare
signer.cose_key()            # o come COSE_Key (OKP, Ed25519)
```

Con la API la chiave è pubblicata su `GET /v1/event-key`:
`{"kid": "event_signing:v1", "alg": "EdDSA", "crv": "Ed25519", "x": "<hex>"}`.
Per la rotazione aggiungi `event_signing_v2`, imposta
`SPHRAGIS_EVENT_KEY_VERSION=2` e pubblica la nuova chiave; gli eventi
precedenti si verificano con la chiave indicata dal loro `kid`.

## Sink

```python
from sphragis import VerificationService, FileEventSink
service = VerificationService(analyzer, event_signer=signer,
                              event_sinks=[FileEventSink("events.log")],
                              events_on=None)     # None: ogni verifica
```

`EventSink` ha un solo metodo, `publish(signed: bytes, event: SignedEvent)`;
da lì si inviano gli eventi a un servizio di log. Un sink che fallisce viene
registrato nei log e saltato, come un sink di alert: non interrompe mai una
verifica. `FileEventSink` aggiunge una riga base64url per evento (file creato
`0600`, ogni riga sincronizzata con fsync); `read_event_file` le rilegge.

Impostazioni della API: `SPHRAGIS_EVENTS_FILE` (abilita la firma),
`SPHRAGIS_EVENTS_ON` (classificazioni da firmare, di default tutte),
`SPHRAGIS_EVENT_KEY_VERSION` (default `1`).

## Verifica

```python
from sphragis import verify_event, read_event_file
for signed in read_event_file("events.log"):
    event = verify_event(signed, public_key, kid=b"event_signing:v1")
```

`verify_event` controlla struttura, algoritmo, id della chiave e firma,
decodifica il payload con un decoder CBOR deterministico rigoroso e solleva
`EventError` per qualunque altra cosa. Qualsiasi libreria COSE può verificare
gli eventi: i test li confrontano con `pycose` in entrambe le direzioni.

## Vettore di test

Segreto `000102030405060708090a0b0c0d0e0f` come `event_signing` (versione 1):

- chiave pubblica `58cf2f1a14d25205b00ba98605c2746ee82ca5235524984235e141e2ba495b75`
- l'evento `id=0123456789abcdef0123456789abcdef, t=1760000000000,
  cls=CLONE_LIKELY, rs=70, tag="h:3f2a", ctr=11, rdr="gate-B",
  sig=["counter_regression"], al=true, be="ntag424-sun", alg="AES-128-CMAC",
  kv=1` si firma nei byte di `KAT_SIGNED` in `tests/test_events.py` (Ed25519
  è deterministico, quindi ogni implementazione deve produrli).
