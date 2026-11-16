# Backend di verifica

*[English](backends.md) · Italiano*

Tutto ciò che viene dopo il controllo crittografico (registro dei tap,
rilevatore di cloni, rate limit, alert, storage, API) ha bisogno solo di tre
fatti su un tap: quale chip l'ha prodotto, il suo contatore monotòno, e che
l'autenticatore del chip è stato verificato. Un **backend di verifica**
trasforma l'URL di un tap in questi fatti; il resto del motore non guarda mai
campi specifici del chip.

## L'interfaccia

```python
class VerificationBackend(Protocol):
    name: str
    def accepts(self, url_or_query: str) -> bool: ...        # solo la forma, niente crittografia
    def authenticate(self, url_or_query: str) -> AuthenticTap: ...
```

`authenticate` restituisce un `AuthenticTap` oppure solleva:

| Esito | Significato | Classificazione |
|-------|-------------|-----------------|
| `AuthenticTap(identity, counter, backend, algorithm, payload)` | l'autenticatore è verificato | valutato dal registro e dal rilevatore |
| `ForgedTap` | il tap è leggibile, l'autenticatore non è valido | `FORGED` (identità e contatore mai restituiti) |
| `SdmError` / `ValueError` | input malformato | `ERROR` |

`identity` è la chiave di ogni storage per tag (registro, cronologia, rate
limit, pseudonimo nei log). Deve essere stabile per un chip e non deve
collidere con le identità di un altro backend che usa gli stessi storage. I
backend NTAG 424 DNA mantengono l'UID in esadecimale maiuscolo, come già negli
storage esistenti; un nuovo backend dovrebbe usare un prefisso (es.
`fido2:<credential id>`).

`payload` porta i dati autenticati recuperati dal backend (ad esempio
`SDMENCFileData` decifrato). L'analyzer lo restituisce solo per i tap nuovi,
mai per un replay o un contatore vecchio.

## Backend inclusi

| Nome | Classe | Tap |
|------|--------|-----|
| `ntag424-sun` | `Ntag424SunBackend` | `?picc_data=…&cmac=…`: SUN semplice, PICCData AES-128 + SDMMAC. Accetta ogni tap senza un parametro di dati di file cifrati, anche quelli malformati, e rifiuta gli altri |
| `ntag424-sun-enc` | `Ntag424EncBackend` | `?picc_data=…&enc=…&cmac=…`: SUN con `SDMENCFileData`; i dati di file decifrati sono il payload |

| `fido2-webauthn` | `WebAuthnBackend` | un'asserzione WebAuthn in JSON (forma di `PublicKeyCredential.toJSON()`): contatori di firma FIDO2, vedi sotto |

`Verifier` ed `EncFileVerifier` sono involucri sottili attorno a questi due
backend e a un floor del contatore; il loro comportamento non cambia.

## Scelta del backend per ogni tap

```python
from sphragis import TagAnalyzer, Ntag424EncBackend, Ntag424SunBackend

analyzer = TagAnalyzer(backends=[Ntag424EncBackend(keys), Ntag424SunBackend(keys)],
                       store=ledger)
```

Ogni tap va al **primo** backend il cui `accepts` restituisce vero, quindi
elenca prima i più specifici. Un tap che nessun backend accetta è un `ERROR`.
`TagAnalyzer(keys)` è una scorciatoia per `backends=[Ntag424SunBackend(keys)]`.
Il risultato porta `backend` e `algorithm`; il servizio registra il backend nei
log e i lettori lo vedono nella risposta API dettagliata.

Con la REST API, `SPHRAGIS_BACKENDS` elenca i backend da abilitare
(`ntag424-sun` di default, es. `ntag424-sun,ntag424-sun-enc`); vengono sempre
provati dal più specifico.

## Contatori di firma FIDO2 / WebAuthn

Una carta FIDO2 risponde a una challenge nuova del browser (anche Safari su
iOS, via NFC) con un'asserzione firmata che porta un contatore di firma.
`WebAuthnBackend` la verifica contro una credenziale registrata dalla relying
party e passa il contatore allo stesso registro e allo stesso rilevatore: una
regressione del contatore genera `counter_regression` esattamente come per un
tap SUN.

```python
from sphragis import (WebAuthnBackend, MemoryCredentialStore,
                      MemoryChallengeStore, RegisteredCredential)

creds, challenges = MemoryCredentialStore(), MemoryChallengeStore(ttl_seconds=120)
creds.add(RegisteredCredential.from_cose_key(credential_id, cose_public_key))
backend = WebAuthnBackend("verify.example.com", ["https://verify.example.com"],
                          creds, challenges)
challenge = challenges.issue()          # da passare a navigator.credentials.get()
```

Il tap è l'asserzione in JSON, con i campi binari in base64url. Il backend
controlla la credenziale, `clientDataJSON` (`webauthn.get`, origine
ammessa), l'hash del RP ID, la presenza dell'utente (e la verifica
dell'utente con `require_user_verification=True`) e la firma ES256 o EdDSA;
solo dopo consuma la challenge, che deve essere stata emessa qui, non
scaduta e non usata, così un input spazzatura non può bruciare una challenge
emessa per qualcun altro. Un'asserzione rigiocata è `FORGED` (la sua
challenge è già spesa). L'identità è `fido2:<credential id>`.

- **Contatore fermo a 0.** Le passkey sincronizzate spesso non tengono un
  contatore. Uno 0 è trattato come *nessun contatore*: il tap è `GENUINE`
  con il segnale a peso zero `no_counter`, e non si applica il rilevamento
  dei cloni basato sul contatore. Se la credenziale ha già riportato un
  contatore diverso da zero, uno 0 è valutato come regressione.
- **Registrazione** (attestation): spetta alla relying party; importa le
  credenziali in `SqliteCredentialStore` / `PostgresCredentialStore` (vedi
  sotto), oppure implementa `CredentialStore.get(credential_id)` sul tuo
  registro, e `ChallengeStore` su uno storage condiviso quando più processi
  verificano.
- **Legame con il RP ID.** Una credenziale funziona solo per il relying party
  ID (dominio) con cui è stata registrata. Se il dominio che verifica cambia,
  le carte esistenti smettono di funzionare: scegli il RP ID con la stessa
  cura di una chiave, per tutta la vita delle carte.

### Con la REST API

Aggiungi `fido2-webauthn` a `SPHRAGIS_BACKENDS` e configura la relying party:

```bash
SPHRAGIS_BACKENDS=fido2-webauthn,ntag424-sun
SPHRAGIS_WEBAUTHN_RP_ID=verify.example.com
SPHRAGIS_WEBAUTHN_ORIGINS=https://verify.example.com
SPHRAGIS_WEBAUTHN_USER_VERIFICATION=preferred     # oppure required, discouraged
```

Ogni origine deve essere https (http solo per `localhost`) e stare dentro il
RP ID; un errore ferma il servizio all'avvio. Credenziali e challenge vivono
nel database che l'API usa già (`SqliteCredentialStore` /
`SqliteChallengeStore` su `SPHRAGIS_DB_PATH`, quelli Postgres su
`SPHRAGIS_DB_URL`), così una challenge emessa da una replica viene consumata
una sola volta da qualunque replica verifichi l'asserzione.

1. Importa ogni credenziale registrata dalla relying party (l'attestation resta
   compito suo). Passa `--rp-id`: la credenziale verifica solo per quel RP ID.

   ```bash
   sphragis credentials import --sqlite sphragis.db \
       --credential-id=<base64url> --cose-key=<base64url> --rp-id verify.example.com
   sphragis credentials list --sqlite sphragis.db
   sphragis credentials revoke --sqlite sphragis.db --credential-id=<base64url>
   ```

2. La pagina chiede a `POST /v1/webauthn/challenge` le opzioni della richiesta
   (`challenge`, `rpId`, `timeout`, `userVerification`) e le passa a
   `navigator.credentials.get()`. L'endpoint non nomina alcuna credenziale,
   quindi non rivela quali esistono; è limitato per IP come gli endpoint di
   verifica e risponde `503` quando le challenge in sospeso arrivano a
   `SPHRAGIS_WEBAUTHN_MAX_CHALLENGES` (100 000).
3. La pagina invia l'asserzione a `POST /v1/verify`, come
   `{"assertion": credential.toJSON()}` (o come stringa JSON in `url`).
   Un'asserzione rigiocata è `INVALID`: la sua challenge è spesa ovunque.

Una credenziale revocata resta nella tabella, così lo stesso id non può essere
reimportato per errore. Ricorda il legame con il RP ID descritto sopra:
spostare l'API su un altro dominio in seguito rende inutilizzabili tutte le
carte importate.

## Scrivere un backend

1. Leggi il tap; solleva `SdmError` (o `ValueError`) su qualunque input
   malformato.
2. Verifica l'autenticatore a tempo costante; solleva `ForgedTap` se non
   corrisponde, senza mettere nel messaggio l'identità o il contatore decodificati.
3. Restituisci `AuthenticTap` con un'identità con prefisso e il contatore del chip.

Nessun'altra parte del motore deve cambiare. `tests/test_verification_backends.py`
fa passare un chip HMAC inventato attraverso analyzer, servizio e storage.
