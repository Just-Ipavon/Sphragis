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

## Scrivere un backend

1. Leggi il tap; solleva `SdmError` (o `ValueError`) su qualunque input
   malformato.
2. Verifica l'autenticatore a tempo costante; solleva `ForgedTap` se non
   corrisponde, senza mettere nel messaggio l'identità o il contatore decodificati.
3. Restituisci `AuthenticTap` con un'identità con prefisso e il contatore del chip.

Nessun'altra parte del motore deve cambiare. `tests/test_verification_backends.py`
fa passare un chip HMAC inventato attraverso analyzer, servizio e storage.
