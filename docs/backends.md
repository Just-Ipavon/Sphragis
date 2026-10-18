# Verification backends

*English · [Italiano](backends.it.md)*

Everything after the cryptographic check (tap ledger, clone detector, rate
limits, alerts, stores, API) only needs three facts about a tap: which chip
produced it, its monotonic counter, and that the chip's authenticator
verified. A **verification backend** turns a tapped URL into those facts; the
rest of the engine never looks at chip-specific fields.

## The interface

```python
class VerificationBackend(Protocol):
    name: str
    def accepts(self, url_or_query: str) -> bool: ...        # shape only, no crypto
    def authenticate(self, url_or_query: str) -> AuthenticTap: ...
```

`authenticate` either returns an `AuthenticTap` or raises:

| Outcome | Meaning | Classification |
|---------|---------|----------------|
| `AuthenticTap(identity, counter, backend, algorithm, payload)` | the authenticator verified | scored by the ledger and the detector |
| `ForgedTap` | the tap parsed, the authenticator does not verify | `FORGED` (identity and counter never returned) |
| `SdmError` / `ValueError` | malformed input | `ERROR` |

`identity` keys every per-tag store (ledger, history, rate limit, log
pseudonym). It must be stable for a chip and must not collide with the
identities of another backend sharing the same stores. The NTAG 424 DNA
backends keep the bare UID in upper-case hex, as existing stores already hold;
a new backend should prefix its identities (e.g. `fido2:<credential id>`).

`payload` carries authenticated data the backend recovered (the decrypted
`SDMENCFileData`, for instance). The analyzer returns it for fresh taps only,
never for a replay or a stale counter.

## Shipped backends

| Name | Class | Tap |
|------|-------|-----|
| `ntag424-sun` | `Ntag424SunBackend` | `?picc_data=…&cmac=…`: plain SUN, AES-128 PICCData + SDMMAC. Accepts every tap without an encrypted file-data parameter, malformed ones included, and fails closed on the rest |
| `ntag424-sun-enc` | `Ntag424EncBackend` | `?picc_data=…&enc=…&cmac=…`: SUN with `SDMENCFileData`; the decrypted file data is the payload |

`Verifier` and `EncFileVerifier` are thin wrappers around these two backends
and a counter floor; their behaviour is unchanged.

## Selecting a backend per tap

```python
from sphragis import TagAnalyzer, Ntag424EncBackend, Ntag424SunBackend

analyzer = TagAnalyzer(backends=[Ntag424EncBackend(keys), Ntag424SunBackend(keys)],
                       store=ledger)
```

Each tap goes to the **first** backend whose `accepts` returns true, so list
the most specific first. A tap no backend accepts is an `ERROR`.
`TagAnalyzer(keys)` is shorthand for `backends=[Ntag424SunBackend(keys)]`.
The result carries `backend` and `algorithm`; the service logs the backend and
readers see it in the detailed API response.

With the REST API, `SPHRAGIS_BACKENDS` lists the backends to enable
(`ntag424-sun` by default, e.g. `ntag424-sun,ntag424-sun-enc`); they are
always tried most specific first.

## Writing a backend

1. Parse the tap; raise `SdmError` (or `ValueError`) on anything malformed.
2. Verify the authenticator in constant time; raise `ForgedTap` on mismatch,
   without putting the decoded identity or counter in the message.
3. Return `AuthenticTap` with a namespaced identity and the chip's counter.

No other part of the engine needs to change. `tests/test_verification_backends.py`
plugs a made-up HMAC chip through the analyzer, the service and the stores.
