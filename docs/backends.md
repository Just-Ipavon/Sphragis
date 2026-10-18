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

| `fido2-webauthn` | `WebAuthnBackend` | a WebAuthn assertion as JSON (`PublicKeyCredential.toJSON()` shape): FIDO2 signature counters, see below |

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

## FIDO2 / WebAuthn signature counters

A FIDO2 card answers a fresh challenge from the browser (Safari on iOS
included, over NFC) with a signed assertion carrying a signature counter.
`WebAuthnBackend` verifies it against a credential the relying party
registered and feeds the counter to the same ledger and detector: a counter
regression raises `counter_regression` exactly as for a SUN tap.

```python
from sphragis import (WebAuthnBackend, MemoryCredentialStore,
                      MemoryChallengeStore, RegisteredCredential)

creds, challenges = MemoryCredentialStore(), MemoryChallengeStore(ttl_seconds=120)
creds.add(RegisteredCredential.from_cose_key(credential_id, cose_public_key))
backend = WebAuthnBackend("verify.example.com", ["https://verify.example.com"],
                          creds, challenges)
challenge = challenges.issue()          # send to the browser's navigator.credentials.get()
```

The tap is the assertion as JSON, binary fields base64url. The backend checks
the credential, `clientDataJSON` (`webauthn.get`, allowed origin), the RP ID
hash, user presence (and user verification with
`require_user_verification=True`) and the ES256 or EdDSA signature; only then
does it consume the challenge, which must have been issued here, be unexpired
and unused, so junk input cannot burn a challenge issued to someone else. A
replayed assertion is `FORGED` (its challenge is spent). The identity is
`fido2:<credential id>`.

- **Counter fixed at 0.** Synced passkeys often keep no counter. A 0 is
  reported as *no counter*: the tap is `GENUINE` with the zero-weight signal
  `no_counter`, and no counter-based clone detection applies. If the credential
  reported a non-zero counter before, a 0 is scored as a regression.
- **Registration** (attestation) is the relying party's job; implement
  `CredentialStore.get(credential_id)` over your registry, and
  `ChallengeStore` over a shared store when several processes verify.
- **RP ID binding.** A credential only works for the relying party ID (domain)
  it was registered under. If the verifying domain changes, existing cards
  stop working: choose the RP ID as carefully as a key, for the whole life of
  the cards.

The REST API does not wire this backend from settings yet (it needs a
credential registry and a challenge endpoint); build the service with
`create_app(VerificationService(TagAnalyzer(backends=[...])))`.

## Writing a backend

1. Parse the tap; raise `SdmError` (or `ValueError`) on anything malformed.
2. Verify the authenticator in constant time; raise `ForgedTap` on mismatch,
   without putting the decoded identity or counter in the message.
3. Return `AuthenticTap` with a namespaced identity and the chip's counter.

No other part of the engine needs to change. `tests/test_verification_backends.py`
plugs a made-up HMAC chip through the analyzer, the service and the stores.
