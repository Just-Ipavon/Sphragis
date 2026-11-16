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
- **Registration** (attestation) is the relying party's job; import the
  credentials into `SqliteCredentialStore` / `PostgresCredentialStore` (see
  below), or implement `CredentialStore.get(credential_id)` over your own
  registry, and `ChallengeStore` over a shared store when several processes
  verify.
- **RP ID binding.** A credential only works for the relying party ID (domain)
  it was registered under. If the verifying domain changes, existing cards
  stop working: choose the RP ID as carefully as a key, for the whole life of
  the cards.

### With the REST API

Add `fido2-webauthn` to `SPHRAGIS_BACKENDS` and set the relying party:

```bash
SPHRAGIS_BACKENDS=fido2-webauthn,ntag424-sun
SPHRAGIS_WEBAUTHN_RP_ID=verify.example.com
SPHRAGIS_WEBAUTHN_ORIGINS=https://verify.example.com
SPHRAGIS_WEBAUTHN_USER_VERIFICATION=preferred     # or required, discouraged
```

Each origin must be https (http only for `localhost`) and lie within the RP
ID; a mistake stops the service at startup. Credentials and challenges live
in the database the API already uses (`SqliteCredentialStore` /
`SqliteChallengeStore` on `SPHRAGIS_DB_PATH`, the Postgres ones on
`SPHRAGIS_DB_URL`), so a challenge issued by one replica is consumed exactly
once by whichever replica verifies the assertion.

1. Import each credential the relying party registered (attestation stays its
   job). Pass `--rp-id`: the credential then only verifies for that RP ID.

   ```bash
   sphragis credentials import --sqlite sphragis.db \
       --credential-id <base64url> --cose-key <base64url> --rp-id verify.example.com
   sphragis credentials list --sqlite sphragis.db
   sphragis credentials revoke --sqlite sphragis.db --credential-id <base64url>
   ```

2. The page asks `POST /v1/webauthn/challenge` for the request options
   (`challenge`, `rpId`, `timeout`, `userVerification`) and passes them to
   `navigator.credentials.get()`. The endpoint names no credential, so it
   reveals nothing about which ones exist; it is rate limited per IP like the
   verification endpoints, and answers `503` once
   `SPHRAGIS_WEBAUTHN_MAX_CHALLENGES` (100 000) are outstanding.
3. The page posts the assertion to `POST /v1/verify`, as
   `{"assertion": credential.toJSON()}` (or as a JSON string in `url`). A
   replayed assertion is `INVALID`: its challenge is spent everywhere.

A revoked credential stays in the table, so the same id cannot be imported
again by mistake. Remember the RP ID binding above: moving the API to another
domain later strands every imported card.

## Writing a backend

1. Parse the tap; raise `SdmError` (or `ValueError`) on anything malformed.
2. Verify the authenticator in constant time; raise `ForgedTap` on mismatch,
   without putting the decoded identity or counter in the message.
3. Return `AuthenticTap` with a namespaced identity and the chip's counter.

No other part of the engine needs to change. `tests/test_verification_backends.py`
plugs a made-up HMAC chip through the analyzer, the service and the stores.
