# Signed verification events

*English · [Italiano](events.it.md)*

Downstream systems keep append-only, third-party verifiable records of what
the engine decided: IETF SCITT, Certificate Transparency style logs, an audit
archive. Sphragis can sign one statement per verification as a **COSE_Sign1**
message (RFC 9052) and hand it to one or more **event sinks**.

## The message

```
COSE_Sign1 (CBOR tag 18)
  protected    {1 (alg): -8 (EdDSA),
                3 (content type): "application/vnd.sphragis.verification-event+cbor",
                4 (kid): "event_signing:v<N>" (bytes)}
  unprotected  {}
  payload      deterministic CBOR map (RFC 8949 §4.2.1), below
  signature    Ed25519 over ["Signature1", protected, h'', payload]
```

| Key | Field | Value |
|-----|-------|-------|
| `v` | schema version | `1` |
| `id` | event id | the `event_id` of the log line and the API response |
| `t` | time | milliseconds since the epoch, server clock |
| `cls` | classification | `GENUINE`, `SUSPICIOUS`, `REPLAY`, `CLONE_LIKELY`, `FORGED`, `ERROR`, `THROTTLED` |
| `rs` | risk score | 0–100 |
| `tag` | tag reference | the log pseudonym (`h:…`), or `null` when the tap did not authenticate |
| `ctr` | read counter | or `null` |
| `rdr` | reader id | or `null` for public taps |
| `sig` | signal names | e.g. `["counter_regression"]` |
| `al` | alert raised | `true` / `false` |
| `be` / `alg` / `kv` | backend, algorithm, key version | see [backends](backends.md) and [key versions](key-management.md#key-versions-and-rotation) |

The payload never carries key material, the tapped URL or the raw UID; signal
details are left out too (they repeat counters in prose).

## The key

The signing key is a 16-byte secret named `event_signing` in the
`SecretsBackend`, versioned like every other key (`event_signing_v2`, …). The
Ed25519 seed is derived from it with HKDF-SHA256 under the label
`sphragis/event-signing/ed25519/v1`, so the secret serves nothing else. The
key id `event_signing:v<N>` names the version; verifiers need only the 32-byte
public key:

```python
from sphragis import EventSigner, EnvSecretsBackend
signer = EventSigner(EnvSecretsBackend(), version=1)
signer.public_key.hex()      # publish this
signer.cose_key()            # or as a COSE_Key (OKP, Ed25519)
```

With the API the key is published at `GET /v1/event-key`:
`{"kid": "event_signing:v1", "alg": "EdDSA", "crv": "Ed25519", "x": "<hex>"}`.
To rotate, add `event_signing_v2`, set `SPHRAGIS_EVENT_KEY_VERSION=2` and
publish the new key; older events keep verifying under the key their `kid`
names.

## Sinks

```python
from sphragis import VerificationService, FileEventSink
service = VerificationService(analyzer, event_signer=signer,
                              event_sinks=[FileEventSink("events.log")],
                              events_on=None)     # None: every verification
```

`EventSink` has one method, `publish(signed: bytes, event: SignedEvent)`;
push to a log service from there. A failing sink is logged and skipped, like
an alert sink: it never breaks a verification. `FileEventSink` appends one
base64url line per event (file created `0600`, every line fsync'd);
`read_event_file` reads them back.

API settings: `SPHRAGIS_EVENTS_FILE` (enables signing), `SPHRAGIS_EVENTS_ON`
(classifications to sign, default all), `SPHRAGIS_EVENT_KEY_VERSION`
(default `1`).

## Verifying

```python
from sphragis import verify_event, read_event_file
for signed in read_event_file("events.log"):
    event = verify_event(signed, public_key, kid=b"event_signing:v1")
```

`verify_event` checks the structure, the algorithm, the key id and the
signature, decodes the payload with a strict deterministic CBOR decoder and
raises `EventError` on anything else. Any COSE library can verify the events
as well: the tests check them against `python-cwt` in both directions.

## Test vector

Secret `000102030405060708090a0b0c0d0e0f` as `event_signing` (version 1):

- public key `58cf2f1a14d25205b00ba98605c2746ee82ca5235524984235e141e2ba495b75`
- the event `id=0123456789abcdef0123456789abcdef, t=1760000000000,
  cls=CLONE_LIKELY, rs=70, tag="h:3f2a", ctr=11, rdr="gate-B",
  sig=["counter_regression"], al=true, be="ntag424-sun", alg="AES-128-CMAC",
  kv=1` signs to the bytes in `KAT_SIGNED` in `tests/test_events.py`
  (Ed25519 is deterministic, so any implementation must produce them).
