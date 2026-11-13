# Changelog

Italiano: [CHANGELOG.it.md](CHANGELOG.it.md). Versions follow
[Semantic Versioning](https://semver.org/).

## Unreleased

### Added

- `/readyz`: every store answers a read and the webhook alert queue is under
  90% full, or `503` with the failing checks. On shutdown the API delivers
  queued webhook alerts (up to 10 s) and closes the stores;
  `BackgroundAlertSink` gains bounded `flush(timeout)` / `close(timeout)` and
  `pending`. `alerted` in results and events is documented as "a sink
  accepted the alert" (queued, for the webhook) (#70).
### Security

- `rekey_tag` (and `tools/rekey.py --to-factory`) no longer changes a keyed
  slot while slot 0 is on factory keys and no UID-specific slot proves a key:
  ChangeKey would send the old key, for slot 2 the fleet-wide `meta_read`,
  under the public zero key. `--allow-known-uid` does not override this.

### Fixed

- Packaging, docs and CI (#69): a `MANIFEST.in` puts in the sdist what its
  tests read (test helpers, docs, tools, examples, locks, workflows), and a
  new CI job builds the sdist and the wheel and runs the suite from the
  unpacked sdist. The license is declared as an SPDX expression with
  `license-files` (setuptools 77 or later), dropping the deprecated table
  and classifier. The README shows the current `clone_demo.py` output, and
  a test keeps it in step. The security workflow installs `pip-audit`,
  `bandit` and `ruff` from a hash-locked `requirements/security.lock` and
  now runs ruff's correctness rules (`F`, `E9`, `B`, fixed across the
  code). The Postgres service image is pinned by digest and its job runs
  on Python 3.10 (the oldest supported); Dependabot also watches `requirements/`.
- The CLI, the emulator and the tools no longer end in a traceback on bad
  input (#68): `emulate --uid` must be 7 hex bytes and `--counter`/`--taps`
  stay within the 24-bit counter, as usage errors; `verify --store` with an
  empty or corrupt file prints an error. `EmulatedTag` refuses a counter out
  of range, stops at the 24-bit limit like a real tag, and appends its SUN
  parameters with `&` to a `base_url` that already has a query.
  `tools/provision.py` and `tools/rekey.py` report reader, APDU and secrets
  errors as one line (exit 2); the provision example without `--port` is
  fixed. Impossible-velocity checks skip history recorded after the tap
  (clock steps, host skew).
- Two genuine taps of one tag processed concurrently no longer make every
  later tap `SUSPICIOUS` (`prior_divergence`). The ledger and the detector
  history are written in two steps, so the history could receive the two
  fresh counters in reverse order and read that as a fork. Each history row
  now records whether the ledger found it fresh or a regression (a
  `regression` column added in place to the SQLite and Postgres
  observation tables), and fresh rows are never taken for a fork; rows from
  2.0.0 are still judged by order (#62).
- SQLite stores (#65): `:memory:` is refused with a clear error instead of
  failing with "no such table" on the first request served by another
  thread; `close()` now closes the connections of every thread (they are
  opened with `check_same_thread=False`), and `SqliteAlertSink` gains
  `close()` and context-manager support. `SqliteKeyInventory` closes its
  connection after every call, the Postgres stores drop and close a broken
  connection when they replace it, and a refused webhook redirect no longer
  leaves the response socket open. The test suite now treats
  `ResourceWarning` as an error.
- Per-IP rate limiting no longer collapses to one bucket behind a Unix
  socket or a proxy that writes `ip:port`: forwarded hops may be `ip:port`,
  `[v6]` or `[v6]:port`, `unix` in `SPHRAGIS_TRUSTED_PROXIES` trusts the
  proxy in front of a Unix socket, and the API logs a warning when the peer
  has no address and nothing tells it the client's (#66).
- Malformed input no longer escapes as an unexpected exception type
  (#64): a WebAuthn `clientDataJSON` whose `origin` or `type` is not a
  string is `ERROR` instead of a `TypeError` reaching the caller;
  `cbor_decode` raises `EventError` for a map key that is not an integer,
  text or bytes, and for nesting deeper than 8 levels (it used to hit
  `RecursionError` before the signature check); `verify_webhook` returns
  `False` for a non-ASCII or missing signature header.
- A genuine tap with an extra query parameter containing `?` or `:`
  (`&next=/a?b=1`, `v:1&…`) was read as a URL and became `ERROR`. A bare
  query is now recognised by a `=` before its first `?` or `#`, and `/t`
  passes its query explicitly (#67).
- The JSON `CounterStore` re-reads the shared file for `last_counter`,
  `is_fresh` and `seen` too, so an instance no longer reports a floor
  another process has already moved past (#67).
- `check_and_advance` also records the counter in a UID's tap ledger once
  that ledger has started, so a store used by both `Verifier` and
  `TagAnalyzer` scores an exact replay as `REPLAY`, not as a counter
  regression (#67).
- Stores no longer upper-case every identity: only bare hex UIDs (NTAG 424
  DNA) are, and prefixed identities such as `fido2:<base64url>` keep their
  case, so two WebAuthn credentials whose ids differ only by case no longer
  share one counter and one history (#63). Upgrading: NTAG data is
  unaffected. Rows that 2.0.0 stored for a non-hex identity were stored
  upper-cased; a credential whose id has lower-case letters starts a new
  history under its real id.

## 2.0.0 — 2026-10-18

The engine opens to several chip families behind one verification interface,
with results that say what produced them and can be signed for long-term
records. Clone detection keeps a forked UID suspect.

### Upgrading from 1.0
- The public API stays compatible: `TagAnalyzer(keys)`, `Verifier`,
  `EncFileVerifier`, the stores and the REST endpoints work as before.
- Some verdicts change on purpose: fresh taps on a UID whose history holds a
  counter regression are `SUSPICIOUS` (`prior_divergence`) instead of
  `GENUINE`; a counter racing ahead of any reader adds `counter_rate`; two
  quick taps from one reader delivered out of order are `SUSPICIOUS`
  (`counter_reordered`) instead of `CLONE_LIKELY`.
- SQLite and Postgres observation and alert tables gain the `backend`,
  `algorithm` and `key_version` columns in place on first start; no manual
  migration. Rows written by 1.0 read back with unknown provenance.
- New optional settings: `SPHRAGIS_BACKENDS`, `SPHRAGIS_KEY_VERSIONS`,
  `SPHRAGIS_EVENTS_FILE`, `SPHRAGIS_EVENTS_ON`, `SPHRAGIS_EVENT_KEY_VERSION`.
  The defaults keep 1.0 behaviour.
- The FIDO2/WebAuthn backend is validated with a software authenticator only;
  hardware card validation is tracked in #39.

### FIDO2 / WebAuthn signature counters (#39)
- `WebAuthnBackend` verifies WebAuthn assertions (ES256, EdDSA) from
  registered credentials against single-use, server-issued challenges and
  feeds the signature counter to the ledger and detector: counter regressions
  raise the same signals as SUN taps.
- A counter fixed at 0 (synced passkeys) is *no counter* (`no_counter`,
  `GENUINE`), not a clone signal; a drop to 0 after a non-zero counter is a
  regression. RP ID binding trade-off documented.

### Signed verification events (#38)
- Optional COSE_Sign1 statement per verification (EdDSA/Ed25519, deterministic
  CBOR payload: pseudonymous tag reference, counter, classification, signal
  names, time, backend, algorithm and key version; no key material, no tap).
- Signing key derived from the `event_signing` secret (versioned); public key
  at `GET /v1/event-key`. `EventSink` interface, `FileEventSink`,
  `verify_event`, known-answer vector; round trips checked against python-cwt.
- API settings `SPHRAGIS_EVENTS_FILE`, `SPHRAGIS_EVENTS_ON`,
  `SPHRAGIS_EVENT_KEY_VERSION`. The `test` extra adds python-cwt, cbor2 and cryptography.

### Crypto agility (#37)
- Keys are addressed by (name, version): version 1 keeps the unsuffixed names,
  version N is `<name>_v<N>`. A `KeyRing` holds several active versions during
  a rotation; the NTAG 424 DNA backends try each and report the one that
  verified (`build_keyring`, `SPHRAGIS_KEY_VERSIONS`).
- Results, detector observations, alerts, log events and the detailed API
  response carry the backend, algorithm and key version. SQLite and Postgres
  observation and alert tables gain the columns in place on first start; older
  rows read back as unknown.
- Rotation procedure and algorithm changes documented in key management.

### Verification backends (#35)
- New `VerificationBackend` interface: a backend parses and verifies a tap and
  returns a normalized `AuthenticTap` (identity, counter, backend, algorithm,
  payload); the ledger, detector, service and API no longer depend on the chip.
- `Ntag424SunBackend` and `Ntag424EncBackend` wrap the existing NTAG 424 DNA
  verifiers with no behaviour change; `TagAnalyzer(backends=[...])` picks the
  first backend that accepts each tap, so SDMENCFileData taps can now go
  through the analyzer and the API (`SPHRAGIS_BACKENDS`).
- Results carry `backend` and `algorithm`; the detailed API response and the
  log event carry the backend.

### Clone detection
- A counter regression stays in the detector's history: later fresh taps on a
  forked UID carry `prior_divergence` (weak alone) instead of reading as
  `GENUINE`.
- New `counter_rate` signal: a counter advancing faster than a tag can be read
  since the floor was set (`max_tap_rate`, `rate_slack_seconds`).
- Two quick taps from one reader whose requests arrive out of order are
  `SUSPICIOUS` (`counter_reordered`) rather than `CLONE_LIKELY`
  (`reorder_counters`, `reorder_seconds`).

## 1.0.0 — 2026-10-15

First stable release: the generic NTAG 424 DNA verification engine, hardened
after an adversarial self-review and validated on physical tags.

### Hardware validation
- Whole tag lifecycle seen on silicon with a Chameleon Ultra: plain SUN and
  encrypted file data provisioning, NDEF write lock, authenticated rewrite,
  per-UID rekey and the way back to factory keys.
- NXP originality key corrected and pinned with signatures read from three
  physical tags; `Read_Sig` accepts the `9190` status real tags return.

### Key provisioning
- `tools/rekey.py` refuses tags that cannot prove their identity: originality
  signature, inventory of keyed UIDs, proof of possession of their own keys,
  typed confirmation of the UID.
- Rekey back to factory keys is reported as done once reached, and a keyed
  tag is opened with its own keys first.
- An EV2 session is closed after any failed exchange or once the PICC ends it,
  so nothing is sent with a counter out of step.

### Provisioning
- NDEF writes locked to key 0 in every layout; writes on a locked tag
  authenticate first.
- Template written in 48-byte single-frame ISOUpdateBinary pieces without Le
  (the trailing Le of the AN12196 form is refused on silicon).

### Detection
- Durable tap ledger on the JSON, SQLite and Postgres stores: a stale counter
  is never authentic, replays cannot hide a clone or throttle the genuine tag,
  a withheld URL alerts once, concurrent copies of a tap yield one GENUINE.
- Forged taps never echo decrypted PICCData; crafted input is `ERROR`, never
  an exception; only the standard PICCData layout is accepted.
- One tap, one encoding: `picc_data` and `cmac` must be exact hex of the right
  length, a blank `enc=` still fails closed, and a URL without a query is
  never read through its path or fragment.

### API
- Client address from `X-Forwarded-For` only through trusted proxies (CIDR),
  IPv6 limited per /64, ASGI request guard (body cap, IP limit before
  parsing), query strings redacted in logs, webhooks without redirects and in
  the background, settings validated at start-up.
- Public `risk_score` fixed per verdict; link previewers get a neutral answer
  and do not spend the tap.

### Storage, secrets and readers
- Counter file locked, fsynced and owner-only; secrets directory checked for
  permissions, symlinks and zero keys; keys hidden from `repr`.
- Every reader exchange bounded (waiting-time extensions, response size,
  deadline), CID/NAD refused, NDEF length checked before reading.
- PN532 backend removed: the Chameleon Ultra is the supported reader.

### Supply chain
- Hash-locked CI dependencies, actions pinned by commit, pip-audit and bandit
  in CI, Dependabot, guard against the legacy PyCrypto package.
- Releases go to PyPI from GitHub through trusted publishing (no token),
  built with hash-locked tools, behind an approval on the `pypi` environment.

## 0.4.0 and earlier

Development releases: SUN/SDM verification against the NXP vectors, clone
detection, REST API, SDMENCFileData, Postgres backends, AN10922
diversification and per-UID key provisioning.
