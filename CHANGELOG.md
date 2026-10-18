# Changelog

Italiano: [CHANGELOG.it.md](CHANGELOG.it.md). Versions follow
[Semantic Versioning](https://semver.org/).

## Unreleased

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
