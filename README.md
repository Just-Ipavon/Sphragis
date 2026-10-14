# Sphragis — a cryptographic seal of authenticity for NTAG 424 DNA

[![CI](https://github.com/Just-Ipavon/Sphragis/actions/workflows/ci.yml/badge.svg)](https://github.com/Just-Ipavon/Sphragis/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%E2%80%933.13-blue)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)

**English** · [Italiano](README.it.md)

> *sphragís* (σφραγίς) — the ancient Greek signet seal that proved a thing
> genuine. Here it is the cryptographic seal that proves an NFC tag — and the
> object it is attached to — authentic and unique.

A focused, well-tested toolkit that does one thing deeply: decide whether an
NFC tap came from a **genuine, unique** NXP **NTAG 424 DNA** tag — or from a
**clone**.

> ⚠️ **Status: learning / portfolio project.** The cryptography is validated
> against the official NXP test vectors and the code was adversarially
> self-reviewed (see the [threat model](THREAT_MODEL.md)), but it has **not**
> been independently audited. It has been validated end to end against physical
> NTAG 424 DNA tags with factory keys (see [docs/hardware.md](docs/hardware.md)),
> but not with production key management. Do not use it as the sole line of
> defense in production without that work.

Anyone can check an AES-CMAC. The hard, interesting part of anti-counterfeiting
is what happens *after* the MAC is valid: proving there is only **one** physical
tag. This project treats that as a first-class, scored problem.

Three pillars:

1. **Correct crypto** — standard NXP SDM/SUN verification, validated against the
   **official NXP AN10922/AN12196 test vector**.
2. **Clone-detection intelligence** — a scored engine (replay, counter
   divergence, impossible velocity) that unmasks even a key-extracted clone.
3. **Adversarial rigor** — a documented [threat model](THREAT_MODEL.md) and a
   harness that mounts real attacks and proves they are caught.

## Why the read counter is the whole game

A valid SDMMAC proves only that *whoever produced this tap holds the secret
key*. It cannot prove there is a single physical tag. An attacker who extracts
the keys can make a perfect clone whose MACs all verify. What they **cannot**
fake is a globally consistent, monotonic read counter across every reader in the
world. So Sphragis scores the counter's behaviour over time:

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

## How verification works

On every tap a tag appends dynamic parameters to a URL:

```
https://example.com/t?picc_data=EF963FF7828658A599F3041510671E88&cmac=94EED9EE65337086
```

- **`picc_data`** — AES-128-CBC encrypted block with the UID and read counter.
- **`cmac`** — truncated AES-CMAC (SDMMAC) authenticating the read.

Pipeline:

```
 tapped URL ─▶ parse ─▶ decrypt PICCData ─▶ verify CMAC ─▶ score counter ─▶ verdict
                              │                  │               │
                           UID + ctr        authenticity   clone / replay
```

Classifications: `GENUINE`, `SUSPICIOUS`, `REPLAY`, `CLONE_LIKELY`, `FORGED`, `ERROR`.

## Install

```bash
pip install -r requirements.txt   # pycryptodome
```

## Quick start (no hardware needed)

```python
import os
from sphragis import TagAnalyzer, DiversifiedKeys
from sphragis.emulator import tag_from_provider

# Per-UID diversified keys (AN10922) — the production key-management pattern.
master, meta = os.urandom(16), os.urandom(16)
keys = DiversifiedKeys(master_file_key=master, meta_read_key=meta, context=b"ART")

tag = tag_from_provider(keys, uid=bytes.fromhex("04DE5F1EACC040"))
analyzer = TagAnalyzer(keys)

r = analyzer.analyze(tag.tap(), reader_id="gate-A")
print(r.classification, r.risk_score)   # GENUINE 0
```

Run the demos:

```bash
python examples/demo.py         # authentic / replay / forgery
python examples/clone_demo.py   # key-extracted clone caught by the counter
```

## Command line

```bash
# Verify the official NXP vector (all-zero keys)
python -m sphragis.cli verify \
  --meta-key 00000000000000000000000000000000 \
  --file-key 00000000000000000000000000000000 \
  "https://example.com/t?picc_data=EF963FF7828658A599F3041510671E88&cmac=94EED9EE65337086"

# Decode what a tag emits: PICCDataTag, UID, SDMReadCtr (LE), NDEF offsets.
# Diagnostic only, no verdict; keys default to the all-zero factory keys.
python -m sphragis.cli inspect \
  "https://example.com/t?picc_data=EF963FF7828658A599F3041510671E88&cmac=94EED9EE65337086"
```

## REST API

An optional FastAPI front end (`pip install "sphragis[api]"`). It takes the
tapped URL and returns a scored verdict, writes one structured JSON log event
per verification, alerts on `CLONE_LIKELY` and rate-limits requests:

```bash
uvicorn --factory sphragis.api:create_app_from_env
curl "http://localhost:8000/t?picc_data=…&cmac=…"
# {"event_id":"…","verdict":"GENUINE","risk_score":0,"message":"Authentic tag."}
```

The public response is deliberately minimal: forged and malformed inputs return
the same `INVALID` answer, so the endpoint gives an attacker no oracle.
Authenticated readers get the full assessment, and their `reader_id` comes from
their token only. See [docs/api.md](docs/api.md).

## Tests

```bash
pip install -e ".[api,test]"
python -m pytest -q      # add ".[pg]" and SPHRAGIS_TEST_PG_DSN to run the Postgres half
```

- **Known-answer**: reproduces the official NXP AN12196 vectors (plain SUN,
  SDMENCFileData, EV2 secure messaging) and taps recorded from a physical tag.
- **Adversarial**: replay, forged MAC, truncated MAC, counter rollback,
  key-clone divergence, impossible velocity, constant-time MAC comparison.
- **Production**: one conformance suite on SQLite and Postgres, with threads
  and processes racing on one UID; secrets backends.
- **Provisioning**: full flows against a fake PICC (plain SUN and encrypted
  mirror, write lock, authenticated rewrite).
- **Service & API**: shared detector history across workers, no-oracle public
  tier, `reader_id` spoofing, alerting on a real key-clone, rate limiting.

## Production hardening

This repository is the **generic, open verification engine** — hardened toward
production, but deliberately application-agnostic. A real deployment layers its
own product on top of it (provisioning, business logic) in a separate codebase;
the public engine stays reusable and clean.

- **Atomic anti-replay floor** — `SqliteCounterStore` enforces counter
  monotonicity inside a serialized transaction (no TOCTOU across threads or
  processes); `PostgresCounterStore` does it in one atomic statement for
  several hosts (`pip install "sphragis[pg]"`).
- **No keys in code** — `secrets.py` abstracts key material behind a
  `SecretsBackend` (env / file / KMS extension point).
- **Constant-time MAC comparison**, fail-closed input validation, documented
  threat model.

```python
from sphragis import Verifier, SqliteCounterStore, EnvSecretsBackend, build_diversified_keys

keys = build_diversified_keys(EnvSecretsBackend())            # keys from env/KMS
verifier = Verifier(keys, SqliteCounterStore("counters.db"))  # durable, atomic
```

## Documentation

| Topic | English | Italiano |
|-------|---------|----------|
| Protocol (SDM/SUN) | [protocol.md](docs/protocol.md) | [protocol.it.md](docs/protocol.it.md) |
| Clone detection | [clone-detection.md](docs/clone-detection.md) | [clone-detection.it.md](docs/clone-detection.it.md) |
| Key management | [key-management.md](docs/key-management.md) | [key-management.it.md](docs/key-management.it.md) |
| REST API | [api.md](docs/api.md) | [api.it.md](docs/api.it.md) |
| Production & deployment | [production.md](docs/production.md) | [production.it.md](docs/production.it.md) |
| Physical tags (bench) | [hardware.md](docs/hardware.md) | [hardware.it.md](docs/hardware.it.md) |
| Threat model | [THREAT_MODEL.md](THREAT_MODEL.md) | [THREAT_MODEL.it.md](THREAT_MODEL.it.md) |
| Security policy | [SECURITY.md](SECURITY.md) | [SECURITY.md](SECURITY.md) |

## Project layout

```
sphragis/
  sdm.py           SDM crypto primitives (PICCData decrypt, session key, SDMMAC)
  verifier.py      simple URL -> verdict pipeline
  sdmenc.py        SDMENCFileData primitives (ENC session key, IV, decrypt)
  encverifier.py   URL -> verdict + decrypted file data (encrypted mirror)
  counterstore.py  JSON read-counter store + CounterBackend protocol
  sqlstore.py      SQLite anti-replay floor with atomic check-and-advance
  pgstore.py       Postgres floor / history / alert audit for multi-host (extra `sphragis[pg]`)
  secrets.py       key-material backends (env / file / KMS extension point)
  diversify.py     AN10922 per-UID key diversification
  detection.py     scored clone-detection engine (signals + risk score)
  observations.py  detector history stores (memory / SQLite, atomic observe)
  analyzer.py      full pipeline: crypto + detection -> scored assessment
  service.py       framework-agnostic verification service (logs, alerts)
  alerts.py        alert sinks (log / SQLite audit trail / signed webhook)
  logs.py          JSON log formatter + UID pseudonymization
  ratelimit.py     token-bucket rate limiter
  api/             FastAPI app (optional extra `sphragis[api]`)
  adversary.py     attacker toolkit (replay, forge, rollback, key-clone)
  emulator.py      software NTAG 424 DNA tag (generates valid SUN URLs)
  diagnostics.py   tap inspection (PICCData byte layout, NDEF offsets)
  ndef.py          NDEF URI file encoding + SDM offset arithmetic
  apdu.py          ISO 7816-4 APDU helpers
  transport/       ApduTransport: scripted / emulated / ISO-DEP / Chameleon Ultra / PN532
  ev2.py           AuthenticateEV2First + secure messaging (AN12196 vectors)
  sdmconfig.py     SDM file settings: build / parse ChangeFileSettings
  provision.py     idempotent zero-key SUN provisioning flow
  cli.py           command-line verify / inspect / emulate
tools/             sdm_probe / provision / tap_verify (run on the hardware host)
tests/             known-answer + adversarial + production + service/API suites
examples/          demo.py, clone_demo.py
docs/              bilingual technical documentation
```

## References

- NXP **AN12196** — *NTAG 424 DNA features and hints (SDM).*
- NXP **AN10922** — *Symmetric key diversifications.*

## License

GPL-3.0-or-later — see [LICENSE](LICENSE).
