# Production & deployment

*English · [Italiano](production.it.md)*

Sphragis is the **generic, open verification engine**. A real deployment layers
its own product (provisioning, business logic, UI) on top of it in a separate
codebase. This document covers hardening the engine itself.

## Atomic anti-replay floor

The read-counter floor is the anti-replay / anti-rollback mechanism, and it must
be correct under concurrency. `SqliteCounterStore` enforces monotonicity inside
a serialized transaction:

- `BEGIN IMMEDIATE` takes the write lock up front, so the read-then-conditional-
  write cannot interleave (no TOCTOU) across threads **and** processes.
- WAL mode keeps readers non-blocking; `busy_timeout` makes writers wait.
- One connection per thread (a single connection must not run interleaved
  statements from multiple threads).
- `synchronous=FULL`: an acknowledged floor advance survives a power loss
  (with `NORMAL`, the last WAL transactions could roll back and their taps
  verify again). The database file is created readable by its owner only.

The JSON `CounterStore` used by the command-line tools is safe for a few
processes on one host: every change re-reads the file under an exclusive
`flock`, is fsynced (file and directory) before memory moves, and an empty or
corrupt file is refused rather than read as "no floors". It is not meant for a
service: use SQLite or Postgres there.

```python
from sphragis import Verifier, SqliteCounterStore, build_diversified_keys, EnvSecretsBackend
verifier = Verifier(build_diversified_keys(EnvSecretsBackend()),
                    SqliteCounterStore("counters.db"))
```

Any object implementing the `CounterBackend` protocol (`last_counter`,
`check_and_advance`) is a drop-in.

## Scaling to Postgres

Several hosts need one shared database. `sphragis.pgstore` (optional extra:
`pip install "sphragis[pg]"`, psycopg 3) implements the same contracts on
Postgres:

- **`PostgresCounterStore`**: `check_and_advance` is one atomic statement;
  the upsert locks the conflicting row, so two hosts racing on one UID cannot
  both accept a counter. No row returned means replay or rollback:

  ```sql
  INSERT INTO sphragis_counters AS c (uid, counter, updated_at) VALUES ($1, $2, $3)
  ON CONFLICT (uid) DO UPDATE SET counter = EXCLUDED.counter, updated_at = EXCLUDED.updated_at
  WHERE c.counter < EXCLUDED.counter
  RETURNING c.counter;
  ```

  It is also the analyzer's tap ledger: `record_tap` adds the counter to
  `sphragis_tap_counters` and advances the floor in one transaction,
  serialized per UID with an advisory lock (see
  [clone detection](clone-detection.md#the-tap-ledger)).

- **`PostgresObservationStore`**: `observe` reads the prior history, appends
  the tap and trims it in one transaction, serialized per UID with a
  transaction-scoped advisory lock.
- **`PostgresAlertSink`**: the alert audit trail, shared by every replica.

Tables (`sphragis_counters`, `sphragis_tap_counters`, `sphragis_tap_ledgers`,
`sphragis_observations`, `sphragis_alerts`) are created on first use. The tap
ledger grows by one small row per accepted tap; existing floors keep working
(counters below the floor a UID had when its ledger began read as `REPLAY`). Each thread holds its own connection; a broken one is
replaced on the next call and errors propagate, so a verification fails closed
rather than skipping the floor.

```python
from sphragis import PostgresCounterStore, Verifier, build_diversified_keys, EnvSecretsBackend
verifier = Verifier(build_diversified_keys(EnvSecretsBackend()),
                    PostgresCounterStore("postgresql://sphragis@db.internal/sphragis"))
```

The REST API switches to these backends when `SPHRAGIS_DB_URL` is set (see
[API](api.md#configuration)). Keep the password out of the URL: libpq reads
`PGPASSWORD` or `~/.pgpass`.

The test suite runs one conformance suite on SQLite and Postgres, including
many threads and several processes racing on one UID
(`tests/test_backends.py`; set `SPHRAGIS_TEST_PG_DSN`, CI starts a Postgres
service).

## Keys

Load keys from a managed KMS/HSM via a `SecretsBackend` (see
[key management](key-management.md)). Never commit key material; never hardcode.

## Observability

A production anti-counterfeiting backend should not return a silent boolean.
The [REST API](api.md) ships with:

- one structured JSON log event per verification (classification, score,
  signals, pseudonymized UID, event id), and never `picc_data` or `cmac`;
- **alerting on `CLONE_LIKELY`** through pluggable `AlertSink`s (CRITICAL log,
  HMAC-signed webhook);
- a durable audit trail of flagged events (`SqliteAlertSink`) for investigation.

Metrics can be derived from the log stream (count by `classification`).

## Shared detector history

The clone detector's per-UID history goes through an `ObservationStore`.
`SqliteObservationStore` makes it durable and shared by every process on the
host, with an atomic `observe()`, so several workers score one consistent
stream. See [the API docs](api.md#horizontal-scale-shared-detector-history).

## Dependencies and supply chain

- **Locked, hash-checked installs.** `requirements/ci.lock` pins every
  dependency of the `api`, `test` and `pg` extras with SHA-256 hashes, for
  Python 3.10–3.13. CI installs only from it (`pip install --require-hashes
  -r requirements/ci.lock`, then `pip install --no-deps -e .`); deploy the
  same way. After changing `pyproject.toml`, regenerate it with
  `uv pip compile pyproject.toml --universal --extra api --extra test
  --extra pg --generate-hashes -o requirements/ci.lock`.
- **Actions pinned by commit SHA**, workflows run with `contents: read`.
  Dependabot proposes updates to both the Python dependencies and the pins.
- **Security workflow:** `pip-audit` on the lock and `bandit` on the code, on
  every change and weekly, since new advisories appear without a commit.
- **pycryptodome, never PyCrypto.** Both install a `Crypto` package; the
  engine refuses to import if `Crypto` is not pycryptodome 3 or later, so a
  stray PyCrypto cannot silently take its place.
- Runtime state and secrets (`*.db`, `*.sqlite`, `keys/`, `.sphragis/`, key
  files) are git-ignored.

## Hardening checklist

- [ ] Keys in KMS/HSM, not in env on long-lived hosts
- [x] Postgres floor with atomic conditional update, shared history and audit trail
- [x] Rate limiting on the verification endpoint (per IP + per authentic UID; in-process, see [API](api.md#rate-limiting))
- [x] Structured logging + alerting on `CLONE_LIKELY`
- [ ] Shared (e.g. Redis) rate limiter for multi-replica deployments
- [ ] Handling for 24-bit `SDMReadCtr` rollover
- [x] `SDMENCFileData` verification and provisioning (validated on a physical tag)
- [x] End-to-end validation against physical tags
