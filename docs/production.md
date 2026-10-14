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

```python
from sphragis import Verifier, SqliteCounterStore, build_diversified_keys, EnvSecretsBackend
verifier = Verifier(build_diversified_keys(EnvSecretsBackend()),
                    SqliteCounterStore("counters.db"))
```

Any object implementing the `CounterBackend` protocol (`last_counter`,
`check_and_advance`) is a drop-in.

## Scaling to Postgres

The same logic is one atomic statement:

```sql
INSERT INTO counters (uid, counter) VALUES ($1, $2)
ON CONFLICT (uid) DO UPDATE SET counter = excluded.counter
WHERE excluded.counter > counters.counter;
```

Treat "0 rows affected" as a replay. This gives horizontal scale with the same
anti-rollback guarantee.

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

## Hardening checklist

- [ ] Keys in KMS/HSM, not in env on long-lived hosts
- [ ] Postgres (or equivalent) floor with atomic conditional update
- [x] Rate limiting on the verification endpoint (per IP + per authentic UID; in-process, see [API](api.md#rate-limiting))
- [x] Structured logging + alerting on `CLONE_LIKELY`
- [ ] Shared (e.g. Redis) rate limiter for multi-replica deployments
- [ ] Handling for 24-bit `SDMReadCtr` rollover
- [ ] Decide `SDMENCFileData` support from the real tag configuration
- [ ] End-to-end validation against physical tags
