# REST verification API

*English · [Italiano](api.it.md)*

An optional HTTP front end for the engine: it takes the URL of a tap and
returns a scored verdict. It also writes one structured log event per
verification, raises an alert on `CLONE_LIKELY`, and rate-limits requests.

```bash
pip install "sphragis[api]"
export SPHRAGIS_MASTER_FILE=<hex>  SPHRAGIS_META_READ=<hex>  SPHRAGIS_LOG_PSEUDONYM=<hex>
uvicorn --factory sphragis.api:create_app_from_env --host 0.0.0.0 --port 8000 --no-access-log
```

The core package still depends only on `pycryptodome`. FastAPI and uvicorn are
pulled in by the `api` extra alone.

**Access logs.** A tapped URL carries `picc_data` and `cmac`, and a tap that
was never verified stays redeemable from wherever it is written down. The app
strips the query string from uvicorn's access-log lines (`QueryRedactingFilter`
on `uvicorn.access`); `--no-access-log` is stricter still. Configure any
reverse proxy in front the same way (log the path, not the query).

## Architecture

```
 HTTP ─▶ IP rate limit ─▶ reader auth ─▶ VerificationService ─▶ response tier
                                              │
                    TagAnalyzer (SDM crypto + clone detection)
                    │  per-UID admission (rate limit, after the MAC)
                    │  server clock, never client time
                    ├─▶ JSON log event (pseudonymized UID)
                    └─▶ AlertSinks on CLONE_LIKELY (log · SQLite/Postgres · webhook)
```

`VerificationService` (`sphragis/service.py`) does not depend on any framework,
so it can be tested without HTTP. `sphragis/api/` is a thin adapter on top of it.

## Endpoints

| Method | Path | Use |
|--------|------|-----|
| `GET`  | `/t?picc_data=…&cmac=…` | The URL a tag points to: a phone opens it on tap |
| `POST` | `/v1/verify` `{"url": "…"}` | An app or backend forwards a tapped URL |
| `GET`  | `/healthz` | Liveness probe (not rate limited) |

Verdicts are always returned as `200`. The other status codes are `401` (bad
credentials), `422` (malformed body or unknown fields) and `429` (rate limited,
with `Retry-After`). Responses carry `Cache-Control: no-store`. The interactive
docs (`/docs`, `/openapi.json`) are off by default.

## Two response tiers

**Public**: anyone who taps the tag gets:

```json
{"event_id": "…", "verdict": "GENUINE", "risk_score": 0, "message": "Authentic tag."}
```

`verdict` ∈ `GENUINE`, `SUSPICIOUS`, `REPLAY`, `CLONE_LIKELY`, `INVALID`.
Malformed **and** forged inputs both become `INVALID` with score 100. The
public tier never returns the UID, the counter or signal details. Without that
rule the endpoint would be an oracle telling an attacker which byte of a forged
or cloned tap is wrong. For the same reason `risk_score` is fixed per verdict
(`GENUINE` 0, `SUSPICIOUS` 50, the others 100); readers get the analyzer's
score.

Link previewers (WhatsApp, Telegram, Slack, Discord, Facebook and similar,
recognised by `User-Agent`) get `{"message": ...}` without verifying, so
sharing the link in a chat does not spend the tap and the owner's next open is
not a `REPLAY`. A forged `User-Agent` only gets the same neutral answer.

**Detailed**: with `Authorization: Bearer <reader token>` the response also
includes `classification`, `uid`, `read_counter`, `reader_id`, `signals`
(name, weight, detail), `detail` and `alerted`. Forged and malformed taps get
the same answer here too (`classification: INVALID`, no UID, no counter):
telling them apart would be an oracle on the decrypted PICCData. The log keeps
the real classification.

A bad or malformed token is rejected with `401`. The request is not silently
downgraded to the public tier.

## Readers and `reader_id`

The impossible-velocity check needs to know *where* a tap happened. The
`reader_id` is derived **only** from the authenticated token and is never read
from the request. A `reader_id` field in the body is rejected (`422`), and one
in the query string is ignored. If the client could choose its reader id, an
attacker could fake velocity alerts against a genuine tag or dodge them for a
clone.

Configure readers as `reader-id=sha256(token)` pairs. Only hashes are stored,
so a leaked configuration does not leak credentials:

```bash
python -c "import secrets,hashlib;t=secrets.token_urlsafe(32);print(t, hashlib.sha256(t.encode()).hexdigest())"
export SPHRAGIS_READER_TOKENS="gate-A=<sha256>,gate-B=<sha256>"
```

Public taps from phones carry no reader id. They still feed the counter floor
and the counter-divergence scoring, but not the velocity check.

## Structured logging

There is one JSON line per verification on stdout, written with the stdlib
`logging` module (`sphragis.logs.JsonFormatter`):

```json
{"ts":"…","level":"WARNING","logger":"sphragis.verify","event":"verification",
 "event_id":"…","classification":"CLONE_LIKELY","risk_score":100,
 "signals":["counter_regression","impossible_velocity"],
 "uid_ref":"h:3f…","read_counter":3,"reader_id":"gate-B","alerted":true}
```

- `uid_ref` is `HMAC-SHA256(log_pseudonym, UID)`. It is stable per tag, so
  events can be correlated, but it cannot be reversed without the key. Set
  `SPHRAGIS_LOG_UID=plain` only if the UID is not sensitive in your deployment.
- `picc_data`, `cmac` and key material are never logged.
- `event_id` is also returned to the client, which lets support match a user's
  report to the log line.

## Alerts

`CLONE_LIKELY` (configurable with `SPHRAGIS_ALERT_ON`, e.g.
`CLONE_LIKELY,REPLAY`) is sent to every configured `AlertSink`:

| Sink | Purpose |
|------|---------|
| `LogAlertSink` | `CRITICAL` event on logger `sphragis.alert`. Route it to your pager |
| `SqliteAlertSink` | Durable audit trail (`alerts` table, `recent(uid_ref=…)`) for investigation |
| `WebhookAlertSink` | HTTPS POST, signed `X-Sphragis-Signature: sha256=HMAC(secret, ts + "." + body)` |

The webhook receiver must verify the signature in constant time and reject
stale `X-Sphragis-Timestamp` values: `sphragis.alerts.verify_webhook(secret,
timestamp, signature, body)` does both. A failing sink is logged and skipped:
it never breaks verification or the other sinks. `create_app_from_env` runs
the webhook on a background worker (`BackgroundAlertSink`, bounded queue), so a
slow endpoint never delays a tap; delivery has a 2 s timeout and no retry,
only a 2xx answer counts, and redirects are refused (they would replay the
signed alert elsewhere). Keep the SQLite or Postgres sink as the system of
record.

## Rate limiting

- **Per client IP**, before any crypto (default: 5/s, burst 20).
- **Per tag UID**, only for taps whose SDMMAC verified (default: 0.2/s, burst
  10). A throttled tap returns `429` and touches **no** state, so a genuine tap
  does not burn its counter value. Forged junk cannot drain a specific tag's
  budget.
- `X-Forwarded-For` is honoured only when the direct peer is listed in
  `SPHRAGIS_TRUSTED_PROXIES` (addresses or CIDR networks). Every header line
  is read, in order, and the client is the right-most untrusted hop, so a
  proxy that appends its own line (HAProxy `option forwardfor`) cannot be
  outvoted by a line the client sent. IPv6 clients are limited per /64.
- The per-IP limit and a body cap (`SPHRAGIS_MAX_BODY_BYTES`, 8 KiB) apply
  before the request is parsed: oversized bodies get `413` without being read
  in full, and invalid JSON counts against the limit like any other request.

The `TokenBucketLimiter` works within a single process. With N replicas the
effective limit is N times higher. For a global limit, implement the
`RateLimiter` protocol on a shared store such as Redis.

## Horizontal scale: shared detector history

The clone detector scores each tap against the tag's *history*. Kept in
memory, every worker would see only a slice of the taps. `create_app_from_env`
therefore stores the history in `SqliteObservationStore`, in the same database
as the counter floor and the alerts. Its `observe()` call is atomic (it reads
the prior history and appends the new tap in one step), so concurrent taps
are scored against each other. Several uvicorn workers on one host share the
same view. For several hosts set `SPHRAGIS_DB_URL`: the floor, the history
and the alert audit trail then live in one Postgres database shared by every
replica (see [production](production.md#scaling-to-postgres)).

## Configuration

| Variable | Default | Meaning |
|----------|---------|---------|
| `SPHRAGIS_DB_PATH` | `sphragis.db` | SQLite file: counter floor, history, alerts |
| `SPHRAGIS_DB_URL` | none | `postgresql://` URL; replaces SQLite for multi-host (needs `sphragis[pg]`) |
| `SPHRAGIS_KEY_CONTEXT` | empty | AN10922 diversification context |
| `SPHRAGIS_READER_TOKENS` | none | `reader=sha256hex,…` |
| `SPHRAGIS_TRUSTED_PROXIES` | none | proxy IPs or CIDRs allowed to set `X-Forwarded-For` |
| `SPHRAGIS_IP_RATE` / `_IP_BURST` | `5` / `20` | per-IP bucket |
| `SPHRAGIS_UID_RATE` / `_UID_BURST` | `0.2` / `10` | per-tag bucket |
| `SPHRAGIS_MIN_TRAVEL_SECONDS` | `60` | impossible-velocity threshold |
| `SPHRAGIS_ALERT_ON` | `CLONE_LIKELY` | classifications that raise an alert |
| `SPHRAGIS_MAX_BODY_BYTES` | `8192` | largest accepted request body |
| `SPHRAGIS_WEBHOOK_URL` | none | alert webhook (https only) |
| `SPHRAGIS_LOG_UID` | `hmac` | `hmac` or `plain` |
| `SPHRAGIS_LOG_LEVEL` | `INFO` | log level |

Every value is validated at startup: rates, bursts and the travel time must
be finite and positive, `SPHRAGIS_ALERT_ON` must name known classifications.
A typo stops the service instead of silently disabling a limit or an alert.

Secrets are read through a `SecretsBackend` (`EnvSecretsBackend` by default,
which expects `SPHRAGIS_<NAME>` as hex): `master_file` and `meta_read` are
required, `log_pseudonym` is required in `hmac` mode, and `webhook` is
required when a webhook URL is set. To use a KMS, pass your own backend to
`create_app_from_env(secrets=…)`.

## Known limitations

- A `REPLAY` is also what a user sees after **reloading** the verification
  page: the URL was already used. The public message asks them to tap the tag
  again.
- Only counters above the floor are charged to a tag's per-UID budget, so
  replaying a captured URL cannot throttle the genuine tag; someone holding
  the tag can still spend it with fresh taps.
- Public taps carry no location, so velocity detection needs authenticated
  readers.
