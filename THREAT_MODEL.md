# Threat model

*English · [Italiano](THREAT_MODEL.it.md)*

What this system defends, how, and — just as important — what it does **not**
defend. Every claim here is backed by an executable attack in
`tests/test_adversarial.py`.

## Assets

- **Authenticity of a tap**: proof that a scanned URL was produced by a genuine
  tag holding the secret keys.
- **Uniqueness of a physical tag**: assurance that there is only *one* physical
  tag for a given identity (the anti-counterfeiting goal).

## Trust assumptions

- The verifier backend is trusted and its key storage is secure.
- `K_SDMMetaReadKey` and `K_SDMFileReadKey` (or the master key they are
  diversified from) are secret. Per-UID diversification (AN10922) limits the
  blast radius if a single tag is compromised.
- AES-128 and AES-CMAC are sound. We rely on the primitives, not on secrecy of
  the scheme (which is the public NXP SDM/SUN standard).

## Adversaries and mitigations

| # | Adversary capability | Attack | Mitigation | Test |
|---|----------------------|--------|------------|------|
| 1 | Observe & resend URLs | **Replay** a captured tap | Read-counter: the counter was already seen → `REPLAY` | `test_replay_attack_is_caught` |
| 2 | Tamper with bytes | **Forge** the SDMMAC (flip bits) | CMAC verification fails → `FORGED` | `test_forged_mac_is_caught` |
| 3 | Tamper with bytes | Submit a **truncated** MAC | Structural + CMAC rejection → `FORGED` | `test_truncated_mac_is_rejected` |
| 4 | Store old URLs | **Counter rollback**: resend an older, lower-counter tap | Counter not fresh → `REPLAY`/`CLONE_LIKELY` | `test_counter_rollback_is_caught` |
| 5 | **Extract keys**, build a perfect clone | Clone runs its own counter stream | Counter **divergence** (value below the max ever seen) → `CLONE_LIKELY` | `test_key_clone_caught_by_counter_divergence` |
| 6 | **Extract keys**, deploy clone elsewhere | Clone scanned far away, seconds apart | **Impossible velocity** across readers → `CLONE_LIKELY` | `test_key_clone_caught_by_impossible_velocity` |
| 7 | Local timing observation | Side-channel on MAC compare | Constant-time comparison via `hmac.compare_digest` | `test_mac_comparison_correctness`, `test_mac_comparison_uses_non_short_circuiting_primitive` |
| 8 | Query the public API | Use the verdict as an **oracle** to iterate on a forgery | Public tier maps malformed *and* forged to one `INVALID` answer; no UID, counter or signal detail | `test_forged_and_malformed_are_indistinguishable_publicly` |
| 9 | Send arbitrary requests | **Spoof `reader_id`** to fake or dodge impossible-velocity | `reader_id` derived only from an authenticated reader token; body field rejected, query param ignored; time from the server clock | `test_query_reader_id_cannot_fake_velocity`, `test_post_rejects_client_supplied_reader_and_oversized_url`, `test_service_uses_server_clock_not_client_time` |
| 10 | Flood the endpoint | **Resource exhaustion** / log flooding | Per-IP token bucket before crypto; per-UID bucket after the MAC (throttled taps touch no state); `X-Forwarded-For` only from trusted proxies | `test_ip_rate_limit_returns_429_with_retry_after`, `test_uid_rate_limit_throttles_authentic_taps`, `test_forwarded_for_ignored_unless_peer_is_trusted_proxy` |
| 11 | Run clones against different workers | Split the observation stream so no worker sees the divergence | Shared, atomic `ObservationStore` (SQLite) across processes | `test_clone_caught_across_workers_sharing_history`, `test_sqlite_observe_is_atomic_under_concurrency` |

The key insight for #5–#7: once an attacker has the keys, the MAC can no longer
distinguish a clone from the original — **only the behaviour of the read counter
over time can**. That is why this project treats counter analysis as a
first-class, scored detector rather than a simple freshness flag.

## Known limitations (honest scope)

- **A single clone used in place of a lost original.** If the genuine tag is
  destroyed and only the clone is ever scanned, its counter can look perfectly
  monotonic. Detection relies on seeing *both* tags, or on side information
  (location/velocity). This is a fundamental limit of counter-only schemes, not
  a bug.
- **A clone that first observes the original's counter** and always stays ahead
  will avoid regression signals; it is then caught only by velocity/location or
  by eventually colliding with the original's stream.
- **Relay/NFC-forwarding attacks** at scan time are out of scope — they attack
  the reader-to-tag channel, not the SDM message.
- **Factory keys on provisioned tags.** `tools/provision.py` alone leaves the
  all-zero factory keys in place. With known keys anyone can compute valid
  PICCData and SDMMAC values, so such a tag proves nothing until
  `tools/rekey.py` has replaced its keys with secret per-UID ones (see
  [key management](docs/key-management.md#writing-keys-to-tags); not yet
  validated on hardware). Whoever holds `master_admin` can reconfigure every
  tag; it belongs on the provisioning station only.
- **Rewriting the tag's URL.** The plain SUN MAC covers no static data, so a
  freely writable NDEF file would let anyone with a phone point a genuine tag
  at another site while it keeps emitting valid taps. Provisioning locks NDEF
  writes in every layout, to key 0, 3 or 4 (never to the FileRead or MetaRead
  keys verification servers hold). The lock means something only once
  `tools/rekey.py` has replaced the all-zero keys.
- **Impersonation at keying time.** A tag is first keyed under the public
  factory key, so a device posing as a factory tag would receive the keys of
  the UID it claims. `rekey_tag` verifies the NXP originality signature,
  refuses a UID already in its inventory that shows factory keys, and requires
  claimed keys to authenticate (see
  [keying safely](docs/key-management.md#keying-safely)). A passive radio
  capture of a factory keying session still yields its keys: key tags in a
  shielded place, from a controlled supply.
- **Counter exhaustion**: `SDMReadCtr` is 24-bit. Rollover handling is a
  deployment concern and not modelled here.
- `TagAnalyzer` keeps a persistent monotonic anti-replay floor (`CounterBackend`)
  *and* a scoring detector whose history lives in an `ObservationStore`. With
  the default in-memory store the scoring is rebuilt from the live stream after
  a restart; `SqliteObservationStore` (used by the API) makes it durable and
  shared across processes on one host; with `SPHRAGIS_DB_URL` the Postgres
  backends share floor, history and alerts across hosts.
- **Per-UID budget**: only counters above the floor, which need the physical
  tag, are charged to the per-UID rate limit; replays of a captured URL are
  answered `REPLAY` without touching it, so they cannot throttle the genuine
  tag. Someone who holds the tag can still spend its budget with fresh taps.
- **Withheld URLs (pre-play)**: someone who reads a tag without submitting the
  URLs can present them later, once each. Above the floor they verify as
  genuine (a one-time window that only a verifier challenge closes); below it
  each raises one `CLONE_LIKELY`, never more, since the tap ledger remembers
  every counter submitted.
- **Public taps carry no location**: impossible-velocity needs authenticated
  readers; anonymous phone taps feed only the counter-based signals.
- The in-process rate limiter is per replica; a global limit needs a shared
  `RateLimiter` backend.

## Residual risk

Anti-clone detection is **probabilistic and observational**: it raises
confidence over repeated scans, it does not provide a single-scan guarantee of
physical uniqueness. The scored output (`risk_score`, `signals`) is designed to
feed a review/escalation workflow, not to be a silent boolean.
