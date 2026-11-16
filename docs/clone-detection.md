# Clone detection

*English · [Italiano](clone-detection.it.md)*

A valid SDMMAC proves **key possession**, not **physical uniqueness**. An
attacker who extracts a tag's keys can mint a perfect clone whose MACs all
verify. The only thing a clone cannot fake is a globally consistent, monotonic
read counter. Sphragis turns that into a *scored* verdict rather than a boolean.

## The tap ledger

Every authentic tap is first checked against the **tap ledger**: the
anti-replay floor plus every counter value ever submitted for the UID, kept in
the same durable store and updated in one atomic step (`record_tap`). It
decides stale taps exactly, whatever happened in between:

- a counter value **already submitted** → `REPLAY`;
- a counter **below the floor, never submitted** → `CLONE_LIKELY`, **once**:
  submitting the same URL again is a `REPLAY` and raises no new alert. The
  only exception is a counter at most `reorder_counters` (2) below the floor,
  from the same authenticated reader that set the floor less than
  `reorder_seconds` (2 s) earlier: two quick taps whose requests arrived out
  of order, reported as `SUSPICIOUS` (`counter_reordered`);
- a counter **above the floor** → fresh: the floor advances and the detector
  scores it.

Replays touch nothing else: they never enter the detector's history, and no
stale tap is charged to the per-UID rate limit, so replaying a captured URL can
neither hide a clone nor throttle the genuine tag. A regression does enter the
history, as evidence that the UID's counter stream has forked (see below). Two copies of the same tap
submitted at once yield one `GENUINE` and one `REPLAY`. A store upgraded from a
bare floor records where each UID's ledger began; counters at or below that
point are reported as `REPLAY` (`stale_counter`), since whether they were
submitted before is unknown.

The ledger and the detector history are two writes, often in two stores. So
that a crash or a failing history store between them cannot consume a
counter that never reaches the history (or swallow a regression alert), the
ledger keeps a note of each new tap in the same transaction and drops it
once the history write succeeds. The next tap of that UID, a retry of the
same URL included, finishes any note left behind; a regression found that way
is reported with that tap, as `CLONE_LIKELY` with `counter_regression`, so its
alert is raised late rather than never.

### Retention

By default the ledger keeps every counter ever submitted. With a window
(`SPHRAGIS_LEDGER_WINDOW=N`, or `ledger_window=N` on the counter stores) it
keeps the counters within `N` of the floor one by one, and summarises older
ones by moving the same "ledger began" mark up to `floor - N`, in the same
transaction as the tap. Taps within the window are classified exactly as
before; a counter at or below the mark is a `REPLAY` (`stale_counter`). The
trade-off: a withheld URL older than `N` reads becomes `REPLAY` instead of
`CLONE_LIKELY`, so choose `N` above the number of reads a tag can make while
a captured URL is held back. The ledger then holds at most `N` counters per
UID.

## Signals

| Signal | Weight | Meaning |
|--------|--------|---------|
| `exact_replay` | 65 | the counter value was already submitted → a captured URL is being resent |
| `counter_regression` | 70 | below the floor and never submitted → a second device with its own counter stream (clone), or a genuine tap that was read and withheld (pre-play) |
| `impossible_velocity` | 60 | a fresh tap at one reader while another reader saw the tag less than `min_travel_seconds` before → two tags. Every authenticated reader observation in that window counts, so an anonymous tap in between hides nothing |
| `large_counter_gap` | 15 | an unusually large jump above the floor; weak / informational |
| `stale_counter` | 65 | at or below the oldest counter the ledger keeps for the UID (upgraded stores, retention window) |
| `counter_rate` | 40 | more unseen reads since the floor was set than a tag can produce (`max_tap_rate`, 25/s, after `rate_slack_seconds`, 2 s, of jitter allowance): e.g. +500 in 10 s. An emulator or a clone with a set counter, or a URL delivered long after its tap |
| `prior_divergence` | 35 | a fresh tap on a UID whose history already holds a regression: the counter stream has forked, so either device may be tapping |
| `counter_reordered` | 30 | just below the floor, same reader, moments later: out-of-order delivery of two quick taps |

## A forked UID stays suspect

After a regression, a stateless check would see the clone's next tap (say 16
after a floor of 15) as monotonic and `GENUINE`. A regression therefore stays
in the detector's history and every later fresh tap carries
`prior_divergence`: `CLONE_LIKELY` does not mean *this tap is the fake*, it
means *this UID's counter stream has forked*. The signal is weak on its own,
since anyone who reads a tag without submitting the URL and submits it after
the owner's next tap can cause a regression; combined with another signal
(velocity, rate) it reaches `CLONE_LIKELY`. It fades once the counter the
regression fell below leaves the `history_limit` window.

## Counter exhaustion

Reading a tag many times without submitting the URLs moves its counter far
ahead. That costs the owner nothing: the next genuine tap is fresh, and the
jump raises at most `large_counter_gap` and, if fast, `counter_rate` —
`SUSPICIOUS`, never a lasting block.

## Tag lifecycle

**Revocation list.** A lost, stolen or returned tag still holds its keys and
keeps producing valid taps. Put it on the revocation list and its taps answer
`REVOKED`, checked once the MAC has verified and before the ledger or the
detector are touched (so a made-up UID learns nothing):

```bash
sphragis revoke 04DE5F1EACC040 --sqlite sphragis.db --reason "reported stolen"
sphragis revoke 04DE5F1EACC040 --sqlite sphragis.db --retire --reason returned
sphragis revocations --sqlite sphragis.db
sphragis reinstate 04DE5F1EACC040 --sqlite sphragis.db
```

(`--db-url postgresql://…` for the shared database.) `revoked` and `retired`
both answer `REVOKED`; the signal (`revoked` or `retired`) and the detail
carry the status and reason. `REVOKED` raises an alert by default.

**Counter rollover.** `SDMReadCtr` is 24-bit: at 16 777 215 the tag stops
emitting taps. `CounterPolicy(warn_at=…)` (`SPHRAGIS_COUNTER_WARN_AT`, default
65 536 taps before the limit) adds the `counter_near_limit` signal to the
first fresh tap that reaches the threshold, and the service alerts on it.
The ledger accepts each counter value once, so the alert fires once per tag,
on every replica together. A clone that holds the keys can also jump a UID
to the maximum, after which every genuine tap is a regression.
`refuse_at` (`SPHRAGIS_COUNTER_REFUSE_AT`, off by default) answers
`COUNTER_LIMIT` for taps at or above it and leaves the floor where it was, so
such a jump cannot pin the floor. Recovery in both cases: retire the tag
(`sphragis revoke --retire`) and issue a new one; a rekey does not reset
`SDMReadCtr`.

**Alert throttling.** `AlertThrottle` (on by default in the API) drops an
alert identical to one sent for the same tag in the last
`SPHRAGIS_ALERT_DEDUP_SECONDS` (300) and allows each tag
`SPHRAGIS_ALERT_UID_BURST` (5) alerts per `SPHRAGIS_ALERT_UID_WINDOW` (3600 s).
Someone replaying a stack of withheld URLs for one tag therefore cannot fill
the webhook queue and push out the alerts for other tags. Suppressed alerts
are logged (`alert_suppressed`) and counted; the signed events and the
verification log still record every tap. The counts, and the alerts the
webhook queue dropped, are at `GET /v1/alert-stats` (reader token). The
throttle is per process: with N replicas a tag can raise up to N times the
budget.

## Scoring

Weights aggregate into a 0–100 risk score mapped to a classification:

- **≥ 60** → `CLONE_LIKELY` (or `REPLAY` when the only strong signal is an exact replay)
- **25–59** → `SUSPICIOUS`
- **> 0** → `SUSPICIOUS`
- **0** → `GENUINE`

The result carries the score and the human-readable signals, so it can feed a
review/escalation workflow instead of silently allowing or denying.

## The honest edge cases

- A lower counter never submitted is either a clone's own stream or a genuine
  URL that someone read and kept (pre-play). The two are cryptographically
  indistinguishable; both mean the tag was duplicated or read without its
  owner, so the alert is warranted, and each such URL alerts only once. A
  clone that only re-emits values already submitted is reported as `REPLAY`.
- A single clone used in place of a destroyed original can look perfectly
  monotonic. Counter-only detection needs to see **both** tags, or side
  information (location/velocity). See the [threat model](../THREAT_MODEL.md).

Detection is **probabilistic and observational**: it raises confidence over
repeated scans, it is not a single-scan guarantee of physical uniqueness.
