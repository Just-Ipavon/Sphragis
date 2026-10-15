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
  submitting the same URL again is a `REPLAY` and raises no new alert;
- a counter **above the floor** → fresh: the floor advances and the detector
  scores it.

Stale taps touch nothing else: they never enter the detector's history and are
never charged to the per-UID rate limit, so replaying a captured URL can
neither hide a clone nor throttle the genuine tag. Two copies of the same tap
submitted at once yield one `GENUINE` and one `REPLAY`. A store upgraded from a
bare floor records where each UID's ledger began; counters at or below that
point are reported as `REPLAY` (`stale_counter`), since whether they were
submitted before is unknown.

## Signals

| Signal | Weight | Meaning |
|--------|--------|---------|
| `exact_replay` | 65 | the counter value was already submitted → a captured URL is being resent |
| `counter_regression` | 70 | below the floor and never submitted → a second device with its own counter stream (clone), or a genuine tap that was read and withheld (pre-play) |
| `impossible_velocity` | 60 | a fresh tap at one reader while another reader saw the tag less than `min_travel_seconds` before → two tags. Every authenticated reader observation in that window counts, so an anonymous tap in between hides nothing |
| `large_counter_gap` | 15 | an unusually large jump above the floor; weak / informational |
| `stale_counter` | 65 | below the floor the UID had when its ledger began (upgraded stores) |

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
