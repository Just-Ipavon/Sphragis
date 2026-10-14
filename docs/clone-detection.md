# Clone detection

*English · [Italiano](clone-detection.it.md)*

A valid SDMMAC proves **key possession**, not **physical uniqueness**. An
attacker who extracts a tag's keys can mint a perfect clone whose MACs all
verify. The only thing a clone cannot fake is a globally consistent, monotonic
read counter. Sphragis turns that into a *scored* verdict rather than a boolean.

## Signals

`detection.CloneDetector` consumes cryptographically authentic observations
(UID, read counter, timestamp, reader id) and emits weighted signals:

| Signal | Weight | Meaning |
|--------|--------|---------|
| `exact_replay` | 65 | the exact counter value was already seen → a captured URL is being resent |
| `counter_regression` | 70 | a counter below the max ever seen → a second device with its own counter stream (clone) |
| `impossible_velocity` | 60 | two taps at different readers closer than any object could travel → two tags |
| `large_counter_gap` | 15 | an unusually large jump; weak / informational |

## Scoring

Weights aggregate into a 0–100 risk score mapped to a classification:

- **≥ 60** → `CLONE_LIKELY` (or `REPLAY` when the only strong signal is an exact replay)
- **25–59** → `SUSPICIOUS`
- **> 0** → `SUSPICIOUS`
- **0** → `GENUINE`

The result carries the score and the human-readable signals, so it can feed a
review/escalation workflow instead of silently allowing or denying.

## The honest edge cases

- A clone that restarts from a low counter re-emits values a replay would also
  produce — Sphragis reports `REPLAY`, which is the truthful label (the two are
  cryptographically indistinguishable).
- A single clone used in place of a destroyed original can look perfectly
  monotonic. Counter-only detection needs to see **both** tags, or side
  information (location/velocity). See the [threat model](../THREAT_MODEL.md).

Detection is **probabilistic and observational**: it raises confidence over
repeated scans, it is not a single-scan guarantee of physical uniqueness.
