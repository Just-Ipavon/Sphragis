# Key management

*English · [Italiano](key-management.it.md)*

A single fixed key on every tag is a single point of total failure: extract it
from one chip and you can forge them all. Sphragis supports the production
pattern — **per-UID diversified keys** — and keeps key material **out of the
code**.

## Diversification (AN10922)

`diversify.diversify_key` derives a per-tag AES-128 key from a master key and
tag-unique data, per NXP AN10922:

```
D      = 0x01 || DivInput || padding   (always 32 bytes: 80h 00h ...)
DivKey = AES-CMAC(MasterKey, D)        (last block XOR K2 if padded, else K1)
```

The two-block padding matters: for a `DivInput` of 15 bytes or less (a bare
7-byte UID, say) a standard CMAC over `0x01 || DivInput` gives a different
key, which no other AN10922 implementation would reproduce. The code follows
the application note and is pinned to its §2.2.1 example
(`tests/test_diversify.py`).

`DiversifiedKeys` wires this into the verifier: the meta-read key stays fixed
(needed to decrypt PICCData before the UID is known), while the file-read key —
which actually authenticates the tap — is unique per UID. A `context` label
mixes in an application/system identifier so the same master key yields
different keys across unrelated deployments.

```python
from sphragis import DiversifiedKeys
keys = DiversifiedKeys(master_file_key=..., meta_read_key=..., context=b"DEMO")
file_key = keys.file_read_key(uid)   # unique per tag
```

## Writing keys to tags

`keyprov.py` replaces the five application keys of a tag with per-UID keys
(`tools/rekey.py` on a hardware host). Key layout:

| Slot | Role | Key |
|------|------|-----|
| 0 | AppMasterKey (reconfigures the tag) | AN10922 from `master_admin`, M = UID ‖ 00h ‖ context |
| 1 | SDMFileRead (MAC, encrypted file data) | `DiversifiedKeys.file_read_key(uid)`, from `master_file` |
| 2 | SDMMetaRead (PICCData) | `meta_read`, shared: the UID is only known after decrypting PICCData |
| 3, 4 | unused by the SUN layout | AN10922 from `master_admin`, M = UID ‖ slot ‖ context |

`master_admin` is a **separate secret**: verification servers need only
`master_file` and `meta_read`, so the key that can reconfigure tags stays on
the provisioning station.

The flow (`rekey_tag`):

1. Authenticate with slot 0 under a known scheme (factory, or the target),
   read the UID with GetCardUID and the version of every slot with
   GetKeyVersion. Factory keys carry version 00h, Sphragis keys 01h (or the
   `--key-version` you choose), so each slot's current key is known; a
   version that matches no known scheme stops the run before any write.
2. ChangeKey slots 1-4, then slot 0 last (changing the session key ends the
   session). AN12196 §5.16 covers both cases; both are pinned to its vectors.
3. Authenticate with every new key and read every version back.

An interrupted run resumes from the versions; `--to-factory` puts the
all-zero keys back. Keys never appear in logs, only key check values (KCV).
The UID comes from GetCardUID, or from a SUN tap that must verify completely
under the candidate keys (decrypting PICCData alone authenticates nothing).

**Do not lose `master_admin`.** Without it a tag can no longer be
reconfigured or reset; taps still verify as long as `master_file` and
`meta_read` exist. Back up the secrets before keying any tag.

## Secrets backends

`secrets.py` abstracts *where* key material comes from behind a tiny
`SecretsBackend` interface, so the verifier never changes when you move from a
dev env var to a managed KMS:

- **`EnvSecretsBackend`** — hex keys from environment variables (`SPHRAGIS_*`).
- **`FileSecretsBackend`** — hex keys from files; **refuses** group/world
  readable files (POSIX).
- **`KmsSecretsBackend`** — extension point: subclass and implement `get_key`
  for AWS KMS, GCP KMS, HashiCorp Vault, or a PKCS#11 HSM.

```python
from sphragis import EnvSecretsBackend, build_diversified_keys
keys = build_diversified_keys(EnvSecretsBackend())   # no raw keys in code
```

## Honest limitation

A software backend fetches the key into process memory, where Python `bytes`
cannot be reliably zeroized. A true HSM keeps the key resident and performs the
crypto inside the module; `KmsSecretsBackend` is where that integration belongs.
For NTAG 424 DNA the master key should live in an HSM/KMS and only diversified
material should transit.
