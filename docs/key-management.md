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

1. Read the NXP originality signature (Read_Sig) before authenticating.
   Authenticate with slot 0 under a known scheme (factory, or the target),
   read the UID with GetCardUID and the version of every slot with
   GetKeyVersion. Factory keys carry version 00h, Sphragis keys 01h (or the
   `--key-version` you choose), so each slot's current key is known; a
   version that matches no known scheme stops the run before any write.
   The identity checks below run here, then the operator confirms the UID.
2. ChangeKey slots 1-4, then slot 0 last (changing the session key ends the
   session). AN12196 §5.16 covers both cases; both are pinned to its vectors.
3. Authenticate with every new key and read every version back.

An interrupted run resumes from the versions; `--to-factory` puts the
all-zero keys back. Keys never appear in logs, only key check values (KCV).
The UID comes from GetCardUID, or from a SUN tap that must verify completely
under the candidate keys (decrypting PICCData alone authenticates nothing).

### Keying safely

The first keying of any NTAG 424 DNA happens under the public all-zero key.
Anything that answers like a factory tag (a Chameleon, a counterfeit chip)
would receive the keys for the UID it claims, so `rekey_tag` checks, before
any key leaves the station:

- **Originality signature.** The ECDSA signature (secp224r1) NXP puts on every
  chip's UID must verify under NXP's public key, and the anticollision UID
  must equal the GetCardUID one where the reader exposes it. A made-up UID
  fails. The signature is static, so an emulator copying a genuine tag can
  replay it: this raises the cost, it does not prove the chip.
- **Inventory of keyed UIDs** (`SqliteKeyInventory`, `--inventory`). The UID is
  recorded as `keying` before the first key is sent and `keyed` once
  verified (`factory` after a verified reset). A UID the inventory holds that
  answers with factory keys is refused: a genuine keyed tag cannot be in that
  state, so it is a copy, or a tag reset outside the tool (`--allow-known-uid`
  for one you have in hand).
- **Proof of possession.** A tag whose slots claim non-factory keys must
  authenticate with them, and only a UID-specific slot (0, 1, 3, 4) counts:
  slot 2 holds the shared `meta_read`, which proves nothing about the UID.
  This is what lets an interrupted run resume safely (slot 1 is changed first).
- **Confirmation.** The UID and the plan are shown; without `--uid` the
  operator types the UID before anything is written.

What remains, by construction: a passive radio capture of a factory keying
session yields the keys sent in it, since the session keys follow from the
zero key and the exchanged randoms. Key tags in a shielded place, close to the
reader, from a supply you control. And `meta_read` is shared by every tag:
its leak breaks UID privacy for all of them (not authenticity, which rests on
the per-UID FileRead key).

**Do not lose `master_admin`.** Without it a tag can no longer be
reconfigured or reset; taps still verify as long as `master_file` and
`meta_read` exist. Back up the secrets before keying any tag.

## Secrets backends

`secrets.py` abstracts *where* key material comes from behind a tiny
`SecretsBackend` interface, so the verifier never changes when you move from a
dev env var to a managed KMS:

- **`EnvSecretsBackend`** — hex keys from environment variables (`SPHRAGIS_*`).
- **`FileSecretsBackend`** — hex keys from files. On POSIX it **refuses** key
  files that are symlinks, not regular files, owned by another user or
  group/world accessible, and a directory that is group/world writable or
  owned by another user; the checks run on the opened descriptor
  (`O_NOFOLLOW` + `fstat`), so the file checked is the file read. Elsewhere it
  warns: protect the directory with the OS ACLs.
- **`KmsSecretsBackend`** — extension point: subclass and implement `get_key`
  for AWS KMS, GCP KMS, HashiCorp Vault, or a PKCS#11 HSM.

Every backend refuses an all-zero key (the public factory key is not a
secret), and the key schemes refuse equal masters: `master_admin`,
`master_file` and `meta_read` must be three different keys, otherwise
verification servers would hold the key that reconfigures tags. The
derivation inputs need no extra framing: the UID is always 7 bytes (other
PICCData layouts are refused), so `context ‖ UID` is unambiguous.

On the command line, `sphragis verify` and `emulate` take keys from
`--secrets-dir` (diversified, like the API), from `SPHRAGIS_CLI_META_KEY` /
`SPHRAGIS_CLI_FILE_KEY`, or by prompting without echo; `--meta-key` /
`--file-key` remain for test keys and print a warning, since arguments are
visible to other users (`ps`, shell history). `tools/provision.py
--enc-data-file` keeps the encrypted plaintext off the command line too.

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
