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
DivKey = AES-CMAC(MasterKey, 0x01 || DivInput)
```

`DiversifiedKeys` wires this into the verifier: the meta-read key stays fixed
(needed to decrypt PICCData before the UID is known), while the file-read key —
which actually authenticates the tap — is unique per UID. A `context` label
mixes in an application/system identifier so the same master key yields
different keys across unrelated deployments.

```python
from sphragis import DiversifiedKeys
keys = DiversifiedKeys(master_file_key=..., meta_read_key=..., context=b"ART")
file_key = keys.file_read_key(uid)   # unique per tag
```

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
