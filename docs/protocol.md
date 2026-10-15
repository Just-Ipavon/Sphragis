# Protocol: SDM / SUN on NTAG 424 DNA

*English · [Italiano](protocol.it.md)*

Sphragis implements the **public** NXP Secure Dynamic Messaging (SDM) scheme,
also called SUN (Secure Unique NFC). It is documented in NXP application note
**AN12196** and is shared by every NTAG 424 DNA deployment — it is not
proprietary.

## The tapped URL

On each tap the tag mirrors dynamic data into a URL:

```
https://example.com/t?picc_data=<hex>&cmac=<hex>
```

- **`picc_data`** — one AES-128 block (16 bytes), AES-CBC encrypted under
  `K_SDMMetaReadKey` with a zero IV. It carries a tag byte, the UID and the
  read counter (`SDMReadCtr`).
- **`cmac`** — the 8-byte truncated SDMMAC authenticating the read.

## Decrypting PICCData

AES-CBC decrypt with `K_SDMMetaReadKey` (IV = 16 zero bytes) yields:

```
byte 0        PICCDataTag   (bit7 = UID mirror, bit6 = counter present, low nibble = UID length)
bytes 1..n    UID           (typically 7 bytes)
next 3 bytes  SDMReadCtr    (little-endian, 24-bit)
remainder     random padding
```

Sphragis validates the declared field lengths against the block size before
slicing (`sdm.decrypt_picc_data`), failing closed on malformed input. The
verifiers then accept only the layout this engine provisions, tag byte `0xC7`
(UID and counter mirrored, 7-byte UID, RFU bits clear): any other value is
`ERROR`, so a random block cannot reach key derivation with an odd UID length
and a missing counter cannot read as 0.

Until the SDMMAC has verified, UID and counter are unauthenticated: a `FORGED`
result carries neither, otherwise anyone could decrypt chosen blocks under the
shared MetaRead key by submitting them with a wrong MAC.

## Verifying the SDMMAC

The MAC uses a per-read session key derived from `K_SDMFileReadKey`
(AN12196 §4.3.3):

```
SV2  = 3Ch C3h 00h 01h 00h 80h || UID || SDMReadCtr
Kses = AES-CMAC(K_SDMFileReadKey, SV2)
SDMMAC = truncate( AES-CMAC(Kses, <mirrored file data, empty for plain SUN>) )
```

`truncate` keeps the 8 bytes at odd indices (1, 3, 5, …, 15). The computed
value is compared against the URL's `cmac` in **constant time**
(`hmac.compare_digest`).

## Encrypted file data (SDMENCFileData)

A tag can also encrypt a slice of the NDEF file's static data on every read
and mirror it as ASCII hex, typically as an `enc` parameter. The plain
`Verifier` keeps refusing such URLs (fail-closed); they are handled by the
opt-in `EncFileVerifier` (`sphragis/encverifier.py`, primitives in
`sphragis/sdmenc.py`). The SUN path in `sdm.py` is reused unchanged.

```
SV1      = C3h 3Ch 00h 01h 00h 80h || UID || SDMReadCtr
KsesENC  = AES-CMAC(K_SDMFileReadKey, SV1)
IVe      = AES-ECB(KsesENC, SDMReadCtr || 00h * 13)
FileData = AES-CBC-Decrypt(KsesENC, IVe, SDMENCFileData)
```

With an encrypted mirror the SDMMAC is **not** over an empty message: it
covers the mirrored ASCII bytes from `SDMMACInputOffset` to `SDMMACOffset - 1`,
which must include the whole `SDMENCFileData`. The supported layout is the one
in AN12196 §3.4.4.2.2:

```
...?picc_data=<32 hex>&enc=<n*32 hex>&cmac=<16 hex>
MAC input = "<enc hex>&cmac="   (anything between enc and cmac is covered too)
```

Verification order: parse (strict hex, no duplicated, re-cased or
percent-encoded parameter names, `cmac` after `enc`) → decrypt PICCData →
check the SDMMAC over the **raw** input in constant time → atomic counter
check → only then decrypt the file data. The decrypted bytes are returned only
on `AUTHENTIC`. Because the MAC is over raw bytes, the URL must reach the
verifier exactly as the tag emitted it: re-encoding it or changing the hex
case makes a genuine tap `FORGED`.

```python
from sphragis import EncFileVerifier, StaticKeys
result = EncFileVerifier(StaticKeys(meta_key, file_key)).verify(url)
result.verdict, result.file_data
```

From the command line: `sphragis verify --enc --meta-key … --file-key … URL`.
`provision_tag(..., file_data=...)` / `tools/provision.py --enc-data` configure
the mirror on a tag and lock the NDEF file's writes to a key; see
[hardware.md](hardware.md) (validated on a physical tag).

## Known-answer validation

The implementation reproduces the official NXP zero-key vector:

```
picc_data = EF963FF7828658A599F3041510671E88
cmac      = 94EED9EE65337086
```

See `tests/test_sdm.py::test_nxp_known_answer_vector`. If the crypto ever
drifts, that test fails immediately.

The encrypted mirror is pinned to the two AN12196 Rev. 2.0 zero-key vectors,
including the intermediate session keys and IV
(`tests/test_sdmenc.py`):

```
Table 3: picc_data = FDE4AFA99B5C820A2C1BB0F1C792D0EB
         enc       = 94592FDE69FA06E8E3B6CA686A22842B
         cmac      = C48B89C17A233B2C   -> file data "xxxxxxxxxxxxxxxx"
Table 5: picc_data = FD91EC264309878BE6345CBE53BADF40
         enc       = CEE9A53E3E463EF1F459635736738962
         cmac      = ECC1E7F6C6C73BF6   -> file data "xxxxxxxxxxxxxxxx"
```

## Not yet supported

- `SDMENCFileData` layouts where `SDMMACInputOffset` is not the start of the
  `enc` value.
- Parts of the EV2 secure channel beyond what provisioning needs: `ev2.py`
  implements AuthenticateEV2First and the CommMode.Full/MAC commands used by
  provisioning and key changes, validated against the AN12196 vectors and on
  a physical tag; AuthenticateEV2NonFirst and LRP mode are not implemented.
