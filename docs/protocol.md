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
slicing (`sdm.decrypt_picc_data`), failing closed on malformed input.

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

## Known-answer validation

The implementation reproduces the official NXP zero-key vector:

```
picc_data = EF963FF7828658A599F3041510671E88
cmac      = 94EED9EE65337086
```

See `tests/test_sdm.py::test_nxp_known_answer_vector`. If the crypto ever
drifts, that test fails immediately.

## Not yet supported

- `SDMENCFileData` (encrypted mirrored file data). URLs carrying it are
  **refused** (fail-closed) rather than partially verified.
- The EV2 secure channel (`AuthenticateEV2First/NonFirst`) — out of scope: this
  is a backend verifier for SUN messages, not a reader/APDU stack.
