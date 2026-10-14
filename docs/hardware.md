# Physical tags: provisioning and bench validation

*English · [Italiano](hardware.it.md)*

How to put a factory-fresh NTAG 424 DNA into the SUN layout the engine
verifies, and how to check real taps against it. Everything here runs with the
**factory all-zero keys**: it is a bench procedure for validating the engine,
not a production provisioning flow (see [key-management.md](key-management.md)).
No command in `tools/` ever issues ChangeKey.

```bash
pip install -e ".[hw]"         # pyserial (Chameleon Ultra), nfcpy (PN532)
```

## Readers

| Backend | `--reader` | Status |
|---------|------------|--------|
| Chameleon Ultra (USB serial) | `chameleon --port /dev/ttyACM0` | validated on firmware v2.1 |
| PN532 via nfcpy | `pn532 --port usb` | not yet validated on hardware |
| Software tag | `emulator` | read-only ISO subset, no hardware |

The Chameleon Ultra is used as a raw ISO 14443-A frame pipe. Sphragis speaks
its serial protocol directly (no vendor client needed) and does ISO-DEP
framing and NTAG 424 DNA secure messaging in Python. Keys never reach the
device. Notes from the hardware:

- The tool switches the device to reader mode if it is emulating.
- Selection (`HF14A_SCAN_KEEP`) already sends RATS. A second RATS gets no
  answer, so the FSC is taken from the ATS the scan returns.
- The reader FIFO limits a frame to 62 bytes plus CRC_A (the firmware answers
  `STATUS_PAR_ERR` otherwise). The FSC is capped at 64, whatever the card
  announces, and longer APDUs go out with ISO-DEP chaining.
- On Linux the user needs access to the serial port (group `dialout`).

## Frozen SDM configuration

For `--base-url https://example.com/t` the tag is left with:

```
NDEF file (85 B): https://example.com/t?picc_data=<32 hex>&cmac=<16 hex>

ChangeFileSettings(02): 40 E0EE C1 F1 21 1F0000 450000 450000
  40      FileOption     SDM enabled, CommMode.Plain
  E0 EE   AccessRights   RW=E Change=0 / Read=E Write=E   (factory, unchanged)
  C1      SDMOptions     UID mirror + SDMReadCtr mirror + ASCII
  F1 21   SDMAccess      CtrRet=1 / MetaRead=2 (encrypted PICCData) FileRead=1
  1F0000  PICCDataOffset
  450000  SDMMACInputOffset   (== SDMMACOffset: CMAC over an empty message)
  450000  SDMMACOffset
```

This matches the engine's expectations: encrypted PICCData (tag `0xC7`, 7-byte
UID, 3-byte little-endian SDMReadCtr) and an SDMMAC over an empty input, as in
NXP AN12196. Offsets follow the base URL; `provision.py --dry-run` prints them.

## Procedure

**1. Probe** (read-only). Selects the NDEF application.

```
$ python tools/sdm_probe.py --reader chameleon --port /dev/ttyACM0
C-APDU : 00 A4 04 0C 07 D2 76 00 00 85 01 01 00
R-APDU : 90 00
SW     : 9000 (OK, NDEF application present)
```

**2. Plan** (read-only). Reads file settings and NDEF content, prints what
would be written.

```
$ python tools/provision.py --reader chameleon --port /dev/ttyACM0 \
      --base-url https://example.com/t --dry-run
current       : settings differ, NDEF differs
would write  : NDEF template via ISOUpdateBinary
would change : file settings (auth with key 0, CommMode.Full)
```

**3. Provision** (writes; requires `--yes`). Writes the template, runs
AuthenticateEV2First with key 0 and ChangeFileSettings in CommMode.Full, then
reads one tap back and decodes it.

```
$ python tools/provision.py --reader chameleon --port /dev/ttyACM0 \
      --base-url https://example.com/t --yes
wrote        : NDEF template
changed      : file settings (authenticated with key 0)
check        : UID 04084582161690, SDMReadCtr 1, CMAC match
RESULT       : provisioned and verified
```

Running it again is a no-op (`already provisioned: nothing to write`). Every
read of the NDEF file is a tap, so the dry run itself advances SDMReadCtr.

**4. Verify taps** through `TagAnalyzer` with all-zero keys.

```
$ python tools/tap_verify.py --reader chameleon --port /dev/ttyACM0 --taps 3
tap 1: GENUINE      UID 04084582161690  ctr 4  score 0
tap 2: GENUINE      UID 04084582161690  ctr 5  score 0
tap 3: GENUINE      UID 04084582161690  ctr 6  score 0
```

Feeding the captured URLs back to the engine behaves as expected: replaying
tap 1 after tap 3 gives `CLONE_LIKELY` (`counter_regression`), a tampered
CMAC gives `FORGED`. Use `--store` to keep the anti-replay floor across runs
and `--wait` to swap tags between taps.

## Physical clone detection

A clone is a second physical device that answers for the same tag. Here the
genuine tag is the provisioned NTAG 424 DNA; the clone is a Chameleon Ultra
emulating an NTAG215 whose NDEF holds a SUN URL computed by Sphragis for the
genuine UID with the (compromised) all-zero keys. Both taps carry a valid
CMAC — the clone is not a forgery, it holds the same keys — so only the read
counter tells them apart: each device runs its own counter stream.

Build the clone URL for a chosen counter and load it into a spare slot:

```bash
sphragis emulate --meta-key 0*32 --file-key 0*32 --uid 04084582161690 --counter 1 --taps 1
# -> https://example.com/t?picc_data=...&cmac=...   (NDEF URI in an NTAG215 image)
```

```
hw slot change -s 5
hw slot enable -s 5 --hf
hw slot type   -s 5 --type NTAG_215
hf mfu eload   -f clone_ntag215.bin        # NTAG215 image carrying the URL
hf mfu econfig -s 5 --uid 04084582161690   # match the genuine UID on the wire
hw slot store                              # persist to flash (survives unplug)
hw mode -e                                 # emulator mode, so a phone can read it
```

Read both tags with a phone (NXP TagInfo shows the URL), then feed the two taps
to the engine in the real order, sharing one history:

```
carta vera (phone)        GENUINE       UID 04084582161690  ctr 8  score 0
clone Chameleon (phone)   CLONE_LIKELY  UID 04084582161690  ctr 2  score 70
  signal counter_regression (+70): read counter 2 is below the maximum seen (8):
  a second device is emitting its own counter stream (clone)
```

The genuine tag advances its counter on every tap; the static clone replays a
lower one, so the engine flags `counter_regression` on real, phone-read data —
not a replayed capture. The anti-collision UID shown over the air is cosmetic:
the engine reads the UID from inside the encrypted PICCData, so a clone with the
default emulator UID is still caught; `econfig --uid` only makes the clone
faithful on the wire.

## Troubleshooting

| Symptom | Meaning |
|---------|---------|
| `no tag in the field` | Nothing answered selection; centre the card on the HF antenna |
| `14443-A exchange failed (status 0x1)` | The card stopped answering mid-session (moved, field lost) |
| `status 0x60` | Frame rejected by the device as too long (should not happen with the FSC cap) |
| `no reply (timeout)` | Serial link silent: wrong port, or another program holds it |
| `check ... CMAC MISMATCH` | Offsets or keys do not match the tag; rerun `--dry-run` and compare |

The engine's fail-closed errors (`inspect`, `tap_verify`) name the field that
does not line up, which is the quickest way to debug a tag configuration.
