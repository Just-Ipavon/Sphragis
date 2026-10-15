# Physical tags: provisioning and bench validation

*English · [Italiano](hardware.it.md)*

How to put a factory-fresh NTAG 424 DNA into the SUN layout the engine
verifies, and how to check real taps against it. The procedure runs with the
**factory all-zero keys** unless stated otherwise; replacing them with per-UID
keys is covered in [Real keys](#real-keys-replacing-the-factory-keys) and
[key management](key-management.md). Only `tools/rekey.py` issues ChangeKey.

```bash
pip install -e ".[hw]"         # pyserial (Chameleon Ultra)
```

## Readers

| Backend | `--reader` | Status |
|---------|------------|--------|
| Chameleon Ultra (USB serial) | `chameleon --port /dev/ttyACM0` | validated on firmware v2.1 |
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

## Encrypted file data (SDMENCFileData)

`--enc-data TEXT` (or `--enc-data-hex HEX`, a multiple of 16 bytes) provisions
the variant that also mirrors encrypted file data. Validated on a factory
NTAG 424 DNA through the Chameleon Ultra (results below).

What changes compared with plain SUN:

- the template gains `&enc=` with a placeholder twice the plaintext size; the
  plaintext sits in its first half (NT4H2421Gx §9.3.6) and never appears in a
  tap, which carries fresh ciphertext every time;
- SDMMACInputOffset moves to the start of `enc`, so the MAC covers the
  ciphertext (`<enc>&cmac=`);
- the NDEF file's Write and ReadWrite rights are **locked to an application
  key** (`--write-key`, default 0). Otherwise anyone with a phone could rewrite
  the plaintext and the tag would MAC it as genuine. Later writes go through
  AuthenticateEV2First + WriteData (CommMode.Plain, in single-frame chunks);
- the check at the end decrypts one tap with `EncFileVerifier` under the zero
  keys and compares the plaintext.

**1. Plan** (read-only), on a factory tag:

```
$ python tools/provision.py --reader chameleon --port /dev/ttyACM0 \
      --base-url https://example.com/t --enc-data 0123456789ABCDEF --dry-run
NDEF file     : 122 B, PICCDataOffset=0x1F, SDMMACInputOffset=SDMENCOffset=0x44, SDMENCLength=0x20, SDMMACOffset=0x6A
file data     : 16 B plaintext, NDEF writes locked to key 0
file settings : 4000E0D1F1211F00004400004400002000006A0000 (SDM on, encrypted PICCData key 2, MAC key 1)
current       : settings differ, NDEF differs
would write  : NDEF template via ISOUpdateBinary
would change : file settings (auth with key 0, CommMode.Full)
```

**2. Provision** (writes; `--yes` instead of `--dry-run`). In this run the
122-byte template went out as a single ISOUpdateBinary, i.e. with ISO-DEP
chaining on the Chameleon Ultra (whose frames are limited to 62 bytes), which
validated chaining on hardware. Since v1.0 the template is written in 48-byte
ISOUpdateBinary pieces that each fit one frame, so every piece is written
atomically; this split still has to be seen on silicon at the next template
write:

```
wrote        : NDEF template (ISOUpdateBinary)
changed      : file settings (authenticated with key 0)
check        : AUTHENTIC, UID 04801A82161690, SDMReadCtr 1, file data match
RESULT       : provisioned and verified
```

**3. Verify taps** with `tools/tap_verify.py --enc`. Three consecutive taps:
fresh ciphertext each time, the same plaintext, a rising counter; replaying
the first URL afterwards gives `REPLAY`:

```
picc_data=159F61C9…&enc=15A911F3450D9A146B7C64559FBA32E6&cmac=71F7103244547328  AUTHENTIC ctr 2  0123456789ABCDEF
picc_data=6157652C…&enc=2DBF9D0E72475941F917DB5732DB9320&cmac=6D80A272901AC2F0  AUTHENTIC ctr 3  0123456789ABCDEF
picc_data=51AF150B…&enc=93A8CAAAABB76A640D53A33190813914&cmac=DC4FB26DE23603FA  AUTHENTIC ctr 4  0123456789ABCDEF
replay of tap 1: REPLAY (counter 2 <= last seen 4)
```

**4. Write lock.** An unauthenticated ISOUpdateBinary of the bytes already
stored at the plaintext offset (so it could not change anything either way):

```
select app   : 00A4040C07D276000085010100  ->  SW 9000
select file  : 00A4000C02E10400  ->  SW 9000
write, no Le : 00D600441030313233343536373839414243444546  ->  SW 6982
write, Le=00 : 00D60044103031323334353637383941424344454600  ->  SW 6700
tap 1: AUTHENTIC    UID 04801A82161690  ctr 5  file data 30313233343536373839414243444546
```

`6982` (security status not satisfied) confirms the lock. Note the second
line: with writes locked, the AN12196 Table 16 form with a trailing Le is
rejected as a length error (`6700`) **before** the access check, while with
free write access the same form is accepted (it is how the template was
written). To test a lock, use the datasheet form without Le; a `6700` proves
nothing about access rights.

**5. Authenticated rewrite.** Changing the plaintext of the locked tag to 32
bytes changes the placeholder too, so one EV2 session carries both plain
WriteData commands (154-byte template, single-frame chunks) and the encrypted
ChangeFileSettings. The latter's MAC covers the command counter, so its
acceptance also confirms the CmdCtr bookkeeping across the plain writes:

```
$ python tools/provision.py … --enc-data 0123456789ABCDEFFEDCBA9876543210 --dry-run
NDEF file     : 154 B, PICCDataOffset=0x1F, SDMMACInputOffset=SDMENCOffset=0x44, SDMENCLength=0x40, SDMMACOffset=0x8A
current       : settings differ, NDEF differs
would write  : NDEF template via WriteData (auth with key 0)
would change : file settings (auth with key 0, CommMode.Full)

$ python tools/provision.py … --enc-data 0123456789ABCDEFFEDCBA9876543210 --yes
wrote        : NDEF template (WriteData, authenticated with key 0)
changed      : file settings (authenticated with key 0)
check        : AUTHENTIC, UID 04801A82161690, SDMReadCtr 8, file data match
RESULT       : provisioned and verified
```

Running the same dry run again decrypts the current tap, finds the plaintext
already in place and writes nothing (`already provisioned: nothing to
write`); further taps verify with the 32-byte plaintext.

All these taps are kept as regression tests (`tests/test_sdmenc.py`,
`test_physical_tag_*`). Running plain provisioning again (without `--enc-data`) returns the tag to
plain SUN; its NDEF file stays locked to `--write-key` (default 0), since the
plain layout locks writes too. `--leave-writable` restores the factory free
write access on a bench tag. While the keys are still all-zero, Change on
key 0 keeps every lock reversible.

Before writing, provisioning authenticates with every key the writes will need
and shows the UID: a tag whose keys you do not hold is refused with nothing
written, and without `--uid` you type the UID to confirm.

Validated on UID 04084582161690 (plain SUN, previously free-writable): the dry
run planned only the access change (`NDEF matches`, `auth check : keys 0
accepted`); `--yes` changed the file settings after the typed confirmation and
the check tap verified (`SDMReadCtr 14, CMAC match`). An unauthenticated
ISOUpdateBinary without Le of the bytes already stored (`example.com` at 0x07)
then returned `6982`, and the next tap was still `AUTHENTIC` (counter 16).

## Real keys: replacing the factory keys

Validated on hardware (UID 04341A82161690, below); `--to-factory` still has to
be seen on silicon. `tools/rekey.py` writes per-UID keys (see
[key management](key-management.md#writing-keys-to-tags)); `--to-factory`
undoes it, so a bench tag stays reusable.

Secrets: one hex file per key, readable by you only, and **backed up before
keying any tag** (losing `master_admin` makes the tag impossible to
reconfigure):

```bash
mkdir -p ~/.sphragis/keys && chmod 700 ~/.sphragis/keys
for k in master_admin master_file meta_read; do
  python -c "import secrets; print(secrets.token_hex(16))" > ~/.sphragis/keys/$k
done
chmod 600 ~/.sphragis/keys/*
```

Then, on a tag already in the SUN layout:

```bash
python tools/rekey.py --reader chameleon --port /dev/ttyACM0 \
    --secrets-dir ~/.sphragis/keys --inventory ~/.sphragis/inventory.db \
    --context DEMO --dry-run                                       # read-only plan
python tools/rekey.py ... --yes                                  # change the keys
python tools/tap_verify.py --reader chameleon --port /dev/ttyACM0 \
    --secrets-dir ~/.sphragis/keys --context DEMO --taps 2         # server-side keys
python tools/rekey.py ... --to-factory --yes                     # back to zero keys
```

The dry run already reads the originality signature (Read_Sig, read-only) and
prints `originality  : NXP signature verifies for this UID`; that line on a
genuine tag is the hardware check of the signature code. `--yes` without
`--uid` asks you to type the UID shown. Keep the inventory file next to the
secrets and back it up with them.

Once keyed, `tools/provision.py` needs the same `--secrets-dir` and
`--context`: changing the SDM settings or writing a locked NDEF file then
authenticates with the tag's real slot 0.

**Hardware run** (UID 04341A82161690, plain SUN layout just provisioned): the
dry run planned slots 1-4 then 0, `--yes` changed them in that order, every
new key authenticated and taps verified with the server-side keys. The
counter skips a few values because the dry run and the rekey each read a SUN
tap to learn the UID.
With factory keys the same tag no longer verifies: its PICCData decrypts to
garbage, not the standard layout, hence `ERROR` rather than `FORGED`.

```
UID (from tap): 04341A82161690
UID          : 04341A82161690 (GetCardUID)
originality  : NXP signature verifies for this UID
current      : 0=factory, 1=factory, 2=factory, 3=factory, 4=factory
target       : diversified, version 01, KCV 76E11F 2C0AA4 0D8655 0E2A6A C27F88
inventory    : unknown UID
About to change slots 1, 2, 3, 4, 0 of tag 04341A82161690.
Type the UID to confirm: 04341A82161690
changed      : slot 1 (factory -> diversified)
changed      : slot 2 (factory -> diversified)
changed      : slot 3 (factory -> diversified)
changed      : slot 4 (factory -> diversified)
changed      : slot 0 (factory -> diversified)
check        : all five keys authenticate, versions 01
RESULT       : keys changed and verified

tap 1: GENUINE      UID 04341A82161690  ctr 7  score 0
tap 2: GENUINE      UID 04341A82161690  ctr 8  score 0
tap 3: GENUINE      UID 04341A82161690  ctr 9  score 0
tap 1: ERROR        UID None  ctr None  score 0      (factory keys)
```

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
