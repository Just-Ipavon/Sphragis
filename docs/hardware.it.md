# Tag fisici: provisioning e validazione al banco

*[English](hardware.md) · Italiano*

Come portare una NTAG 424 DNA nuova di fabbrica nel layout SUN che il motore
verifica, e come controllare tap reali. La procedura gira con le **chiavi di
fabbrica a zero** salvo dove indicato; sostituirle con chiavi per UID è
descritto in [Chiavi reali](#chiavi-reali-sostituire-le-chiavi-di-fabbrica) e
in [gestione chiavi](key-management.it.md). Solo `tools/rekey.py` esegue
ChangeKey.

```bash
pip install -e ".[hw]"         # pyserial (Chameleon Ultra), nfcpy (PN532)
```

## Lettori

| Backend | `--reader` | Stato |
|---------|------------|-------|
| Chameleon Ultra (seriale USB) | `chameleon --port /dev/ttyACM0` | validato su firmware v2.1 |
| PN532 via nfcpy | `pn532 --port usb` | non ancora validato su hardware |
| Tag software | `emulator` | sottoinsieme ISO in sola lettura, senza hardware |

Il Chameleon Ultra fa da semplice tubo di frame ISO 14443-A. Sphragis parla
direttamente il suo protocollo seriale (non serve il client del produttore) e
gestisce in Python il framing ISO-DEP e il secure messaging della NTAG 424 DNA.
Le chiavi non arrivano mai al dispositivo. Note dall'hardware:

- Il tool porta il dispositivo in modalità reader se sta emulando.
- La selezione (`HF14A_SCAN_KEEP`) manda già il RATS. Un secondo RATS non
  riceve risposta, quindi il FSC si ricava dall'ATS restituito dalla scansione.
- La FIFO del lettore limita un frame a 62 byte più il CRC_A (altrimenti il
  firmware risponde `STATUS_PAR_ERR`). Il FSC è limitato a 64, qualunque valore
  annunci la carta, e gli APDU più lunghi vengono inviati con il chaining ISO-DEP.
- Su Linux l'utente deve poter accedere alla porta seriale (gruppo `dialout`).

## Configurazione SDM congelata

Con `--base-url https://example.com/t` il tag resta così:

```
File NDEF (85 B): https://example.com/t?picc_data=<32 hex>&cmac=<16 hex>

ChangeFileSettings(02): 40 E0EE C1 F1 21 1F0000 450000 450000
  40      FileOption     SDM attivo, CommMode.Plain
  E0 EE   AccessRights   RW=E Change=0 / Read=E Write=E   (di fabbrica, invariati)
  C1      SDMOptions     mirror UID + mirror SDMReadCtr + ASCII
  F1 21   SDMAccess      CtrRet=1 / MetaRead=2 (PICCData cifrato) FileRead=1
  1F0000  PICCDataOffset
  450000  SDMMACInputOffset   (== SDMMACOffset: CMAC su messaggio vuoto)
  450000  SDMMACOffset
```

Combacia con quello che il motore si aspetta: PICCData cifrato (tag `0xC7`, UID
di 7 byte, SDMReadCtr di 3 byte little-endian) e SDMMAC su input vuoto, come in
NXP AN12196. Gli offset dipendono dall'URL base; `provision.py --dry-run` li stampa.

## Procedura

**1. Probe** (sola lettura). Seleziona l'applicazione NDEF.

```
$ python tools/sdm_probe.py --reader chameleon --port /dev/ttyACM0
C-APDU : 00 A4 04 0C 07 D2 76 00 00 85 01 01 00
R-APDU : 90 00
SW     : 9000 (OK, NDEF application present)
```

**2. Piano** (sola lettura). Legge le file settings e il contenuto NDEF, e
stampa cosa verrebbe scritto.

```
$ python tools/provision.py --reader chameleon --port /dev/ttyACM0 \
      --base-url https://example.com/t --dry-run
current       : settings differ, NDEF differs
would write  : NDEF template via ISOUpdateBinary
would change : file settings (auth with key 0, CommMode.Full)
```

**3. Provisioning** (scrive; richiede `--yes`). Scrive il template, esegue
AuthenticateEV2First con la key 0 e ChangeFileSettings in CommMode.Full, poi
rilegge un tap e lo decodifica.

```
$ python tools/provision.py --reader chameleon --port /dev/ttyACM0 \
      --base-url https://example.com/t --yes
wrote        : NDEF template
changed      : file settings (authenticated with key 0)
check        : UID 04084582161690, SDMReadCtr 1, CMAC match
RESULT       : provisioned and verified
```

Rilanciarlo non fa nulla (`already provisioned: nothing to write`). Ogni
lettura del file NDEF è un tap, quindi anche il dry run fa avanzare SDMReadCtr.

**4. Verifica dei tap** tramite `TagAnalyzer` con chiavi a zero.

```
$ python tools/tap_verify.py --reader chameleon --port /dev/ttyACM0 --taps 3
tap 1: GENUINE      UID 04084582161690  ctr 4  score 0
tap 2: GENUINE      UID 04084582161690  ctr 5  score 0
tap 3: GENUINE      UID 04084582161690  ctr 6  score 0
```

Ripassando al motore gli URL catturati, il comportamento è quello atteso:
rigiocare il tap 1 dopo il tap 3 dà `CLONE_LIKELY` (`counter_regression`), un
CMAC alterato dà `FORGED`. Con `--store` la soglia anti-replay persiste tra
un'esecuzione e l'altra; con `--wait` si possono scambiare i tag tra un tap e
l'altro.

## Dati di file cifrati (SDMENCFileData)

`--enc-data TESTO` (o `--enc-data-hex HEX`, un multiplo di 16 byte) configura
la variante che riflette anche dati di file cifrati. Validato su una NTAG 424
DNA di fabbrica tramite il Chameleon Ultra (risultati sotto).

Cosa cambia rispetto al SUN semplice:

- il modello acquisisce `&enc=` con uno spazio riservato grande il doppio del
  testo in chiaro; il testo in chiaro sta nella prima metà (NT4H2421Gx §9.3.6)
  e non compare mai in un tap, che porta ogni volta un cifrato diverso;
- SDMMACInputOffset si sposta all'inizio di `enc`, quindi il MAC copre il
  cifrato (`<enc>&cmac=`);
- i diritti Write e ReadWrite del file NDEF sono **bloccati su una chiave
  applicativa** (`--write-key`, default 0). Altrimenti chiunque con un
  telefono potrebbe riscrivere il testo in chiaro e il tag lo firmerebbe come
  genuino. Le scritture successive passano da AuthenticateEV2First + WriteData
  (CommMode.Plain, a blocchi di un solo frame);
- il controllo finale decifra un tap con `EncFileVerifier` a chiavi zero e
  confronta il testo in chiaro.

**1. Piano** (sola lettura), su una tag di fabbrica:

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

**2. Provisioning** (scrive; `--yes` al posto di `--dry-run`). Il modello da
122 byte è passato con una sola ISOUpdateBinary, cioè con il chaining ISO-DEP
del Chameleon Ultra (i cui frame sono limitati a 62 byte):

```
wrote        : NDEF template (ISOUpdateBinary)
changed      : file settings (authenticated with key 0)
check        : AUTHENTIC, UID 04801A82161690, SDMReadCtr 1, file data match
RESULT       : provisioned and verified
```

**3. Verifica dei tap** con `tools/tap_verify.py --enc`. Tre tap consecutivi:
cifrato diverso ogni volta, stesso testo in chiaro, contatore che sale;
riproporre poi il primo URL dà `REPLAY`:

```
picc_data=159F61C9…&enc=15A911F3450D9A146B7C64559FBA32E6&cmac=71F7103244547328  AUTHENTIC ctr 2  0123456789ABCDEF
picc_data=6157652C…&enc=2DBF9D0E72475941F917DB5732DB9320&cmac=6D80A272901AC2F0  AUTHENTIC ctr 3  0123456789ABCDEF
picc_data=51AF150B…&enc=93A8CAAAABB76A640D53A33190813914&cmac=DC4FB26DE23603FA  AUTHENTIC ctr 4  0123456789ABCDEF
replay del tap 1: REPLAY (contatore 2 <= ultimo visto 4)
```

**4. Blocco della scrittura.** Una ISOUpdateBinary non autenticata degli
stessi byte già presenti all'offset del testo in chiaro (quindi in nessun caso
poteva cambiare qualcosa):

```
select app   : 00A4040C07D276000085010100  ->  SW 9000
select file  : 00A4000C02E10400  ->  SW 9000
write, no Le : 00D600441030313233343536373839414243444546  ->  SW 6982
write, Le=00 : 00D60044103031323334353637383941424344454600  ->  SW 6700
tap 1: AUTHENTIC    UID 04801A82161690  ctr 5  file data 30313233343536373839414243444546
```

`6982` (security status not satisfied) conferma il blocco. Attenzione alla
seconda riga: con la scrittura bloccata, la forma di AN12196 Tabella 16 con Le
in coda è rifiutata come errore di lunghezza (`6700`) **prima** del controllo
dei permessi, mentre con la scrittura libera la stessa forma è accettata (è
così che è stato scritto il modello). Per provare un blocco va usata la forma
del datasheet senza Le; un `6700` non dimostra nulla sui permessi.

**5. Riscrittura autenticata.** Portare a 32 byte il testo in chiaro della tag
bloccata cambia anche lo spazio riservato, quindi un'unica sessione EV2 porta
sia i WriteData in chiaro (modello da 154 byte, a blocchi di un frame) sia il
ChangeFileSettings cifrato. Il MAC di quest'ultimo copre il contatore
comandi, quindi il fatto che sia accettato conferma anche la gestione del
CmdCtr durante le scritture in chiaro:

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

Rilanciando lo stesso dry run, lo strumento decifra il tap corrente, trova il
testo in chiaro già a posto e non scrive nulla (`already provisioned: nothing
to write`); i tap successivi si verificano con il testo da 32 byte.

Tutti questi tap sono conservati come test di regressione
(`tests/test_sdmenc.py`, `test_physical_tag_*`). Rilanciare il provisioning semplice (senza `--enc-data`) riporta il tag al SUN
semplice; il file NDEF resta bloccato sulla `--write-key` (default 0), perché
anche il layout semplice blocca le scritture. `--leave-writable` ripristina la
scrittura libera di fabbrica su una tag di banco. Finché le chiavi sono a zero,
Change sulla chiave 0 rende ogni blocco reversibile.

Prima di scrivere, il provisioning si autentica con ogni chiave che le
scritture richiederanno e mostra l'UID: una tag di cui non hai le chiavi viene
rifiutata senza scrivere nulla, e senza `--uid` digiti l'UID per confermare.

## Chiavi reali: sostituire le chiavi di fabbrica

Non ancora validato su hardware. `tools/rekey.py` scrive chiavi per UID (vedi
[gestione chiavi](key-management.it.md#scrivere-le-chiavi-sulle-tag));
`--to-factory` annulla, così una tag di banco resta riutilizzabile.

Segreti: un file esadecimale per chiave, leggibile solo da te, e **salvato in
backup prima di cambiare le chiavi di qualunque tag** (perdere `master_admin`
rende la tag non più riconfigurabile):

```bash
mkdir -p ~/.sphragis/keys && chmod 700 ~/.sphragis/keys
for k in master_admin master_file meta_read; do
  python -c "import secrets; print(secrets.token_hex(16))" > ~/.sphragis/keys/$k
done
chmod 600 ~/.sphragis/keys/*
```

Poi, su una tag già nel layout SUN:

```bash
python tools/rekey.py --reader chameleon --port /dev/ttyACM0 \
    --secrets-dir ~/.sphragis/keys --inventory ~/.sphragis/inventory.db \
    --context DEMO --dry-run                                       # piano, sola lettura
python tools/rekey.py ... --yes                                  # cambia le chiavi
python tools/tap_verify.py --reader chameleon --port /dev/ttyACM0 \
    --secrets-dir ~/.sphragis/keys --context DEMO --taps 2         # chiavi lato server
python tools/rekey.py ... --to-factory --yes                     # di nuovo chiavi zero
```

Il dry run legge già la firma di originalità (Read_Sig, sola lettura) e stampa
`originality  : NXP signature verifies for this UID`; quella riga su una tag
autentica è la verifica su hardware del codice della firma. `--yes` senza
`--uid` chiede di digitare l'UID mostrato. Tieni il file d'inventario accanto
ai segreti e fanne il backup insieme a loro.

Dopo il cambio, `tools/provision.py` vuole gli stessi `--secrets-dir` e
`--context`: modificare le impostazioni SDM o scrivere un file NDEF bloccato
richiede allora l'autenticazione con il vero slot 0 della tag.

## Clone detection su hardware

Un clone è un secondo dispositivo fisico che risponde per lo stesso tag. Qui il
tag autentico è la NTAG 424 DNA programmata; il clone è un Chameleon Ultra che
emula una NTAG215 il cui NDEF contiene un URL SUN calcolato da Sphragis per
l'UID autentico con le chiavi a zero (compromesse). Entrambi i tap hanno un CMAC
valido — il clone non è un falso, ha le stesse chiavi — quindi a distinguerli è
solo il contatore di letture: ogni dispositivo ha il suo flusso di contatore.

Genera l'URL clone per un contatore scelto e caricalo in uno slot libero:

```bash
sphragis emulate --meta-key 0*32 --file-key 0*32 --uid 04084582161690 --counter 1 --taps 1
# -> https://example.com/t?picc_data=...&cmac=...   (URI NDEF in un'immagine NTAG215)
```

```
hw slot change -s 5
hw slot enable -s 5 --hf
hw slot type   -s 5 --type NTAG_215
hf mfu eload   -f clone_ntag215.bin        # immagine NTAG215 con l'URL
hf mfu econfig -s 5 --uid 04084582161690   # stesso UID dell'autentico sul filo
hw slot store                              # salva in flash (regge lo scollegamento)
hw mode -e                                 # modalità emulatore, così il telefono legge
```

Leggi entrambi i tag col telefono (NXP TagInfo mostra l'URL), poi passa i due
tap all'engine nell'ordine reale, con lo stesso storico:

```
carta vera (telefono)       GENUINE       UID 04084582161690  ctr 8  score 0
clone Chameleon (telefono)  CLONE_LIKELY  UID 04084582161690  ctr 2  score 70
  signal counter_regression (+70): read counter 2 is below the maximum seen (8):
  a second device is emitting its own counter stream (clone)
```

Il tag autentico fa avanzare il contatore a ogni tap; il clone statico ne
ripropone uno più basso, quindi l'engine segnala `counter_regression` su dati
fisici letti dal telefono, non su una cattura rigiocata. L'UID di
anticollisione sul filo è solo estetico: l'engine legge l'UID dentro il
PICCData cifrato, quindi un clone con l'UID di default dell'emulatore viene
comunque rilevato; `econfig --uid` serve solo a rendere il clone fedele sul filo.

## Risoluzione dei problemi

| Sintomo | Significato |
|---------|-------------|
| `no tag in the field` | Nessuna risposta alla selezione; centra la carta sull'antenna HF |
| `14443-A exchange failed (status 0x1)` | La carta ha smesso di rispondere a metà sessione (spostata, campo perso) |
| `status 0x60` | Frame rifiutato dal dispositivo perché troppo lungo (non dovrebbe succedere con il limite al FSC) |
| `no reply (timeout)` | Link seriale muto: porta sbagliata, o un altro programma la tiene aperta |
| `check ... CMAC MISMATCH` | Offset o chiavi non combaciano con il tag; rilancia `--dry-run` e confronta |

Gli errori fail-closed del motore (`inspect`, `tap_verify`) indicano il campo
che non torna, ed è il modo più rapido per correggere la configurazione di un tag.
