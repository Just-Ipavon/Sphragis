# Tag fisici: provisioning e validazione al banco

*[English](hardware.md) · Italiano*

Come portare una NTAG 424 DNA nuova di fabbrica nel layout SUN che il motore
verifica, e come controllare tap reali. Tutto gira con le **chiavi di fabbrica
a zero**: è una procedura di banco per validare il motore, non un flusso di
provisioning per la produzione (vedi [key-management.it.md](key-management.it.md)).
Nessun comando in `tools/` esegue mai ChangeKey.

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
