# Protocollo: SDM / SUN su NTAG 424 DNA

*[English](protocol.md) · Italiano*

Sphragis implementa lo schema **pubblico** NXP Secure Dynamic Messaging (SDM),
detto anche SUN (Secure Unique NFC). È documentato nell'application note NXP
**AN12196** ed è comune a ogni deployment NTAG 424 DNA — non è proprietario.

## L'URL letto

A ogni tap il tag riflette dati dinamici in un URL:

```
https://example.com/t?picc_data=<hex>&cmac=<hex>
```

- **`picc_data`** — un blocco AES-128 (16 byte), cifrato AES-CBC con
  `K_SDMMetaReadKey` e IV a zero. Contiene un tag byte, lo UID e il contatore di
  letture (`SDMReadCtr`).
- **`cmac`** — l'SDMMAC troncato a 8 byte che autentica la lettura.

## Decifrare il PICCData

La decifratura AES-CBC con `K_SDMMetaReadKey` (IV = 16 byte a zero) produce:

```
byte 0        PICCDataTag   (bit7 = UID mirror, bit6 = contatore presente, nibble basso = lunghezza UID)
byte 1..n     UID           (tipicamente 7 byte)
3 byte succ.  SDMReadCtr    (little-endian, 24 bit)
resto         padding casuale
```

Sphragis valida le lunghezze dichiarate rispetto alla dimensione del blocco
prima di affettare (`sdm.decrypt_picc_data`), fallendo in modo chiuso su input
malformati.

## Verificare l'SDMMAC

Il MAC usa una chiave di sessione per-lettura derivata da `K_SDMFileReadKey`
(AN12196 §4.3.3):

```
SV2  = 3Ch C3h 00h 01h 00h 80h || UID || SDMReadCtr
Kses = AES-CMAC(K_SDMFileReadKey, SV2)
SDMMAC = troncatura( AES-CMAC(Kses, <dati file riflessi, vuoti per SUN semplice>) )
```

La `troncatura` tiene gli 8 byte in posizione dispari (1, 3, 5, …, 15). Il
valore calcolato è confrontato con il `cmac` dell'URL **a tempo costante**
(`hmac.compare_digest`).

## Validazione known-answer

L'implementazione riproduce il vettore ufficiale NXP a chiavi zero:

```
picc_data = EF963FF7828658A599F3041510671E88
cmac      = 94EED9EE65337086
```

Vedi `tests/test_sdm.py::test_nxp_known_answer_vector`. Se la crittografia
dovesse deviare, quel test fallisce subito.

## Non ancora supportato

- `SDMENCFileData` (dati file cifrati riflessi). Gli URL che lo contengono sono
  **rifiutati** (fail-closed) invece di essere verificati parzialmente.
- Il canale sicuro EV2 (`AuthenticateEV2First/NonFirst`) — fuori ambito: questo
  è un verificatore backend di messaggi SUN, non uno stack reader/APDU.
