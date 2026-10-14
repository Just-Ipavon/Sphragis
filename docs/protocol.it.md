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

## Dati di file cifrati (SDMENCFileData)

Un tag può anche cifrare a ogni lettura una porzione dei dati statici del file
NDEF e rifletterla come esadecimale ASCII, di solito nel parametro `enc`. Il
`Verifier` semplice continua a rifiutare questi URL (fail-closed); li gestisce
l'`EncFileVerifier`, da scegliere esplicitamente (`sphragis/encverifier.py`,
primitive in `sphragis/sdmenc.py`). Il percorso SUN di `sdm.py` è riusato
senza modifiche.

```
SV1      = C3h 3Ch 00h 01h 00h 80h || UID || SDMReadCtr
KsesENC  = AES-CMAC(K_SDMFileReadKey, SV1)
IVe      = AES-ECB(KsesENC, SDMReadCtr || 00h * 13)
FileData = AES-CBC-Decrypt(KsesENC, IVe, SDMENCFileData)
```

Con il mirror cifrato l'SDMMAC **non** è calcolato su un messaggio vuoto: copre
i byte ASCII riflessi da `SDMMACInputOffset` a `SDMMACOffset - 1`, che devono
includere tutto `SDMENCFileData`. Il layout supportato è quello di AN12196
§3.4.4.2.2:

```
...?picc_data=<32 hex>&enc=<n*32 hex>&cmac=<16 hex>
input MAC = "<enc hex>&cmac="   (è coperto anche ciò che sta fra enc e cmac)
```

Ordine di verifica: parsing (hex rigoroso, nessun nome di parametro duplicato,
con maiuscole diverse o percent-encoded, `cmac` dopo `enc`) → decifratura del
PICCData → controllo dell'SDMMAC sull'input **grezzo** a tempo costante →
controllo atomico del contatore → solo allora decifratura dei dati di file. I
byte decifrati sono restituiti solo con `AUTHENTIC`. Poiché il MAC è sui byte
grezzi, l'URL deve arrivare al verificatore esattamente come l'ha emesso il
tag: ricodificarlo o cambiare le maiuscole dell'esadecimale rende `FORGED` un
tap genuino.

```python
from sphragis import EncFileVerifier, StaticKeys
result = EncFileVerifier(StaticKeys(meta_key, file_key)).verify(url)
result.verdict, result.file_data
```

Da riga di comando: `sphragis verify --enc --meta-key … --file-key … URL`.
`provision_tag(..., file_data=...)` / `tools/provision.py --enc-data`
configurano il mirror su un tag e bloccano su una chiave la scrittura del file
NDEF; vedi [hardware.it.md](hardware.it.md) (non ancora validato su tag fisici).

## Validazione known-answer

L'implementazione riproduce il vettore ufficiale NXP a chiavi zero:

```
picc_data = EF963FF7828658A599F3041510671E88
cmac      = 94EED9EE65337086
```

Vedi `tests/test_sdm.py::test_nxp_known_answer_vector`. Se la crittografia
dovesse deviare, quel test fallisce subito.

Il mirror cifrato è vincolato ai due vettori a chiavi zero di AN12196 Rev. 2.0,
comprese le chiavi di sessione intermedie e l'IV (`tests/test_sdmenc.py`):

```
Tabella 3: picc_data = FDE4AFA99B5C820A2C1BB0F1C792D0EB
           enc       = 94592FDE69FA06E8E3B6CA686A22842B
           cmac      = C48B89C17A233B2C   -> dati file "xxxxxxxxxxxxxxxx"
Tabella 5: picc_data = FD91EC264309878BE6345CBE53BADF40
           enc       = CEE9A53E3E463EF1F459635736738962
           cmac      = ECC1E7F6C6C73BF6   -> dati file "xxxxxxxxxxxxxxxx"
```

## Non ancora supportato

- La validazione del provisioning `SDMENCFileData` su tag fisici (il flusso è
  provato solo contro un PICC finto).
- Layout `SDMENCFileData` in cui `SDMMACInputOffset` non coincide con l'inizio
  del valore di `enc`.
- Il canale sicuro EV2 (`AuthenticateEV2First/NonFirst`) — fuori ambito: questo
  è un verificatore backend di messaggi SUN, non uno stack reader/APDU.
