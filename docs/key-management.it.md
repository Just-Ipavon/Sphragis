# Gestione delle chiavi

*[English](key-management.md) · Italiano*

Una singola chiave fissa su ogni tag è un punto di fallimento totale: estraila
da un chip e puoi falsificarli tutti. Sphragis supporta il pattern di produzione
— **chiavi diversificate per UID** — e tiene il materiale chiave **fuori dal
codice**.

## Diversificazione (AN10922)

`diversify.diversify_key` deriva una chiave AES-128 per tag da una master key e
da dati unici del tag, secondo NXP AN10922:

```
D      = 0x01 || DivInput || padding   (sempre 32 byte: 80h 00h ...)
DivKey = AES-CMAC(MasterKey, D)        (ultimo blocco XOR K2 se imbottito, altrimenti K1)
```

L'imbottitura a due blocchi conta: con un `DivInput` di 15 byte o meno (per
esempio un UID da 7 byte) un CMAC standard su `0x01 || DivInput` darebbe una
chiave diversa, che nessun'altra implementazione AN10922 riprodurrebbe. Il
codice segue la nota applicativa ed è vincolato al suo esempio §2.2.1
(`tests/test_diversify.py`).

`DiversifiedKeys` la collega al verificatore: la meta-read key resta fissa
(serve a decifrare il PICCData prima di conoscere lo UID), mentre la file-read
key — quella che autentica davvero il tap — è unica per UID. Un'etichetta
`context` inserisce un identificatore di applicazione/sistema, così la stessa
master key produce chiavi diverse tra deployment non collegati.

```python
from sphragis import DiversifiedKeys
keys = DiversifiedKeys(master_file_key=..., meta_read_key=..., context=b"DEMO")
file_key = keys.file_read_key(uid)   # unica per tag
```

## Scrivere le chiavi sulle tag

`keyprov.py` sostituisce le cinque chiavi applicative di una tag con chiavi
per UID (`tools/rekey.py` sull'host con il lettore). Assegnazione:

| Slot | Ruolo | Chiave |
|------|-------|--------|
| 0 | AppMasterKey (riconfigura la tag) | AN10922 da `master_admin`, M = UID ‖ 00h ‖ contesto |
| 1 | SDMFileRead (MAC, dati di file cifrati) | `DiversifiedKeys.file_read_key(uid)`, da `master_file` |
| 2 | SDMMetaRead (PICCData) | `meta_read`, condivisa: l'UID si conosce solo dopo aver decifrato il PICCData |
| 3, 4 | non usate dal layout SUN | AN10922 da `master_admin`, M = UID ‖ slot ‖ contesto |

`master_admin` è un **segreto separato**: i server di verifica hanno bisogno
solo di `master_file` e `meta_read`, quindi la chiave che può riconfigurare le
tag resta sulla postazione di provisioning.

Il flusso (`rekey_tag`):

1. Autenticazione sullo slot 0 con uno schema noto (fabbrica o destinazione),
   lettura dell'UID con GetCardUID e della versione di ogni slot con
   GetKeyVersion. Le chiavi di fabbrica hanno versione 00h, quelle Sphragis
   01h (o la `--key-version` scelta), quindi la chiave attuale di ogni slot è
   nota; una versione che non corrisponde a nessuno schema noto ferma tutto
   prima di qualunque scrittura.
2. ChangeKey degli slot 1-4, poi lo slot 0 per ultimo (cambiare la chiave di
   sessione chiude la sessione). AN12196 §5.16 copre entrambi i casi; entrambi
   sono vincolati ai suoi vettori.
3. Autenticazione con ogni nuova chiave e rilettura di tutte le versioni.

Un'esecuzione interrotta riprende dalle versioni; `--to-factory` rimette le
chiavi tutte a zero. Le chiavi non compaiono mai nei log, solo i key check
value (KCV). L'UID viene da GetCardUID, oppure da un tap SUN che deve
verificare per intero con le chiavi candidate (decifrare il PICCData da solo
non autentica nulla).

**Non perdere `master_admin`.** Senza, una tag non si può più riconfigurare né
riportare alle chiavi di fabbrica; i tap continuano a verificare finché
esistono `master_file` e `meta_read`. Fai un backup dei segreti prima di
cambiare le chiavi di qualunque tag.

## Backend dei segreti

`secrets.py` astrae *da dove* arriva il materiale chiave dietro una piccola
interfaccia `SecretsBackend`, così il verificatore non cambia quando passi da
una variabile d'ambiente di sviluppo a un KMS gestito:

- **`EnvSecretsBackend`** — chiavi hex da variabili d'ambiente (`SPHRAGIS_*`).
- **`FileSecretsBackend`** — chiavi hex da file; **rifiuta** i file leggibili da
  gruppo/altri (POSIX).
- **`KmsSecretsBackend`** — punto di estensione: sottoclassa e implementa
  `get_key` per AWS KMS, GCP KMS, HashiCorp Vault o un HSM PKCS#11.

```python
from sphragis import EnvSecretsBackend, build_diversified_keys
keys = build_diversified_keys(EnvSecretsBackend())   # nessuna chiave nel codice
```

## Limite onesto

Un backend software porta la chiave nella memoria del processo, dove i `bytes`
di Python non possono essere azzerati in modo affidabile. Un vero HSM tiene la
chiave residente ed esegue la crittografia dentro il modulo; `KmsSecretsBackend`
è il punto dove va quell'integrazione. Per NTAG 424 DNA la master key dovrebbe
vivere in un HSM/KMS e dovrebbe transitare solo materiale diversificato.
