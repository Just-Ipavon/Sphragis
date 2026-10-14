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
