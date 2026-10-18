# Security Policy / Politica di sicurezza

*English below · Italiano più sotto*

---

## English

### Status

Sphragis 2.0 has its cryptography validated against the official NXP test
vectors and its code adversarially self-reviewed (see
[THREAT_MODEL.md](THREAT_MODEL.md)), but it has **not** been independently
audited. It has been validated end to end on physical NTAG 424 DNA tags,
including the replacement of the factory all-zero keys with per-UID keys by
`tools/rekey.py`. A tag keeps the factory keys, and is therefore not
protected, until that step runs (see
[THREAT_MODEL.md](THREAT_MODEL.md#known-limitations-honest-scope)).
Treat it accordingly.

### Supported versions

Only the latest release (2.0.x) and `main` are supported. There are no
backported fixes to earlier versions.

### Reporting a vulnerability

Please **do not** open a public issue for security problems. Use GitHub's
**private vulnerability reporting** (the "Report a vulnerability" button under
the repository's *Security* tab) to open a private advisory.

Helpful details: affected file/function, a minimal reproduction, and the impact
you observed. A first response can be expected within a few days; this is a
personal project, not a staffed product.

### Scope

In scope: cryptographic verification (SDM/SUN and SDMENCFileData), the
clone-detection logic, the anti-replay stores (SQLite and Postgres), input
validation, key handling, and the provisioning tools (EV2 secure messaging,
APDU transports) in this repository.

Out of scope: physical attacks on the tag silicon, relay attacks on the
reader-to-tag channel, and anything in a downstream product built on top of
this engine.

---

## Italiano

### Stato

Sphragis 2.0 ha la crittografia validata contro i test vector ufficiali NXP e
il codice sottoposto a un auto-audit avversariale (vedi
[THREAT_MODEL.it.md](THREAT_MODEL.it.md)), ma **non** è stato verificato in
modo indipendente. È stato validato end to end su tag NTAG 424 DNA fisici,
compresa la sostituzione delle chiavi di fabbrica tutte a zero con chiavi per
UID tramite `tools/rekey.py`. Un tag tiene le chiavi di fabbrica, e quindi non
è protetto, finché quel passo non viene eseguito (vedi
[THREAT_MODEL.it.md](THREAT_MODEL.it.md#limiti-noti-ambito-onesto)).
Regolati di conseguenza.

### Versioni supportate

Sono supportati solo l'ultima release (2.0.x) e `main`. Non ci sono fix
retroportati alle versioni precedenti.

### Segnalare una vulnerabilità

Per favore **non** aprire una issue pubblica per problemi di sicurezza. Usa il
**private vulnerability reporting** di GitHub (il pulsante "Report a
vulnerability" nella scheda *Security* del repository) per aprire un advisory
privato.

Dettagli utili: file/funzione interessati, una riproduzione minima e l'impatto
osservato. Una prima risposta è prevista entro qualche giorno; questo è un
progetto personale, non un prodotto con un team dedicato.

### Ambito

Nell'ambito: verifica crittografica (SDM/SUN e SDMENCFileData), logica di
clone-detection, store anti-replay (SQLite e Postgres), validazione input,
gestione chiavi e strumenti di provisioning (secure messaging EV2, transport
APDU) in questo repository.

Fuori ambito: gli attacchi fisici al silicio del tag, gli attacchi relay sul
canale lettore-tag, e qualsiasi cosa in un prodotto a valle costruito su questo
motore.
