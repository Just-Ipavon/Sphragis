# Security Policy / Politica di sicurezza

*English below · Italiano più sotto*

---

## English

### Status

Sphragis is a **learning / portfolio project**. Its cryptography is validated
against the official NXP test vectors and the code has been adversarially
self-reviewed (see [THREAT_MODEL.md](THREAT_MODEL.md)), but it has **not** been
independently audited and has not yet been validated against physical tags.
Treat it accordingly.

### Supported versions

Only the latest `main` is supported. There are no backported fixes.

### Reporting a vulnerability

Please **do not** open a public issue for security problems. Use GitHub's
**private vulnerability reporting** (the "Report a vulnerability" button under
the repository's *Security* tab) to open a private advisory.

Helpful details: affected file/function, a minimal reproduction, and the impact
you observed. A first response can be expected within a few days; this is a
personal project, not a staffed product.

### Scope

In scope: cryptographic verification (SDM/SUN), the clone-detection logic, the
anti-replay store, input validation, and key handling in this repository.

Out of scope: the EV2 secure channel and APDU layer (not implemented), physical
attacks on the tag silicon, and anything in a downstream product built on top of
this engine.

---

## Italiano

### Stato

Sphragis è un **progetto di studio / portfolio**. La sua crittografia è validata
contro i test vector ufficiali NXP e il codice è stato sottoposto a un
auto-audit avversariale (vedi [THREAT_MODEL.it.md](THREAT_MODEL.it.md)), ma
**non** è stato verificato in modo indipendente e non è ancora stato validato su
tag fisici. Regolati di conseguenza.

### Versioni supportate

È supportato solo l'ultimo `main`. Non ci sono fix retroportati.

### Segnalare una vulnerabilità

Per favore **non** aprire una issue pubblica per problemi di sicurezza. Usa il
**private vulnerability reporting** di GitHub (il pulsante "Report a
vulnerability" nella scheda *Security* del repository) per aprire un advisory
privato.

Dettagli utili: file/funzione interessati, una riproduzione minima e l'impatto
osservato. Una prima risposta è prevista entro qualche giorno; questo è un
progetto personale, non un prodotto con un team dedicato.

### Ambito

Nell'ambito: verifica crittografica (SDM/SUN), logica di clone-detection, store
anti-replay, validazione input e gestione chiavi in questo repository.

Fuori ambito: il canale sicuro EV2 e il livello APDU (non implementati), gli
attacchi fisici al silicio del tag, e qualsiasi cosa in un prodotto a valle
costruito su questo motore.
