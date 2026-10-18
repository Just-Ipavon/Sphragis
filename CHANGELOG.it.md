# Registro delle modifiche

English: [CHANGELOG.md](CHANGELOG.md). Le versioni seguono il
[Semantic Versioning](https://semver.org/).

## Non rilasciato

### Contatori di firma FIDO2 / WebAuthn (#39)
- `WebAuthnBackend` verifica asserzioni WebAuthn (ES256, EdDSA) di credenziali
  registrate, con challenge monouso emesse dal server, e passa il contatore di
  firma al registro e al rilevatore: le regressioni del contatore generano gli
  stessi segnali dei tap SUN.
- Un contatore fermo a 0 (passkey sincronizzate) è *nessun contatore*
  (`no_counter`, `GENUINE`), non un segnale di clone; un calo a 0 dopo un
  contatore diverso da zero è una regressione. Documentato il compromesso del
  legame con il RP ID.

### Eventi di verifica firmati (#38)
- Dichiarazione COSE_Sign1 opzionale per ogni verifica (EdDSA/Ed25519, payload
  CBOR deterministico: riferimento pseudonimo alla tag, contatore,
  classificazione, nomi dei segnali, tempo, backend, algoritmo e versione
  della chiave; nessun materiale di chiave, nessun tap).
- Chiave di firma derivata dal segreto `event_signing` (con versioni); chiave
  pubblica su `GET /v1/event-key`. Interfaccia `EventSink`, `FileEventSink`,
  `verify_event`, vettore di test noto; andata e ritorno verificati con pycose.
- Impostazioni API `SPHRAGIS_EVENTS_FILE`, `SPHRAGIS_EVENTS_ON`,
  `SPHRAGIS_EVENT_KEY_VERSION`. L'extra `test` aggiunge pycose e cbor2 < 6.

### Agilità crittografica (#37)
- Le chiavi sono indirizzate per (nome, versione): la versione 1 mantiene i
  nomi senza suffisso, la versione N è `<nome>_v<N>`. Un `KeyRing` contiene più
  versioni attive durante una rotazione; i backend NTAG 424 DNA le provano e
  riportano quella che ha verificato (`build_keyring`, `SPHRAGIS_KEY_VERSIONS`).
- Risultati, osservazioni del rilevatore, alert, eventi di log e risposta API
  dettagliata riportano backend, algoritmo e versione della chiave. Le tabelle
  di osservazioni e alert su SQLite e Postgres ricevono le colonne sul posto al
  primo avvio; le righe precedenti risultano sconosciute.
- Procedura di rotazione e cambi di algoritmo documentati nella gestione delle
  chiavi.

### Backend di verifica (#35)
- Nuova interfaccia `VerificationBackend`: un backend legge e verifica un tap e
  restituisce un `AuthenticTap` normalizzato (identità, contatore, backend,
  algoritmo, payload); registro, rilevatore, servizio e API non dipendono più
  dal chip.
- `Ntag424SunBackend` e `Ntag424EncBackend` incapsulano i verificatori NTAG 424
  DNA esistenti senza cambiarne il comportamento; `TagAnalyzer(backends=[...])`
  sceglie il primo backend che accetta ogni tap, quindi i tap con
  SDMENCFileData passano ora anche per l'analyzer e la API (`SPHRAGIS_BACKENDS`).
- I risultati portano `backend` e `algorithm`; la risposta API dettagliata e
  l'evento di log riportano il backend.

### Rilevamento dei cloni
- Una regressione del contatore resta nella cronologia del rilevatore: i tap
  nuovi successivi su un UID biforcato portano `prior_divergence` (debole da
  solo) invece di risultare `GENUINE`.
- Nuovo segnale `counter_rate`: un contatore che avanza più in fretta di quanto
  una tag possa essere letta dal momento del floor (`max_tap_rate`,
  `rate_slack_seconds`).
- Due tap rapidi dallo stesso lettore le cui richieste arrivano in ordine
  inverso sono `SUSPICIOUS` (`counter_reordered`) anziché `CLONE_LIKELY`
  (`reorder_counters`, `reorder_seconds`).

## 1.0.0 — 2026-10-15

Prima release stabile: il motore generico di verifica per NTAG 424 DNA,
irrobustito dopo un auto-audit avversariale e validato su tag fisici.

### Validazione su hardware
- Intero ciclo di vita visto sul chip con un Chameleon Ultra: provisioning SUN
  in chiaro e con dati di file cifrati, blocco della scrittura NDEF,
  riscrittura autenticata, cambio delle chiavi per UID e ritorno alle chiavi
  di fabbrica.
- Chiave di originalità NXP corretta e fissata con le firme lette da tre tag
  fisiche; `Read_Sig` accetta lo stato `9190` restituito dalle tag reali.

### Gestione delle chiavi
- `tools/rekey.py` rifiuta le tag che non dimostrano la propria identità:
  firma di originalità, inventario degli UID già configurati, prova di
  possesso delle proprie chiavi, conferma digitando l'UID.
- Il ritorno alle chiavi di fabbrica risulta concluso una volta raggiunto, e
  una tag già configurata viene aperta prima con le sue chiavi.
- Una sessione EV2 viene chiusa dopo qualunque scambio fallito o quando il
  chip la termina, così non si invia nulla con un contatore disallineato.

### Provisioning
- Scritture NDEF bloccate sulla chiave 0 in ogni layout; le scritture su una
  tag bloccata si autenticano prima.
- Modello scritto in pezzi ISOUpdateBinary da 48 byte in un solo frame e senza
  Le (il Le in coda della forma di AN12196 è rifiutato dal chip).

### Rilevamento
- Registro durevole dei tap sugli store JSON, SQLite e Postgres: un contatore
  vecchio non è mai autentico, i replay non nascondono un clone né rallentano
  la tag genuina, un URL trattenuto genera un solo allarme, copie concorrenti
  dello stesso tap danno un solo GENUINE.
- I tap forgiati non restituiscono mai il PICCData decifrato; l'input
  costruito ad arte dà `ERROR`, mai un'eccezione; è accettato solo il layout
  standard del PICCData.
- Un tap, una sola codifica: `picc_data` e `cmac` devono essere esadecimali
  esatti della lunghezza giusta, un `enc=` vuoto blocca comunque la verifica e
  un URL senza query non viene mai letto dal percorso o dal frammento.

### API
- Indirizzo del client da `X-Forwarded-For` solo tramite proxy fidati (CIDR),
  IPv6 limitato per /64, filtro ASGI delle richieste (limite del corpo, limite
  per IP prima del parsing), query string oscurate nei log, webhook senza
  redirect e in background, impostazioni validate all'avvio.
- `risk_score` pubblico fisso per verdetto; le anteprime dei link ricevono una
  risposta neutra e non consumano il tap.

### Archiviazione, segreti e lettori
- File dei contatori con lock, fsync e accesso solo al proprietario; cartella
  dei segreti controllata per permessi, link simbolici e chiavi a zero; chiavi
  nascoste da `repr`.
- Ogni scambio con il lettore è limitato (estensioni del tempo d'attesa,
  dimensione della risposta, scadenza), CID/NAD rifiutati, lunghezza NDEF
  controllata prima della lettura.
- Backend PN532 rimosso: il lettore supportato è il Chameleon Ultra.

### Catena di fornitura
- Dipendenze della CI bloccate con hash, action fissate per commit, pip-audit
  e bandit nella CI, Dependabot, protezione contro il vecchio pacchetto
  PyCrypto.
- Le release vanno su PyPI da GitHub con il trusted publishing (nessun
  token), costruite con strumenti bloccati con hash, dietro un'approvazione
  sull'ambiente `pypi`.

## 0.4.0 e precedenti

Release di sviluppo: verifica SUN/SDM sui vettori NXP, rilevamento dei cloni,
API REST, SDMENCFileData, backend Postgres, diversificazione AN10922 e
gestione delle chiavi per UID.
