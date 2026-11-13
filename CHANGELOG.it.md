# Registro delle modifiche

English: [CHANGELOG.md](CHANGELOG.md). Le versioni seguono il
[Semantic Versioning](https://semver.org/).

## Non rilasciato

### Corretto

- Packaging, documentazione e CI (#69): un `MANIFEST.in` mette nella sdist
  ciò che i suoi test leggono (helper dei test, documentazione, tool, esempi,
  lock, workflow), e un nuovo job di CI costruisce sdist e wheel ed esegue la
  suite dalla sdist estratta. La licenza è dichiarata come espressione SPDX
  con `license-files` (setuptools 77 o successivo), senza la tabella e il
  classifier deprecati. Il README mostra l'output attuale di
  `clone_demo.py`, e un test lo tiene allineato. Il workflow di sicurezza
  installa `pip-audit`, `bandit` e `ruff` da un
  `requirements/security.lock` con hash e ora esegue le regole di
  correttezza di ruff (`F`, `E9`, `B`, corrette in tutto il codice).
  L'immagine Postgres del servizio è fissata per digest e il suo job gira
  su Python 3.10 (la più vecchia supportata); Dependabot controlla anche `requirements/`.
### Sicurezza

- `rekey_tag` (e `tools/rekey.py --to-factory`) non cambia più uno slot già
  cambiato mentre lo slot 0 è su chiavi di fabbrica e nessuno slot specifico
  dell'UID prova una chiave: ChangeKey invierebbe la vecchia chiave, per lo
  slot 2 la `meta_read` comune a tutta la flotta, sotto la chiave pubblica
  tutta a zero. `--allow-known-uid` non scavalca il controllo.

### Corretto

- La CLI, l'emulatore e i tool non terminano più con un traceback su input
  errato (#68): `emulate --uid` deve essere di 7 byte esadecimali e
  `--counter`/`--taps` restano nel contatore a 24 bit, come errori d'uso;
  `verify --store` con un file vuoto o corrotto stampa un errore.
  `EmulatedTag` rifiuta un contatore fuori intervallo, si ferma al limite di
  24 bit come una tag reale, e aggiunge i parametri SUN con `&` a un
  `base_url` che ha già una query. `tools/provision.py` e `tools/rekey.py`
  riportano gli errori di lettore, APDU e segreti su una riga (uscita 2);
  l'esempio di provision senza `--port` è corretto. Il controllo di velocità
  impossibile ignora la cronologia registrata dopo il tap (salti
  dell'orologio, sfasamento tra host).
- Due tap autentici dello stesso tag elaborati in contemporanea non rendono
  più `SUSPICIOUS` (`prior_divergence`) tutti i tap successivi. Il registro e
  la cronologia del rilevatore sono scritti in due passi, quindi la
  cronologia poteva ricevere i due contatori nuovi in ordine inverso e
  leggerlo come una biforcazione. Ogni riga della cronologia ora registra se
  il registro l'ha trovata nuova o in regressione (colonna `regression`
  aggiunta sul posto alle tabelle SQLite e Postgres), e le righe nuove non
  vengono mai prese per una biforcazione; le righe della 2.0.0 sono ancora
  giudicate dall'ordine (#62).
- Storage SQLite (#65): `:memory:` viene rifiutato con un errore chiaro invece
  di fallire con "no such table" alla prima richiesta servita da un altro
  thread; `close()` ora chiude le connessioni di tutti i thread (aperte con
  `check_same_thread=False`), e `SqliteAlertSink` ottiene `close()` e il
  supporto come context manager. `SqliteKeyInventory` chiude la connessione
  dopo ogni chiamata, gli storage Postgres scartano e chiudono una
  connessione rotta quando la sostituiscono, e un redirect di webhook
  rifiutato non lascia più aperto il socket della risposta. La suite di test
  ora tratta `ResourceWarning` come errore.
- Il rate limit per IP non si riduce più a un solo bucket dietro un socket
  Unix o un proxy che scrive `ip:porta`: gli hop inoltrati possono essere
  `ip:porta`, `[v6]` o `[v6]:porta`, `unix` in `SPHRAGIS_TRUSTED_PROXIES`
  rende fidato il proxy davanti a un socket Unix, e l'API registra un avviso
  quando il peer non ha indirizzo e nulla indica quello del client (#66).
- L'input malformato non sfugge più con un tipo di eccezione inatteso (#64):
  un `clientDataJSON` WebAuthn il cui `origin` o `type` non è una stringa dà
  `ERROR` invece di un `TypeError` che arriva al chiamante; `cbor_decode`
  solleva `EventError` per una chiave di mappa che non è intero, testo o
  byte, e per annidamenti oltre gli 8 livelli (prima arrivava a
  `RecursionError` prima del controllo della firma); `verify_webhook`
  restituisce `False` per un header di firma non ASCII o assente.
- Un tap autentico con un parametro di query aggiuntivo contenente `?` o `:`
  (`&next=/a?b=1`, `v:1&…`) veniva letto come URL e diventava `ERROR`. Una
  query senza URL ora si riconosce da un `=` prima del primo `?` o `#`, e
  `/t` passa la sua query in modo esplicito (#67).
- Il `CounterStore` JSON rilegge il file condiviso anche per `last_counter`,
  `is_fresh` e `seen`, così un'istanza non riporta più una soglia che un altro
  processo ha già superato (#67).
- `check_and_advance` registra il contatore anche nel registro dei tap di un
  UID, una volta che questo è iniziato, così uno storage usato sia da
  `Verifier` sia da `TagAnalyzer` valuta un replay esatto come `REPLAY` e non
  come regressione del contatore (#67).
- Gli storage non convertono più in maiuscolo ogni identità: solo gli UID
  esadecimali senza prefisso (NTAG 424 DNA), mentre le identità con prefisso
  come `fido2:<base64url>` conservano maiuscole e minuscole, così due
  credenziali WebAuthn i cui id differiscono solo per le maiuscole non
  condividono più contatore e cronologia (#63). Aggiornamento: i dati NTAG non
  cambiano. Le righe che la 2.0.0 ha salvato per un'identità non esadecimale
  erano in maiuscolo; una credenziale con lettere minuscole nell'id inizia una
  nuova cronologia con il suo id reale.

## 2.0.0 — 2026-10-18

Il motore si apre a più famiglie di chip dietro un'unica interfaccia di
verifica, con risultati che dicono cosa li ha prodotti e possono essere firmati
per registri a lungo termine. Il rilevamento dei cloni tiene sotto
osservazione un UID biforcato.

### Aggiornare dalla 1.0
- La API pubblica resta compatibile: `TagAnalyzer(keys)`, `Verifier`,
  `EncFileVerifier`, gli storage e gli endpoint REST funzionano come prima.
- Alcuni verdetti cambiano di proposito: i tap nuovi su un UID la cui
  cronologia contiene una regressione del contatore sono `SUSPICIOUS`
  (`prior_divergence`) invece di `GENUINE`; un contatore che corre più veloce
  di qualsiasi lettore aggiunge `counter_rate`; due tap rapidi dallo stesso
  lettore consegnati in ordine inverso sono `SUSPICIOUS` (`counter_reordered`)
  invece di `CLONE_LIKELY`.
- Le tabelle di osservazioni e alert su SQLite e Postgres ricevono le colonne
  `backend`, `algorithm` e `key_version` sul posto al primo avvio; nessuna
  migrazione manuale. Le righe scritte dalla 1.0 risultano con provenienza
  sconosciuta.
- Nuove impostazioni facoltative: `SPHRAGIS_BACKENDS`, `SPHRAGIS_KEY_VERSIONS`,
  `SPHRAGIS_EVENTS_FILE`, `SPHRAGIS_EVENTS_ON`, `SPHRAGIS_EVENT_KEY_VERSION`. I
  valori di default mantengono il comportamento della 1.0.
- Il backend FIDO2/WebAuthn è validato solo con un autenticatore software; la
  validazione su una carta fisica è seguita in #39.

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
  `verify_event`, vettore di test noto; andata e ritorno verificati con python-cwt.
- Impostazioni API `SPHRAGIS_EVENTS_FILE`, `SPHRAGIS_EVENTS_ON`,
  `SPHRAGIS_EVENT_KEY_VERSION`. L'extra `test` aggiunge python-cwt, cbor2 e cryptography.

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
