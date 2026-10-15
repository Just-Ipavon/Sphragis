# Registro delle modifiche

English: [CHANGELOG.md](CHANGELOG.md). Le versioni seguono il
[Semantic Versioning](https://semver.org/).

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
