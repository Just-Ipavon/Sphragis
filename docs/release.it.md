# Pubblicare una release

English: [release.md](release.md).

Pubblicare una release su GitHub costruisce il pacchetto e lo carica su PyPI
(`.github/workflows/release.yml`). Non esiste alcun token PyPI: PyPI si fida
del workflow tramite OpenID Connect (trusted publishing).

## Configurazione iniziale (una volta sola)

1. **PyPI.** Accedi a pypi.org → *Your projects* → *Publishing* → *Add a new
   pending publisher* (GitHub):
   - PyPI project name: `sphragis`
   - Owner: `Just-Ipavon` · Repository: `Sphragis`
   - Workflow name: `release.yml` · Environment name: `pypi`
2. **GitHub.** Settings → *Environments* → *New environment* `pypi`. In
   *Deployment protection rules* aggiungi te stesso come **required
   reviewer**, così ogni caricamento aspetta la tua approvazione, e limita
   *Deployment branches and tags* ai tag che corrispondono a `v*`.

## A ogni release

1. Aggiorna `version` in `pyproject.toml` e `__version__` in
   `sphragis/__init__.py`, aggiungi la sezione a `CHANGELOG.md` e
   `CHANGELOG.it.md`, fai il merge su `main` con la CI verde.
2. Crea il tag sul commit di merge e fai il push del tag:
   ```bash
   git checkout main && git pull
   git tag -a v1.0.0 -m "Sphragis 1.0.0"
   git push origin v1.0.0
   ```
3. Crea la release su GitHub dal tag, con la sezione del changelog come note:
   ```bash
   awk '/^## 1.0.0/{f=1;next} /^## /{f=0} f' CHANGELOG.md > /tmp/notes.md
   gh release create v1.0.0 --title "Sphragis 1.0.0" --notes-file /tmp/notes.md --latest
   ```
4. Actions → *Release*: il job di build controlla che il tag sia `v` + la
   versione del pacchetto, costruisce sdist e wheel con gli strumenti bloccati
   con hash in `requirements/release.lock`, poi il job di pubblicazione
   aspetta la tua approvazione sull'ambiente `pypi` e carica con le
   attestazioni.
5. Controlla <https://pypi.org/project/sphragis/> e
   `pip install sphragis==1.0.0` in un ambiente pulito.

Una versione si può caricare su PyPI una sola volta: un errore richiede una
nuova patch release, non un nuovo caricamento.

Gli strumenti di build si bloccano con:

```bash
uv pip compile requirements/release.in --universal --generate-hashes -o requirements/release.lock
```
