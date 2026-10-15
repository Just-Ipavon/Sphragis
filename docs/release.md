# Releasing

Italiano: [release.it.md](release.it.md).

Publishing a GitHub release builds the package and uploads it to PyPI
(`.github/workflows/release.yml`). There is no PyPI token anywhere: PyPI
trusts the workflow through OpenID Connect (trusted publishing).

## One-time setup

1. **PyPI.** Log in at pypi.org → *Your projects* → *Publishing* → *Add a new
   pending publisher* (GitHub):
   - PyPI project name: `sphragis`
   - Owner: `Just-Ipavon` · Repository: `Sphragis`
   - Workflow name: `release.yml` · Environment name: `pypi`
2. **GitHub.** Settings → *Environments* → *New environment* `pypi`. Under
   *Deployment protection rules* add yourself as **required reviewer**, so
   every upload waits for your approval, and limit *Deployment branches and
   tags* to tags matching `v*`.

## Each release

1. Bump `version` in `pyproject.toml` and `__version__` in
   `sphragis/__init__.py`, add the section to `CHANGELOG.md` and
   `CHANGELOG.it.md`, merge to `main` with CI green.
2. Tag the merge commit and push the tag:
   ```bash
   git checkout main && git pull
   git tag -a v1.0.0 -m "Sphragis 1.0.0"
   git push origin v1.0.0
   ```
3. Create the GitHub release from the tag, with the changelog section as
   notes:
   ```bash
   awk '/^## 1.0.0/{f=1;next} /^## /{f=0} f' CHANGELOG.md > /tmp/notes.md
   gh release create v1.0.0 --title "Sphragis 1.0.0" --notes-file /tmp/notes.md --latest
   ```
4. Actions → *Release*: the build job checks that the tag equals `v` +
   the package version, builds sdist and wheel with the hash-locked tools in
   `requirements/release.lock`, then the publish job waits for your approval
   on the `pypi` environment and uploads with attestations.
5. Check <https://pypi.org/project/sphragis/> and
   `pip install sphragis==1.0.0` in a clean environment.

A version can be uploaded to PyPI only once: a mistake means a new patch
release, not a re-upload.

The build tools are locked with:

```bash
uv pip compile requirements/release.in --universal --generate-hashes -o requirements/release.lock
```
