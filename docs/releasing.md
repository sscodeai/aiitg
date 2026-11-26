# Releasing

This project publishes from a version tag through `.github/workflows/publish.yml`.

## One-time PyPI setup

The workflow uses PyPI Trusted Publishing, so no API token is stored in GitHub.

1. Create the `aiitg` project on PyPI (or use an existing project).
2. Add a trusted publisher with:
   - owner: `sscodeai`
   - repository: `aiitg`
   - workflow: `publish.yml`
   - environment: `pypi`
3. Create a GitHub environment named `pypi` and add protection rules if required by the repository.

## Release checklist

1. Bump the version in both places:
   - `pyproject.toml`
   - `src/aiitg/_version.py`
2. Move the `[Unreleased]` entries into a dated `[X.Y.Z]` section in `CHANGELOG.md`.
3. Run the gates:
   ```bash
   make test
   make lint
   make typecheck
   uv build
   uvx twine check dist/*
   ```
4. Open a release PR (`chore(release): X.Y.Z`) and merge it to `main`.
5. Create and push the annotated tag:
   ```bash
   git tag -a vX.Y.Z -m "aiitg X.Y.Z — <summary>"
   git push github vX.Y.Z
   ```
6. The `Publish` workflow builds the sdist/wheel and publishes to PyPI via Trusted Publishing.
7. Create the GitHub Release for the tag:
   ```bash
   gh release create vX.Y.Z --repo sscodeai/aiitg --title "aiitg X.Y.Z" --generate-notes
   ```

## Notes

- `uv.lock` is checked in; run `uv lock` after changing dependencies.
- The publish workflow only runs for tags matching `v*`.
- PyPI publishes are immutable: a version number cannot be reused after upload.
