# Publishing redveil to PyPI

This guide walks through publishing the `redveil` package to PyPI so anyone in the world can install it via `pip install redveil`.

## Prerequisites

- Python 3.12+
- An account on https://pypi.org (free)
- API token from https://pypi.org/manage/account/token/

## Step 1: Update `pyproject.toml`

Replace `FitzyPrjkt` with your GitHub username/organization in the `[project.urls]` section.

```toml
[project.urls]
Homepage = "https://github.com/YOUR_USERNAME/your-repo-name"
Repository = "https://github.com/YOUR_USERNAME/your-repo-name"
# etc.
```

Also update the author email:
```toml
authors = [{name = "Your Name", email = "you@example.com"}]
```

## Step 2: Verify the build

```bash
cd redveil
.venv/bin/pip install --upgrade build twine
.venv/bin/python -m build
```

This creates `dist/redveil-0.1.0-py3-none-any.whl` and `dist/redveil-0.1.0.tar.gz`.

## Step 3: Test the build locally

```bash
# Create a fresh test environment
python3.12 -m venv /tmp/redveil-test
/tmp/redveil-test/bin/pip install dist/redveil-0.1.0-py3-none-any.whl

# Verify the command works
/tmp/redveil-test/bin/redveil --help
/tmp/redveil-test/bin/redveil list-checks
```

## Step 4: Upload to Test PyPI (recommended first)

```bash
.venv/bin/twine upload --repository testpypi dist/*
```

You'll be prompted for username and password. Use `__token__` as username and your PyPI token as password (including the `pypi-` prefix).

Test install from Test PyPI:
```bash
python3.12 -m venv /tmp/test-from-pypi
/tmp/test-from-pypi/bin/pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ redveil
/tmp/test-from-pypi/bin/redveil --help
```

(The `--extra-index-url` lets pip fall back to PyPI for dependencies.)

## Step 5: Upload to production PyPI

```bash
.venv/bin/twine upload dist/*
```

This time use your production PyPI token (or the same one — they're the same if you only created one).

## Step 6: Verify

```bash
pip install redveil
redveil --help
redveil list-checks
redveil scan https://example.com
```

That's it! Your package is now live for the world.

## Subsequent releases

When you make changes:

1. Bump version in `pyproject.toml` (e.g., `0.1.0` → `0.1.1` or `0.2.0`)
2. Update `CHANGELOG.md` with the new version section
3. Commit to git: `git tag v0.1.1 && git push --tags`
4. Rebuild: `.venv/bin/python -m build`
5. Re-upload: `.venv/bin/twine upload dist/*`

## Automation (optional)

Add a GitHub Action to auto-publish on tag push. See `.github/workflows/release.yml` (not yet created — to be added).

## Troubleshooting

### "Invalid distribution filename"
The wheel must be named `redveil-VERSION-py3-none-any.whl`. If you see a different name, your `[project]` `name` field is wrong.

### "Package name already taken"
The name `redveil` might be taken on PyPI. Try alternatives: `redveil-sec`, `redveil-scanner`, `redveil-pentest`. Update `pyproject.toml` and rebuild.

### "Missing classifiers"
PyPI requires valid `classifiers` strings. Use the official list: https://pypi.org/classifiers/

### "Description missing or too short"
The PyPI page needs a long description. By default it uses `README.md`. Make sure your README has substantive content (not just a one-liner).

## Security

- NEVER commit your PyPI token to git
- Use environment variables: `TWINE_USERNAME=__token__ TWINE_PASSWORD=pypi-XXX twine upload dist/*`
- For CI, use GitHub Secrets: https://github.com/FitzyPrjkt/Redveil/settings/secrets/actions
- Enable 2FA on your PyPI account
