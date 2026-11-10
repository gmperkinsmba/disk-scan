# Disk Scan

Local, read-only folder scanner. Groups exact byte duplicates by SHA-256, flags same-name files with different contents, and proposes a cleanup plan. It never deletes or moves files.

## Run

```sh
python3 disk.py
python3 disk.py --root /absolute/path/to/folder
```

The Mac app is built with `build_desktop.py` and installed with `install_desktop.py`; the README gives the exact steps and the pinned requirements file.

## Test

```sh
python -m py_compile disk.py desktop.py desktop_policy.py build_desktop.py install_desktop.py test_disk.py test_desktop.py
python -m unittest -v
```

Run the tests before committing. There is no separate lint step.

## Layout

- Core code: `disk.py`
- Browser UI: `app.css`, `app.js`, `index.html`
- Mac app wrapper, build and install: `build_desktop.py`, `desktop-app-owner.txt`, `desktop-assets.txt`, `desktop.py`, `desktop_policy.py`, `install_desktop.py`
- Installer and runtime safety checks: `install_security.py`
- Dependencies: `requirements-desktop.lock.txt`, `requirements-desktop.txt`
- Tests: `test_desktop.py`, `test_disk.py`, `tests/`
- Docs: `CONTEXT.md`, `LICENSE`, `README.md`, `SECURITY.md`, `third_party_licenses/`

## Conventions

- `README.md` describes behaviour and limits; `CONTEXT.md` holds the domain terms and rules. Keep both in step with code changes.
- Read `SECURITY.md` before changing request handling, file access, or the installer.
- Demo data, fixtures and examples are made up. Keep them that way.
- Never commit secrets, keys, tokens, or runtime data.
- A behaviour change comes with a test.
