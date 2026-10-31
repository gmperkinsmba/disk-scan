# Disk Evidence

**First principle:** Show evidence for each cleanup idea. Never change scanned files.

Disk Evidence is a local, read-only folder scanner. It groups exact byte duplicates by SHA-256. It flags files with the same name but different contents. It compares file sizes across complete scans. Its cleanup plan proposes one copy to keep and rechecks every file. The plan does not delete or move files.

## macOS app

The native app uses a local WebKit window and a loopback-only server. It opens in the synthetic demo. Use the Folder menu to choose a folder or return to the demo. The menu uses the macOS folder picker.

To build on macOS with Python 3.12 and uv:

    uv venv --python 3.12 .desktop-venv
    . .desktop-venv/bin/activate
    uv pip install --python .desktop-venv/bin/python -r requirements-desktop.lock.txt
    python build_desktop.py
    python install_desktop.py

The build writes `dist/Disk Evidence.app`. It replaces only an earlier build with the matching bundle ID and ownership marker, and keeps a timestamped copy. The installer checks the app identity before copying it to `~/Applications`; it refuses unmarked or unrelated apps and keeps a timestamped copy of an owned install. PyInstaller applies an ad-hoc signature. The app has no Apple Developer ID signature and is not notarized. macOS may ask you to approve opening it. Build on macOS for its Cocoa window. The bundle includes third-party license notices.

After install, open `~/Applications/Disk Evidence.app` in Finder. The bundle includes its Python runtime, so the app does not need a separate Python install, browser, or server command. Quit with Command-Q or close its window. To uninstall, move the app to Trash. Local settings and demo data in `~/.disk-evidence` remain.

To work on the native shell, keep the source assets in this folder and run `python desktop.py` from the activated environment. The desktop shell does not expose a Python bridge to page scripts.

**Browser alternative.**

The browser server uses only the Python standard library. It is useful for development or when you want to scan a folder from a browser.

The browser version remains available for development and as an alternative. Start it with the synthetic demo folder:

    python3 disk.py

Open http://127.0.0.1:8315. The demo has same-byte files with different names. It also has different files with the same name and a small growing log. Use Add synthetic log line to add one line. Then scan again.

To scan a folder you choose, provide its path when starting the server:

    python3 disk.py --root /absolute/path/to/folder

The browser cannot change the selected root. Stop the server to select another folder. Bind is loopback only.

## Settings and limits

Settings are kept outside this folder in ~/.disk-evidence with owner-only permissions. Exclusions are relative to the selected root. Built-in exclusions cover .git, .svn, .hg, node_modules, .venv, venv, and __pycache__.

The default limits are 5,000 files, 500 MB read, and 10 seconds. Hard limits are 20,000 files, 2 GB read, and 25 seconds. A scan that reaches a limit is marked incomplete. It does not replace the saved comparison history. The app skips symlinks and other non-regular files. This includes directories and devices. It rejects a symlink in the selected root path.

## Review and export

The scan view shows file sizes and shortened hashes, duplicate groups, same-name conflicts, and size growth. Pick one retained copy per duplicate group to draft a review plan. The app re-reads the files within the scan limits and marks changed files stale. Export saves the current scan and optional plan as JSON. No cleanup action is implemented.

## Tests

    python -m py_compile disk.py desktop.py desktop_policy.py build_desktop.py install_desktop.py test_disk.py test_desktop.py
    python -m unittest -v

Tests check duplicate and name grouping, successive growth, and symlink boundaries. They also check that scans leave source bytes unchanged. Other tests check partial scans, deadlines during file reads, and bounded stale-plan checks.

## Data and license

The demo data is synthetic. Scan history and settings stay in the local runtime folder. That folder is not part of this repository. Original code is under the MIT License. See LICENSE.
