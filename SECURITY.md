# Security

Disk Scan finds duplicate, large, and changed files and creates a review plan. It does not move or delete scanned files. The scanner rejects unsafe roots and symlinks, opens files without following links, and applies file-count, byte, and time limits. SHA-256 supports duplicate detection and comparison; it does not encrypt files. Scanned paths and names can be sensitive, so use made-up folders in reports.

Saved scan results are plaintext protected by account permissions. Use your Mac’s disk encryption to protect saved files. The native app has an ad-hoc code signature. This lets the installer check whether its files changed. It does not prove who made the app. The build is not notarized.

Report security issues through [GitHub private vulnerability reporting](https://github.com/gmperkinsmba/disk-scan/security/advisories/new).
