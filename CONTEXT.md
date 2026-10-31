# Context

Disk Evidence produces a read-only file inventory for one explicit folder root. Its main records are scan files, exact duplicate groups, same-name content conflicts, growth observations, exclusions, and a review-only cleanup plan.

The scanner follows only regular files and directories opened relative to the selected root. It rejects symbolic links in the root path, skips symbolic links below it, and applies file, byte, and time limits. Incomplete scans remain visible and do not update the size-comparison baseline.

The app stores only local settings and prior sizes outside the product folder. Demo files are synthetic. The interface does not accept a filesystem path or issue cleanup operations. A plan records candidate paths, a retained path, hashes, and a recheck result so a person can inspect the evidence.

## Data choice

No external service or credentials are needed. Demo data is generated locally. Runtime state is private to the current account and excluded from version control.
