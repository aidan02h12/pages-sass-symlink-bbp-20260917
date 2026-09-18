# Authorized GitHub Pages security fixture

This repository is a disposable, marker-only fixture owned by `aidan02h12`.
It tests whether the classic GitHub Pages Sass build follows a source-tree
symlink outside the repository boundary.

The `_sass/_leak.scss` Git entry is intentionally a symbolic link to the
harmless standard container file `/etc/hostname`. No user data, credential,
PII, or third-party repository is targeted.

