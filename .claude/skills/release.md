# /release — vulnScan Release Workflow

Walk through a complete versioned release of vulnScan. Run this after all changes are committed and the working tree is clean.

## Steps

Follow these steps in order. Do not skip any. Confirm each before proceeding to the next.

### 1. Pre-flight checks

- Run `git status` — working tree must be clean. If not, stop and tell the user.
- Run `shellcheck vulnScan.sh apply-hardening.sh` — must be zero warnings. If not, stop and tell the user.
- Show the user the current version (grep `readonly VERSION` in `vulnScan.sh`) and the latest git tag.
- Ask the user for the new version number (e.g. `0.3.0`). Store it as NEW_VERSION.

### 2. Bump versions

Make all four version updates in a single pass:

1. `vulnScan.sh` header comment — `# Version  : X.X.X`
2. `vulnScan.sh` VERSION constant — `readonly VERSION="X.X.X"`
3. `apply-hardening.sh` header comment — `# Version  : X.X.X`
4. `CLAUDE.md` first line after the title — `**Current release:** vX.X.X`
5. `README.md` version badge URL — `version-vX.X.X-blue` and the release tag link

After all edits, run `shellcheck vulnScan.sh apply-hardening.sh` again to confirm still clean.

### 3. Commit the version bump

Stage only the four files changed above and commit with message:
```
Bump versions to vX.X.X
```

### 4. Tag at HEAD

Check if the tag `vX.X.X` already exists. If it does, delete it locally and remotely first. Then create a new annotated tag at HEAD:
```
git tag -a vX.X.X -m "vX.X.X — <one-line summary of what's new>"
```
Push the tag: `git push origin vX.X.X`

### 5. Create GitHub release

Use `gh release create` with:
- Title: `vX.X.X — <short description>`
- Body: what's new in this release (ask the user for highlights if not obvious from the commit log)
- Link to full changelog: `vPREV...vX.X.X` compare URL

### 6. Update memory

Update the project memory file at `~/.claude/projects/-home-notsure-Desktop-vulnScan/memory/project_vulnscan.md` to reflect the new latest release, marking it fully shipped with the GitHub release URL.

### 7. Final confirmation

Run `git log --oneline -5` and `git tag` and report the release URL to the user.
