# vulnScan — CLAUDE.md

## Project Purpose

`vulnScan` is a single-file interactive Bash security audit script for Fedora/RHEL/CentOS systems.
It walks the user through a sequential series of security checks, displays colorized findings with
PASS/WARN/FAIL ratings, and produces an overall numeric risk score. No changes are applied
automatically — the script is read-only and educational.

Target audience: homelab users, sysadmins, security learners. The README is layered to serve all three.

---

## Repository Layout

```
vulnScan/
├── vulnScan.sh        # Primary script — single monolithic file
├── CLAUDE.md          # This file
├── README.md          # Public-facing documentation
├── LICENSE            # MIT
└── .gitignore         # Sanitization list (see below)
```

---

## Script Architecture (`vulnScan.sh`)

### Structure (top to bottom)

1. **Header block** — shebang, license notice, version, description
2. **Global constants** — ANSI color codes, version string, score thresholds
3. **Utility functions** — `print_header`, `print_pass`, `print_warn`, `print_fail`, `print_info`, `pause`
4. **Privilege check** — warn if not root, offer `sudo` re-run
5. **Check modules** (each is a named function, called sequentially from `main`):
   - `check_system_hardening`   — sysctl, ASLR, core dumps, kernel params
   - `check_user_auth`          — passwords, PAM, sudo, SSH keys, failed logins
   - `check_network_firewall`   — open ports, firewalld rules, listening services
   - `check_file_permissions`   — SUID/SGID, world-writable, /tmp, sensitive file perms
   - `check_packages`           — outdated packages, unneeded services, CVE surface
   - `check_logging_audit`      — auditd, journald, syslog, log rotation
   - `check_boot_integrity`     — GRUB password, Secure Boot, UEFI, initramfs
   - `check_containers`         — Docker daemon, namespace isolation, SELinux, AppArmor
6. **Score summary** — tally PASS/WARN/FAIL counts, compute 0-100 risk score, print final report
7. **`main`** — calls privilege check, runs modules in order with `pause` between each, prints summary

### Scoring System

- Each check contributes points to a running tally
- PASS = 0 risk points, WARN = 1 risk point, FAIL = 3 risk points
- Final score: `min(100, (risk_points / max_possible) * 100)`
- Score buckets: 0-20 = Hardened, 21-40 = Acceptable, 41-60 = Needs Attention, 61-80 = Vulnerable, 81-100 = Critical

### Color Scheme (ANSI)

| Variable    | Color         | Use                        |
|-------------|---------------|----------------------------|
| `$RED`      | Bold red      | FAIL findings              |
| `$YELLOW`   | Bold yellow   | WARN findings              |
| `$GREEN`    | Bold green    | PASS findings              |
| `$CYAN`     | Bold cyan     | Section headers            |
| `$BLUE`     | Bold blue     | Informational / labels     |
| `$MAGENTA`  | Bold magenta  | Recommendations            |
| `$WHITE`    | Bold white    | General text               |
| `$RESET`    | Reset         | End of colored segment     |

### Navigation UX

- `pause` function prints `"\n${BLUE}Press [Enter] to continue...${RESET}"` and calls `read -r`
- Each check module starts with a full-width `print_header` banner showing the category name
- Recommendations are printed inline under each WARN/FAIL, prefixed with `[REC]` in magenta

---

## Coding Conventions

- Every function has a **multi-line comment block** above it explaining: purpose, what it checks, why it matters
- Every individual check inside a function has an **inline comment** explaining the security rationale
- Variable names: `UPPER_SNAKE_CASE` for globals/constants, `lower_snake_case` for locals
- Use `command -v foo &>/dev/null` to test for tool availability before calling it
- Gracefully skip any check whose required tool is missing, printing an INFO notice
- Never use `eval`. Avoid subshells in loops where a pipeline would work
- Quote all variable expansions: `"$var"` not `$var`
- Target: `bash 5.x` (Fedora default). No `#!/bin/sh` compatibility needed.

---

## What to Sanitize Before Committing

The following must never appear in any committed file:

- Hostnames, IP addresses, MAC addresses
- Usernames other than generic examples (`user`, `admin`, `example`)
- SSH public key material
- Filesystem paths that reveal real directory structure beyond standard locations
- Any output from real runs of the script (screenshots, logs, etc.)

`.gitignore` should exclude: `*.log`, `*.txt` (report files), `.env`, any `output/` directory.

---

## Development Notes

- Test with `shellcheck vulnScan.sh` before committing — zero warnings target
- The script is read-only; it must not write files, modify configs, or run anything with side effects
- Checks should prefer reading `/proc`, `/sys`, and config files over running commands where possible
- `ss` is preferred over `netstat`; `ip` over `ifconfig`; `systemctl` over `service`
- Fedora/RHEL primary: use `dnf`, `firewall-cmd`, `sestatus`, `dnf updateinfo`
- SELinux status is a first-class check — not an afterthought

---

## README Audience Layers

The README is structured to serve three audiences:

1. **Homelab / personal** — quick start, what it does, one-liner install
2. **Sysadmins / ops** — requirements, privilege model, what each category covers, no-auto-fix guarantee
3. **Security learners** — why each check category matters, links to CIS Benchmark and NIST SP 800-123

---

## Future Work (tracked here, not in code)

- [ ] Modular split into `lib/*.sh` for maintainability
- [ ] `--json` output flag for integration with dashboards
- [ ] HTML report generation
- [ ] GitHub Actions CI for shellcheck + bats unit tests
- [ ] Config file (`vulnScan.conf`) to toggle check categories
- [ ] Debian/Ubuntu distro family support
