# vulnScan

> An interactive, colorized Bash security audit tool for Fedora / RHEL / CentOS systems.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Shell: Bash 5+](https://img.shields.io/badge/shell-bash%205%2B-blue.svg)]()
[![Platform: Fedora/RHEL](https://img.shields.io/badge/platform-Fedora%20%7C%20RHEL%20%7C%20CentOS-informational.svg)]()
[![ShellCheck](https://img.shields.io/badge/shellcheck-passing-brightgreen.svg)]()

---

## What is vulnScan?

`vulnScan` is a single-file, read-only Bash script that audits a Linux system against common
security best practices. It walks you through **8 check categories** one section at a time,
displays results in color-coded PASS / WARN / FAIL format, and ends with an overall **numeric
risk score** so you know exactly where your system stands.

**vulnScan never modifies your system.** It reads configuration, inspects the kernel, and
queries running services — but it does not write files, change settings, or restart anything.

Once you have your results, a companion script — **`apply-hardening.sh`** — can automatically
apply the most common fixes for you. Run it after the audit, then re-run the audit to see your
improved score.

---

## Features

- **8 security check categories** covering the full hardening surface
- **Color-coded findings** — green PASS, yellow WARN, red FAIL
- **Inline recommendations** for every WARN and FAIL finding
- **Numeric risk score** (0–100) with a letter-grade summary at the end
- **Interactive walk-through** — pause between sections so you can digest results
- **Root-aware** — warns clearly if not root, offers to re-run with `sudo`
- **Graceful degradation** — skips checks whose required tools are missing, tells you why
- **Zero side effects** — read-only, safe to run on production systems
- **Heavily commented** — every check explains what it does and why it matters
- **ShellCheck clean** — linted to zero warnings

---

## Check Categories

| # | Category | What It Covers |
|---|----------|----------------|
| 1 | **System Hardening** | Kernel parameters (`sysctl`), ASLR, core dumps, `/proc` hardening |
| 2 | **User & Auth Security** | Password policies, PAM config, `sudo` rules, SSH key hygiene, failed logins |
| 3 | **Network & Firewall** | Open ports (`ss`), `firewalld` rules, listening services, IPv6 exposure |
| 4 | **File & Permission Auditing** | SUID/SGID binaries, world-writable files, `/tmp` permissions, sensitive file modes |
| 5 | **Package & Software** | Outdated packages (`dnf`), unneeded/enabled services, known-vulnerable software |
| 6 | **Logging & Auditd** | `auditd` status and rules, `journald` config, log rotation, syslog integrity |
| 7 | **Boot & Integrity** | GRUB password, Secure Boot / UEFI state, `initramfs` permissions |
| 8 | **Container / VM Surface** | Docker daemon security, SELinux / AppArmor status, namespace isolation |

---

## Risk Scoring

After all checks complete, vulnScan calculates a **risk score from 0 to 100**:

| Score | Grade | Meaning |
|-------|-------|---------|
| 0 – 20 | **A — Hardened** | Excellent posture, minimal exposure |
| 21 – 40 | **B — Acceptable** | Good baseline, a few items to tighten |
| 41 – 60 | **C — Needs Attention** | Meaningful gaps that should be addressed |
| 61 – 80 | **D — Vulnerable** | Significant misconfigurations present |
| 81 – 100 | **F — Critical** | High-risk state, immediate action recommended |

Each WARN finding adds **1 risk point**; each FAIL adds **3 risk points**.

---

## Requirements

| Requirement | Notes |
|-------------|-------|
| **OS** | Fedora 38+, RHEL 8/9, CentOS Stream 8/9, AlmaLinux, Rocky Linux |
| **Shell** | Bash 5.0 or newer |
| **Privileges** | Root or `sudo` (most checks require elevated access) |
| **Tools** | `ss`, `firewall-cmd`, `sestatus`, `dnf`, `auditctl`, `systemctl` — all standard on Fedora/RHEL |

> **Note for other distros:** Debian/Ubuntu support is planned. The script will warn and skip
> distro-specific checks (like `firewall-cmd` or `dnf`) if it detects an incompatible environment.

---

## Installation

```bash
# Clone the repo
git clone https://github.com/cainepavl/vulnScan.git
cd vulnScan

# Make both scripts executable
chmod +x vulnScan.sh apply-hardening.sh
```

No dependencies to install beyond what ships with Fedora/RHEL by default.

---

## Usage

### Basic run (recommended — requires root)

```bash
sudo ./vulnScan.sh
```

### Run as a normal user (limited checks, informational)

```bash
./vulnScan.sh
```

> vulnScan will detect that it is not running as root, explain which checks will be skipped,
> and offer to re-run with `sudo` before proceeding.

### Navigation

- Each section displays its findings, then pauses with **`[Enter] to continue`**
- Recommendations are shown inline under each WARN/FAIL result, prefixed with `[REC]`
- The final summary shows total PASS/WARN/FAIL counts and your risk score

---

## Applying Fixes with apply-hardening.sh

After reviewing your audit results, run the companion script to automatically apply the most
common hardening remediations:

```bash
sudo bash apply-hardening.sh
```

The script works through **4 sections** in order:

| Step | What It Does |
|------|-------------|
| **1/4 — Kernel sysctl** | Writes `/etc/sysctl.d/99-hardening.conf` with ~15 hardened kernel parameters (ASLR, ptrace scope, SYN cookies, ICMP redirect blocking, martian logging, and more) and applies them live via `sysctl --system` — no reboot needed |
| **2/4 — SSH Hardening** | Sets `PermitRootLogin no`, `MaxAuthTries 3`, and `X11Forwarding no` in `sshd_config`; validates the config with `sshd -t` before restarting — restores the backup automatically if validation fails |
| **3/4 — Password Policy** | Sets `minlen = 14` in `/etc/security/pwquality.conf` and `deny = 5` (lockout after 5 failed attempts) in `/etc/security/faillock.conf` |
| **4/4 — Unnecessary Services** | Disables and stops `cups`, `cups-browsed`, `avahi-daemon`, and `bluetooth` if they are running or enabled |

**Safety guarantees:**

- **Idempotent** — safe to run more than once; existing values are updated, not duplicated
- **Backups first** — every config file is backed up with a timestamp before it is touched (e.g. `sshd_config.bak.20260518143201`)
- **Validation before restart** — SSH config is tested with `sshd -t`; if it fails the backup is restored and the daemon is not restarted
- **PasswordAuthentication left unchanged** — disabling password auth before SSH keys are in place would lock you out; the script warns you to handle this step manually

After `apply-hardening.sh` completes, re-run the audit to measure your improvement:

```bash
sudo bash vulnScan.sh
```

---

## Example Output

```
╔══════════════════════════════════════════════════════╗
║          vulnScan — System Security Audit            ║
║          Fedora 44 | 2026-05-16 | root               ║
╚══════════════════════════════════════════════════════╝

─── [ 1/8 ] System Hardening ───────────────────────────

  [PASS] ASLR is enabled (kernel.randomize_va_space = 2)
  [PASS] Core dumps are restricted
  [WARN] kernel.dmesg_restrict is not set
         [REC] Add 'kernel.dmesg_restrict = 1' to /etc/sysctl.d/99-hardening.conf
  [FAIL] Kernel pointer leaks are exposed (kernel.kptr_restrict = 0)
         [REC] Set 'kernel.kptr_restrict = 2' to prevent KASLR bypass

Press [Enter] to continue...
```

*(Actual terminal output includes full ANSI color.)*

---

## Security Guarantees

These guarantees apply to **`vulnScan.sh`** (the audit script):

- **No writes:** The script never creates, modifies, or deletes any file on your system
- **No network calls:** vulnScan is entirely offline — no telemetry, no update checks
- **No `eval`:** The script avoids `eval` and other injection-prone constructs
- **ShellCheck clean:** Linted with ShellCheck before every release

**`apply-hardening.sh`** intentionally does write files and restart services — that is its
purpose. Review the script before running it on any system you care about.

---

## For Security Learners

Each check in the script includes a comment explaining **why** it matters, not just **what** it checks.
Reading through the source is itself a learning exercise.

For deeper background, these references align with vulnScan's check categories:

- [CIS Red Hat Enterprise Linux Benchmark](https://www.cisecurity.org/benchmark/red_hat_linux)
- [NIST SP 800-123: Guide to General Server Security](https://csrc.nist.gov/publications/detail/sp/800-123/final)
- [Arch Linux Security wiki](https://wiki.archlinux.org/title/Security) (distro-agnostic concepts)
- [Linux Hardening Guide — madaidans-insecurities.github.io](https://madaidans-insecurities.github.io/guides/linux-hardening.html)

---

## For Sysadmins

- vulnScan is safe to run on production systems — it is strictly read-only
- Schedule it via `cron` or `systemd timer` to get periodic snapshots (pipe to a file with `--no-color`, coming soon)
- The script exits with code `0` on success, `1` on critical internal error, `2` if required tools are missing
- Planned: `--json` output for integration with monitoring dashboards and SIEM ingestion

---

## Contributing

Contributions welcome. Please:

1. Fork the repo and create a branch (`git checkout -b feature/check-xyz`)
2. Run `shellcheck vulnScan.sh` — zero warnings required
3. Follow the comment style in the existing code (every check explains its rationale)
4. Do not include any real system output, hostnames, IPs, or usernames in PRs
5. Open a PR with a clear description of what the new check tests and why it matters

---

## Roadmap

- [x] `apply-hardening.sh` — companion script to apply common remediations automatically
- [ ] Debian / Ubuntu distro family support
- [ ] `--json` output flag
- [ ] HTML report generation
- [ ] GitHub Actions CI (ShellCheck + `bats` unit tests)
- [ ] `vulnScan.conf` config file to toggle check categories
- [ ] Modular `lib/*.sh` architecture for large-scale contributors

---

## License

[MIT License](LICENSE) — free to use, modify, and distribute with attribution.

---

## Disclaimer

vulnScan is an **informational tool**. Its findings are not a substitute for a professional
security assessment. Running it on systems you do not own or have explicit authorization to
audit may violate computer fraud laws. Use responsibly.
