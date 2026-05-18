#!/usr/bin/env bash
# ==============================================================================
# vulnScan.sh — Interactive Linux Security Audit Tool
#
# Version  : 0.2.0
# License  : MIT
# Platform : Fedora / RHEL / CentOS (bash 5+)
# Project  : https://github.com/cainepavl/vulnScan
# ==============================================================================
#
# WHAT IT DOES:
#   Walks through 8 security check categories sequentially, displaying
#   color-coded PASS / WARN / FAIL results for each finding, printing
#   inline recommendations for every WARN and FAIL, and concluding with
#   a numeric risk score (0–100) and letter grade.
#
# WHAT IT DOES NOT DO:
#   Modify any file, change any setting, restart any service, or make any
#   network call. This script is strictly read-only and safe on production.
#
# USAGE:
#   sudo ./vulnScan.sh          # Recommended — full check suite
#   ./vulnScan.sh               # Limited checks (skips root-only reads)
#
# REQUIREMENTS:
#   bash 5+, Fedora / RHEL / CentOS, root or sudo for most checks
#
# ==============================================================================

# nounset: treat unset variables as errors (catches typos)
# We intentionally omit -e (errexit) and -o pipefail because many security
# audit commands legitimately return non-zero (e.g. dnf check-update = 100
# when updates exist, grep = 1 when no match). Each check handles its own
# return code explicitly.
set -u

# ==============================================================================
# ── SECTION 1: GLOBAL CONSTANTS & COLOR CODES ─────────────────────────────────
# ==============================================================================

# ANSI escape codes. All bold variants for readability on dark/light terminals.
# See CLAUDE.md §Color Scheme for the full usage table.
readonly RED='\033[1;31m'      # FAIL findings
readonly YELLOW='\033[1;33m'   # WARN findings
readonly GREEN='\033[1;32m'    # PASS findings
readonly CYAN='\033[1;36m'     # Section headers / box borders
readonly BLUE='\033[1;34m'     # Informational labels
readonly MAGENTA='\033[1;35m'  # Inline recommendations [REC]
readonly WHITE='\033[1;37m'    # General text / prompts
readonly DIM='\033[2m'         # Dimmed text (sub-labels, separators)
readonly RESET='\033[0m'       # Reset all attributes

readonly VERSION="0.2.0"
readonly SCRIPT_NAME="vulnScan"

# Score tracking — updated by the print_pass / print_warn / print_fail helpers.
# Each check contributes to these globals; summary reads them at the end.
PASS_COUNT=0
WARN_COUNT=0
FAIL_COUNT=0
RISK_POINTS=0       # Accumulated: WARN += 1, FAIL += 3
MAX_RISK_POINTS=0   # Max possible if every check were a FAIL (each check = 3 pts headroom)
TOTAL_CHECKS=0

# ==============================================================================
# ── SECTION 2: UTILITY FUNCTIONS ──────────────────────────────────────────────
# ==============================================================================

# ------------------------------------------------------------------------------
# print_banner — Draw the tool's intro banner with OS / user / date context.
# ------------------------------------------------------------------------------
print_banner() {
    local date_str user_str distro
    date_str=$(date '+%Y-%m-%d %H:%M')
    user_str=$(whoami)
    distro="Unknown"
    if [[ -f /etc/os-release ]]; then
        # Extract the human-readable distro name from os-release
        distro=$(grep -oP '(?<=^PRETTY_NAME=").*(?=")' /etc/os-release 2>/dev/null \
                 || grep -oP '(?<=^PRETTY_NAME=)[^"]*' /etc/os-release 2>/dev/null \
                 || echo "Unknown")
    fi

    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${CYAN}║${WHITE}       ${SCRIPT_NAME} v${VERSION} — Linux Security Audit Tool       ${CYAN}║${RESET}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════════════╣${RESET}"
    printf "${CYAN}║${DIM}  OS   : %-52s${CYAN}║${RESET}\n" "${distro}"
    printf "${CYAN}║${DIM}  User : %-20s Date : %-28s${CYAN}║${RESET}\n" "${user_str}" "${date_str}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════════════╣${RESET}"
    echo -e "${CYAN}║${DIM}  Read-only — no files modified, no settings changed.         ${CYAN}║${RESET}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${RESET}"
    echo ""
}

# ------------------------------------------------------------------------------
# print_header — Full-width section banner between each module.
# Args: $1 = "N/8" (progress), $2 = section name
# ------------------------------------------------------------------------------
print_header() {
    local num="$1"
    local name="$2"
    local sep
    sep=$(printf '─%.0s' {1..62})
    echo ""
    echo -e "${CYAN}${sep}${RESET}"
    echo -e "${CYAN}  [ ${num} ]  ${name}${RESET}"
    echo -e "${CYAN}${sep}${RESET}"
    echo ""
}

# ------------------------------------------------------------------------------
# Scoring helpers — call exactly one per discrete check result.
# They print the finding and update the global counters.
# Args: $1 = finding text
# ------------------------------------------------------------------------------
print_pass() {
    echo -e "  ${GREEN}[PASS]${RESET} $1"
    PASS_COUNT=$(( PASS_COUNT + 1 ))
    TOTAL_CHECKS=$(( TOTAL_CHECKS + 1 ))
    MAX_RISK_POINTS=$(( MAX_RISK_POINTS + 3 ))   # Headroom: this could have been a FAIL
}

print_warn() {
    echo -e "  ${YELLOW}[WARN]${RESET} $1"
    WARN_COUNT=$(( WARN_COUNT + 1 ))
    RISK_POINTS=$(( RISK_POINTS + 1 ))
    TOTAL_CHECKS=$(( TOTAL_CHECKS + 1 ))
    MAX_RISK_POINTS=$(( MAX_RISK_POINTS + 3 ))
}

print_fail() {
    echo -e "  ${RED}[FAIL]${RESET} $1"
    FAIL_COUNT=$(( FAIL_COUNT + 1 ))
    RISK_POINTS=$(( RISK_POINTS + 3 ))
    TOTAL_CHECKS=$(( TOTAL_CHECKS + 1 ))
    MAX_RISK_POINTS=$(( MAX_RISK_POINTS + 3 ))
}

# Inline recommendation — always follows a print_warn or print_fail call
print_rec()  { echo -e "         ${MAGENTA}[REC]${RESET}  $1"; }

# Informational output — no score impact
print_info() { echo -e "  ${BLUE}[INFO]${RESET} $1"; }

# Skipped check — tool unavailable or insufficient privilege
print_skip() { echo -e "  ${DIM}[SKIP]${RESET}  $1"; }

# ------------------------------------------------------------------------------
# pause — Wait for Enter before moving to the next section.
# Gives the user time to read findings without scrolling past them.
# ------------------------------------------------------------------------------
pause() {
    echo ""
    echo -e "  ${BLUE}Press [Enter] to continue...${RESET}"
    read -r _pause_dummy
}

# ------------------------------------------------------------------------------
# sysctl_check — Read a kernel parameter and compare to an expected value.
# Reduces boilerplate for the many sysctl checks in module 1.
# Args: $1=key  $2=expected  $3=pass_msg  $4=fail_msg  $5=rec_msg
# ------------------------------------------------------------------------------
sysctl_check() {
    local key="$1" expected="$2" pass_msg="$3" fail_msg="$4" rec_msg="$5"
    local actual
    actual=$(sysctl -n "$key" 2>/dev/null || true)

    if [[ -z "$actual" ]]; then
        print_warn "Cannot read ${key} — key not present in this kernel build"
        print_rec  "$rec_msg"
        return
    fi

    if [[ "$actual" == "$expected" ]]; then
        print_pass "${pass_msg} (${key} = ${actual})"
    else
        print_fail "${fail_msg} (${key} = ${actual}, expected ${expected})"
        print_rec  "$rec_msg"
    fi
}

# ==============================================================================
# ── SECTION 3: PRIVILEGE CHECK ────────────────────────────────────────────────
# ==============================================================================

# ------------------------------------------------------------------------------
# check_privileges — Verify root. If not root, warn and offer sudo re-launch.
# We do not force exit — the script degrades gracefully, printing [SKIP] for
# any check that truly requires elevated access.
# ------------------------------------------------------------------------------
check_privileges() {
    if [[ "$EUID" -eq 0 ]]; then
        print_info "Running as root — full check suite available."
        return
    fi

    echo ""
    echo -e "${YELLOW}┌─────────────────────────────────────────────────────────────┐${RESET}"
    echo -e "${YELLOW}│  WARNING: Not running as root                               │${RESET}"
    echo -e "${YELLOW}│                                                             │${RESET}"
    echo -e "${YELLOW}│  Checks that will be skipped without root:                  │${RESET}"
    echo -e "${YELLOW}│    • /etc/shadow and PAM inspection                         │${RESET}"
    echo -e "${YELLOW}│    • auditd rule enumeration (auditctl -l)                  │${RESET}"
    echo -e "${YELLOW}│    • Full filesystem SUID / world-writable scan             │${RESET}"
    echo -e "${YELLOW}│    • Some sysctl values may be unreadable                   │${RESET}"
    echo -e "${YELLOW}└─────────────────────────────────────────────────────────────┘${RESET}"
    echo ""
    echo -ne "  Re-run now with sudo? [y/N]: "
    read -r _ans
    if [[ "${_ans}" =~ ^[Yy]$ ]]; then
        exec sudo bash "$0"
    fi
    echo ""
    print_info "Continuing in limited (non-root) mode..."
}

# ==============================================================================
# ── SECTION 4: CHECK MODULES ──────────────────────────────────────────────────
# ==============================================================================

# ==============================================================================
# MODULE 1 — SYSTEM HARDENING
# ==============================================================================
# Reads kernel parameters via sysctl. These settings control low-level security
# behaviours: address space randomization, memory protections, network stack
# hardening, and process isolation. Many are off by default on a stock install
# and must be explicitly enabled in /etc/sysctl.d/ config files.
# Reference: CIS RHEL Benchmark §3.x, NIST SP 800-123 §4.2

check_system_hardening() {
    print_header "1/8" "System Hardening — Kernel Parameters"

    # ASLR (Address Space Layout Randomization)
    # Randomises where programs load into memory, making it much harder for an
    # attacker to predict code/data locations and exploit memory corruption bugs.
    # 2 = full randomisation (preferred). 1 = partial. 0 = disabled.
    sysctl_check "kernel.randomize_va_space" "2" \
        "ASLR is fully enabled" \
        "ASLR is not fully enabled — memory layout is predictable" \
        "Set 'kernel.randomize_va_space = 2' in /etc/sysctl.d/99-hardening.conf"

    # dmesg restriction
    # The kernel ring buffer can leak kernel addresses and hardware detail that
    # helps bypass KASLR. Restricting it to root prevents info-leakage to users.
    sysctl_check "kernel.dmesg_restrict" "1" \
        "dmesg output is restricted to root" \
        "dmesg is world-readable — can leak kernel addresses" \
        "Set 'kernel.dmesg_restrict = 1' in /etc/sysctl.d/99-hardening.conf"

    # Kernel pointer hiding
    # Kernel pointers exposed in /proc let attackers compute KASLR slide.
    # 2 = hide from everyone including root. 1 = hide from non-root only.
    sysctl_check "kernel.kptr_restrict" "2" \
        "Kernel pointers hidden from all users" \
        "Kernel pointers are exposed — KASLR bypass risk" \
        "Set 'kernel.kptr_restrict = 2' in /etc/sysctl.d/99-hardening.conf"

    # SUID core dump restriction
    # When a SUID binary crashes, its dump may contain privileged memory contents.
    # 0 = no core dumps from SUID/privileged processes.
    sysctl_check "fs.suid_dumpable" "0" \
        "SUID core dumps are disabled" \
        "SUID processes can produce core dumps — risk of privileged data exposure" \
        "Set 'fs.suid_dumpable = 0' in /etc/sysctl.d/99-hardening.conf"

    # Yama ptrace scope
    # ptrace lets one process read another's memory. Scope 1 restricts it to
    # parent→child relationships only, blocking process injection attacks where
    # any same-uid process could inspect any other.
    sysctl_check "kernel.yama.ptrace_scope" "1" \
        "ptrace restricted to parent/child relationships (Yama)" \
        "ptrace scope is permissive — any process can inspect same-uid peers" \
        "Set 'kernel.yama.ptrace_scope = 1' in /etc/sysctl.d/99-hardening.conf"

    # TCP SYN cookies
    # Defends against SYN-flood DoS attacks by not allocating connection state
    # until the three-way handshake completes successfully.
    sysctl_check "net.ipv4.tcp_syncookies" "1" \
        "TCP SYN cookie flood protection is enabled" \
        "TCP SYN cookies are disabled — vulnerable to SYN-flood DoS" \
        "Set 'net.ipv4.tcp_syncookies = 1' in /etc/sysctl.d/99-hardening.conf"

    # Source routing
    # Lets the sender specify its own route, bypassing network security controls.
    # No legitimate use on modern networks — should always be disabled.
    sysctl_check "net.ipv4.conf.all.accept_source_route" "0" \
        "IPv4 source routing disabled" \
        "IPv4 source routing enabled — packets can bypass routing policy" \
        "Set 'net.ipv4.conf.all.accept_source_route = 0' in /etc/sysctl.d/99-hardening.conf"

    sysctl_check "net.ipv6.conf.all.accept_source_route" "0" \
        "IPv6 source routing disabled" \
        "IPv6 source routing is enabled" \
        "Set 'net.ipv6.conf.all.accept_source_route = 0' in /etc/sysctl.d/99-hardening.conf"

    # ICMP redirect acceptance
    # Redirects can silently alter the system's routing table — a classic
    # man-in-the-middle vector. Servers should never accept or send them.
    sysctl_check "net.ipv4.conf.all.accept_redirects" "0" \
        "IPv4 ICMP redirects rejected" \
        "IPv4 ICMP redirects accepted — routing table can be manipulated" \
        "Set 'net.ipv4.conf.all.accept_redirects = 0' in /etc/sysctl.d/99-hardening.conf"

    sysctl_check "net.ipv4.conf.all.send_redirects" "0" \
        "IPv4 ICMP redirect sending disabled" \
        "This host can send ICMP redirects to manipulate peer routing" \
        "Set 'net.ipv4.conf.all.send_redirects = 0' in /etc/sysctl.d/99-hardening.conf"

    sysctl_check "net.ipv6.conf.all.accept_redirects" "0" \
        "IPv6 ICMP redirects rejected" \
        "IPv6 ICMP redirects are accepted" \
        "Set 'net.ipv6.conf.all.accept_redirects = 0' in /etc/sysctl.d/99-hardening.conf"

    # Reverse path filtering
    # Validates that packets arrive on the interface they would logically use.
    # Prevents IP spoofing. 1 = strict, 2 = loose (both block spoofing).
    local rp
    rp=$(sysctl -n net.ipv4.conf.all.rp_filter 2>/dev/null || echo "0")
    if [[ "$rp" =~ ^[0-9]+$ ]] && [[ "$rp" -ge 1 ]]; then
        print_pass "Reverse path filtering enabled (rp_filter = ${rp})"
    else
        print_fail "Reverse path filtering disabled — IP spoofing is possible"
        print_rec  "Set 'net.ipv4.conf.all.rp_filter = 1' in /etc/sysctl.d/99-hardening.conf"
    fi

    # Martian packet logging
    # Logs packets with impossible source addresses (e.g. loopback on eth0).
    # These indicate misconfiguration or active spoofing attacks.
    sysctl_check "net.ipv4.conf.all.log_martians" "1" \
        "Martian (spoofed source) packets are logged" \
        "Martian packet logging is disabled — spoofed traffic goes unnoticed" \
        "Set 'net.ipv4.conf.all.log_martians = 1' in /etc/sysctl.d/99-hardening.conf"

    # Broadcast ICMP (Smurf attack amplification)
    # Responding to broadcast pings can amplify DoS traffic toward a victim.
    sysctl_check "net.ipv4.icmp_echo_ignore_broadcasts" "1" \
        "Broadcast ICMP echo requests are ignored" \
        "Host responds to broadcast pings — Smurf DoS amplification risk" \
        "Set 'net.ipv4.icmp_echo_ignore_broadcasts = 1' in /etc/sysctl.d/99-hardening.conf"

    # Bogus ICMP error responses
    sysctl_check "net.ipv4.icmp_ignore_bogus_error_responses" "1" \
        "Bogus ICMP error responses are ignored" \
        "Host processes malformed ICMP error responses" \
        "Set 'net.ipv4.icmp_ignore_bogus_error_responses = 1' in /etc/sysctl.d/99-hardening.conf"

    # CPU NX/XD (No-Execute) bit
    # Hardware-level protection that marks data pages non-executable, preventing
    # shellcode planted in the stack or heap from running. Verify it's exposed.
    if grep -qE 'nx|xd' /proc/cpuinfo 2>/dev/null; then
        print_pass "CPU NX/XD (No-Execute) bit is present and visible"
    else
        print_warn "NX/XD bit not detected in /proc/cpuinfo"
        print_rec  "Verify that virtualisation settings expose the NX bit to this guest"
    fi

    # Unprivileged user namespace restriction
    # Unprivileged user namespaces have been the root cause of dozens of kernel
    # privilege-escalation CVEs. Fedora exposes user.max_user_namespaces to limit them.
    local userns
    userns=$(sysctl -n user.max_user_namespaces 2>/dev/null || echo "unknown")
    if [[ "$userns" == "0" ]]; then
        print_pass "Unprivileged user namespaces are disabled"
    elif [[ "$userns" == "unknown" ]]; then
        print_skip "user.max_user_namespaces not readable on this kernel"
    else
        print_warn "Unprivileged user namespaces are enabled (max: ${userns})"
        print_rec  "If containers are not in use: sysctl -w user.max_user_namespaces=0"
    fi
}

# ==============================================================================
# MODULE 2 — USER & AUTHENTICATION SECURITY
# ==============================================================================
# Checks account hygiene, password policy, PAM hardening, and SSH config.
# Weak authentication is the #1 vector for initial access. These checks verify
# that password complexity, lockout policies, root restrictions, and SSH
# key-only login are properly configured.
# Reference: CIS RHEL Benchmark §5.x, NIST SP 800-123 §4.3

check_user_auth() {
    print_header "2/8" "User & Authentication Security"

    # UID-0 accounts (root-equivalent)
    # Any account with UID 0 has full root capability regardless of its name.
    # There must be exactly one: root itself. Extra UID-0 accounts can indicate
    # a backdoor or prior compromise and should be investigated immediately.
    local uid0_list
    uid0_list=$(awk -F: '$3 == 0 { print $1 }' /etc/passwd 2>/dev/null || true)
    local uid0_count
    uid0_count=$(echo "${uid0_list}" | grep -c '[^[:space:]]' || true)

    if [[ "${uid0_count}" -eq 1 ]]; then
        print_pass "Only root has UID 0"
    else
        print_fail "Multiple UID-0 accounts detected: ${uid0_list}"
        print_rec  "Investigate and remove any unauthorised UID-0 accounts immediately"
    fi

    # Empty password accounts
    # An account with an empty password field in /etc/shadow can be logged
    # into without any credential. This should never occur on any live system.
    if [[ "$EUID" -eq 0 ]]; then
        local empty_pw_users
        empty_pw_users=$(awk -F: '($2 == "" || $2 == " ") { print $1 }' /etc/shadow 2>/dev/null || true)
        if [[ -z "${empty_pw_users}" ]]; then
            print_pass "No accounts with empty passwords found"
        else
            print_fail "Accounts with empty passwords: ${empty_pw_users}"
            print_rec  "Lock each account: passwd -l <username>"
        fi
    else
        print_skip "Empty-password check skipped (requires root to read /etc/shadow)"
    fi

    # System accounts with login shells
    # Service accounts (UID < 1000, excluding root) should have /sbin/nologin
    # or /bin/false as their shell. A login shell on a service account is a
    # potential lateral-movement pivot if the account is ever compromised.
    local bad_svc_accts
    bad_svc_accts=$(awk -F: '$3 > 0 && $3 < 1000 && $7 !~ /nologin|false|sync|shutdown|halt/ \
                   { print $1 "  (shell: " $7 ")" }' /etc/passwd 2>/dev/null || true)
    if [[ -z "${bad_svc_accts}" ]]; then
        print_pass "All system/service accounts have non-login shells"
    else
        print_warn "Service accounts with interactive shells detected:"
        echo "${bad_svc_accts}" | while IFS= read -r line; do
            echo -e "         ${DIM}${line}${RESET}"
        done
        print_rec  "Set shell to /sbin/nologin: usermod -s /sbin/nologin <user>"
    fi

    # /etc/passwd permissions
    # Must be world-readable (for user lookups by all programs) but not writable
    # by group or other. Mode 644 is correct. A writable passwd file = instant
    # privilege escalation (attacker can insert a UID-0 line).
    local passwd_perms
    passwd_perms=$(stat -c '%a' /etc/passwd 2>/dev/null || echo "unknown")
    if [[ "${passwd_perms}" == "644" ]]; then
        print_pass "/etc/passwd permissions are 644 (correct)"
    else
        print_fail "/etc/passwd permissions are ${passwd_perms} (expected 644)"
        print_rec  "chmod 644 /etc/passwd"
    fi

    # /etc/shadow permissions
    # Contains hashed passwords. Must be readable only by root (000 or 640).
    # Any broader permissions expose hashes to offline cracking tools.
    if [[ "$EUID" -eq 0 ]]; then
        local shadow_perms
        shadow_perms=$(stat -c '%a' /etc/shadow 2>/dev/null || echo "unknown")
        if [[ "${shadow_perms}" =~ ^(000|400|600|640)$ ]]; then
            print_pass "/etc/shadow permissions are ${shadow_perms} (restrictive)"
        else
            print_fail "/etc/shadow permissions are ${shadow_perms} — too permissive"
            print_rec  "chmod 000 /etc/shadow  (or 640 if the shadow group is required)"
        fi
    else
        print_skip "/etc/shadow permission check skipped (requires root)"
    fi

    # Password minimum length via pam_pwquality
    # pam_pwquality is the standard password-quality enforcer on Fedora/RHEL.
    # minlen should be at least 12; 14+ is recommended by NIST SP 800-63B.
    if [[ -f /etc/security/pwquality.conf ]]; then
        local minlen
        minlen=$(grep -oP '^\s*minlen\s*=\s*\K\d+' /etc/security/pwquality.conf 2>/dev/null || echo "")
        if [[ -z "${minlen}" ]]; then
            print_warn "minlen not configured in pwquality.conf (system default may be 8)"
            print_rec  "Set 'minlen = 14' in /etc/security/pwquality.conf"
        elif [[ "${minlen}" -ge 12 ]]; then
            print_pass "Password minimum length is ${minlen} characters (≥ 12)"
        else
            print_warn "Password minimum length is only ${minlen} — recommend at least 12"
            print_rec  "Set 'minlen = 14' in /etc/security/pwquality.conf"
        fi
    else
        print_warn "/etc/security/pwquality.conf not found — password policy may be unenforced"
        print_rec  "Install and configure pam_pwquality: dnf install libpwquality"
    fi

    # Account lockout via pam_faillock
    # pam_faillock (Fedora default) temporarily locks an account after N failed
    # logins. Without this, brute-force password attacks run unchecked.
    if [[ -f /etc/security/faillock.conf ]]; then
        local deny_val
        deny_val=$(grep -oP '^\s*deny\s*=\s*\K\d+' /etc/security/faillock.conf 2>/dev/null || echo "")
        if [[ -z "${deny_val}" ]]; then
            print_warn "faillock.conf exists but 'deny' threshold is not explicitly set"
            print_rec  "Set 'deny = 5' in /etc/security/faillock.conf"
        elif [[ "${deny_val}" -le 5 ]]; then
            print_pass "Account lockout triggers after ${deny_val} failed attempts"
        else
            print_warn "Lockout threshold is ${deny_val} — consider ≤ 5 for stronger protection"
            print_rec  "Set 'deny = 5' in /etc/security/faillock.conf"
        fi
    else
        print_warn "/etc/security/faillock.conf not found — account lockout may not be active"
        print_rec  "Ensure pam_faillock is configured in /etc/pam.d/system-auth"
    fi

    # /etc/sudoers permissions
    # sudoers must be 440 (read-only, root-owned). A writable sudoers file lets
    # any user grant themselves root access — a one-step privilege escalation.
    local sudoers_perms
    sudoers_perms=$(stat -c '%a' /etc/sudoers 2>/dev/null || echo "unknown")
    if [[ "${sudoers_perms}" =~ ^(440|400)$ ]]; then
        print_pass "/etc/sudoers permissions are ${sudoers_perms} (correct)"
    else
        print_fail "/etc/sudoers permissions are ${sudoers_perms} (expected 440)"
        print_rec  "chmod 440 /etc/sudoers"
    fi

    # NOPASSWD entries in sudoers
    # NOPASSWD allows running sudo commands without a password. If an account
    # with NOPASSWD is compromised, the attacker gains instant root access.
    if [[ "$EUID" -eq 0 ]]; then
        local nopasswd_lines
        nopasswd_lines=$(grep -rh 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null \
                         | grep -v '^\s*#' || true)
        if [[ -z "${nopasswd_lines}" ]]; then
            print_pass "No NOPASSWD entries in sudoers"
        else
            print_warn "NOPASSWD sudo entries found — review carefully:"
            echo "${nopasswd_lines}" | while IFS= read -r line; do
                echo -e "         ${DIM}${line}${RESET}"
            done
            print_rec  "Remove any NOPASSWD grants that are not absolutely required"
        fi
    fi

    # SSH daemon hardening
    # SSH is the primary remote-access vector. Each setting below closes a specific
    # attack surface. We use 'sshd -T' (print effective config) where available,
    # falling back to grepping sshd_config directly.
    local sshd_cfg="/etc/ssh/sshd_config"
    if [[ ! -f "${sshd_cfg}" ]]; then
        print_info "sshd_config not found — SSH server does not appear to be installed"
    else
        # sshd_config file permissions — should be 600 (root read/write only)
        local sshd_perms
        sshd_perms=$(stat -c '%a' "${sshd_cfg}" 2>/dev/null || echo "unknown")
        if [[ "${sshd_perms}" =~ ^(600|640)$ ]]; then
            print_pass "sshd_config permissions are ${sshd_perms}"
        else
            print_warn "sshd_config permissions are ${sshd_perms} (expected 600)"
            print_rec  "chmod 600 /etc/ssh/sshd_config"
        fi

        # Helper: resolve a directive from effective sshd config or raw file
        sshd_val() {
            local directive="$1"
            local result
            result=$(sshd -T 2>/dev/null | grep -i "^${directive} " | awk '{print $2}' || true)
            if [[ -z "${result}" ]]; then
                result=$(grep -i "^${directive}[[:space:]]" "${sshd_cfg}" 2>/dev/null \
                         | awk '{print $2}' | tail -1 || true)
            fi
            echo "${result:-unknown}"
        }

        # PermitRootLogin — direct root login exposes a known target username
        # to brute-force and eliminates the sudo audit trail.
        local permit_root
        permit_root=$(sshd_val "PermitRootLogin")
        if [[ "${permit_root,,}" == "no" ]]; then
            print_pass "SSH PermitRootLogin is disabled"
        elif [[ "${permit_root}" == "unknown" ]]; then
            # sshd -T needs root; value absent from config means OpenSSH default applies.
            # Modern OpenSSH default is 'prohibit-password', not 'no' — worth flagging.
            print_warn "SSH PermitRootLogin not explicitly set (run as root for full check)"
            print_rec  "Set 'PermitRootLogin no' in /etc/ssh/sshd_config"
        else
            print_fail "SSH PermitRootLogin is '${permit_root}' — root can log in directly"
            print_rec  "Set 'PermitRootLogin no' in /etc/ssh/sshd_config"
        fi

        # PasswordAuthentication — SSH keys provide far stronger authentication
        # than passwords, which are susceptible to brute force and phishing.
        local passwd_auth
        passwd_auth=$(sshd_val "PasswordAuthentication")
        if [[ "${passwd_auth,,}" == "no" ]]; then
            print_pass "SSH PasswordAuthentication is disabled (key-only)"
        else
            print_warn "SSH PasswordAuthentication is enabled — passwords accepted"
            print_rec  "Set 'PasswordAuthentication no' after deploying SSH keys for all users"
        fi

        # PermitEmptyPasswords — should always be no; belt-and-suspenders check
        local empty_pw_ssh
        empty_pw_ssh=$(sshd_val "PermitEmptyPasswords")
        if [[ "${empty_pw_ssh,,}" == "no" || "${empty_pw_ssh}" == "unknown" ]]; then
            print_pass "SSH PermitEmptyPasswords is disabled"
        else
            print_fail "SSH PermitEmptyPasswords is enabled — blank passwords accepted"
            print_rec  "Set 'PermitEmptyPasswords no' in /etc/ssh/sshd_config"
        fi

        # MaxAuthTries — limits attempts before the connection is dropped,
        # slowing brute-force attacks. Default is 6; 3 is recommended.
        local max_tries
        max_tries=$(sshd_val "MaxAuthTries")
        if [[ "${max_tries}" =~ ^[0-9]+$ ]] && [[ "${max_tries}" -le 4 ]]; then
            print_pass "SSH MaxAuthTries is ${max_tries} (≤ 4)"
        elif [[ "${max_tries}" == "unknown" ]]; then
            print_warn "SSH MaxAuthTries not explicitly set (default is 6)"
            print_rec  "Set 'MaxAuthTries 3' in /etc/ssh/sshd_config"
        else
            print_warn "SSH MaxAuthTries is ${max_tries} — more brute-force headroom than needed"
            print_rec  "Set 'MaxAuthTries 3' in /etc/ssh/sshd_config"
        fi

        # X11Forwarding — tunnels the X display over SSH, exposing the local
        # GUI environment to the remote host. Rarely needed on servers.
        local x11_fwd
        x11_fwd=$(sshd_val "X11Forwarding")
        if [[ "${x11_fwd,,}" == "no" ]]; then
            print_pass "SSH X11Forwarding is disabled"
        else
            print_warn "SSH X11Forwarding is enabled — remote X11 access permitted"
            print_rec  "Set 'X11Forwarding no' unless remote GUI access is required"
        fi

        # Protocol version — SSHv1 is cryptographically broken (BEAST, etc.)
        # Modern OpenSSH defaults to v2 only but check for any explicit v1 lines.
        if grep -qi '^\s*Protocol.*1' "${sshd_cfg}" 2>/dev/null; then
            print_fail "SSHv1 is explicitly enabled in sshd_config"
            print_rec  "Remove the 'Protocol' line or set 'Protocol 2' — SSHv1 is broken"
        else
            print_pass "SSHv1 is not enabled (SSHv2 only)"
        fi
        unset -f sshd_val
    fi
}

# ==============================================================================
# MODULE 3 — NETWORK & FIREWALL
# ==============================================================================
# Checks the host's network exposure: firewall state, listening ports, and
# the presence of dangerous legacy services. An attacker can only exploit what
# is reachable — minimising the network surface is a primary hardening goal.
# Reference: CIS RHEL Benchmark §3.4, NIST SP 800-123 §4.4

check_network_firewall() {
    print_header "3/8" "Network & Firewall"

    # firewalld — Fedora/RHEL's primary firewall manager
    # A running firewall is the single most impactful network hardening measure.
    if command -v firewall-cmd &>/dev/null; then
        if systemctl is-active --quiet firewalld 2>/dev/null; then
            print_pass "firewalld is active and running"

            # Default zone — "trusted" means all traffic is accepted; dangerous.
            local def_zone
            def_zone=$(firewall-cmd --get-default-zone 2>/dev/null || echo "unknown")
            if [[ "${def_zone}" == "trusted" ]]; then
                print_fail "firewalld default zone is 'trusted' — all inbound traffic is accepted"
                print_rec  "firewall-cmd --set-default-zone=public --permanent && firewall-cmd --reload"
            else
                print_pass "firewalld default zone is '${def_zone}'"
            fi

            # List currently open services for the user's reference
            local open_svcs
            open_svcs=$(firewall-cmd --list-services 2>/dev/null || echo "")
            if [[ -n "${open_svcs}" ]]; then
                print_info "Services open in default zone: ${open_svcs}"
            fi
        else
            print_fail "firewalld is installed but not running"
            print_rec  "systemctl enable --now firewalld"
        fi
    else
        # Fall back to checking nftables or raw iptables
        if systemctl is-active --quiet nftables 2>/dev/null; then
            print_pass "nftables firewall is active"
        else
            local ipt_rules=0
            if command -v iptables &>/dev/null; then
                ipt_rules=$(iptables -L -n 2>/dev/null | grep -c '^Chain')
            fi
            if [[ "${ipt_rules}" -gt 3 ]]; then
                print_pass "iptables is active with rules loaded"
            else
                print_fail "No active firewall detected (firewalld / nftables / iptables)"
                print_rec  "dnf install firewalld && systemctl enable --now firewalld"
            fi
        fi
    fi

    # Listening ports
    # Services listening on 0.0.0.0 or :: are reachable from the network.
    # We enumerate them and flag well-known dangerous/legacy ports.
    echo ""
    print_info "Listening TCP/UDP ports:"
    if command -v ss &>/dev/null; then
        local dangerous_found=0
        # Associative map: port number → service description
        declare -A RISKY_PORTS=(
            [21]="FTP — plaintext file transfer, no encryption"
            [23]="Telnet — plaintext remote shell"
            [111]="rpcbind — RPC portmapper, often exploited"
            [512]="rexec — legacy remote exec, no encryption"
            [513]="rlogin — legacy remote login, no encryption"
            [514]="rsh — legacy remote shell, unauthenticated"
            [873]="rsync daemon — can expose entire filesystem"
            [2049]="NFS — network file sharing, complex attack surface"
        )

        while IFS= read -r line; do
            echo -e "         ${DIM}${line}${RESET}"
            local port
            port=$(echo "${line}" | grep -oP '(?<=:)\d+(?=\s)' | head -1 || true)
            if [[ -n "${port}" && -v RISKY_PORTS["${port}"] ]]; then
                print_warn "Risky port ${port} is open: ${RISKY_PORTS[${port}]}"
                print_rec  "Disable or firewall port ${port} if this service is not required"
                dangerous_found=1
            fi
        done < <(ss -tlnpu 2>/dev/null | tail -n +2)

        if [[ "${dangerous_found}" -eq 0 ]]; then
            echo ""
            print_pass "No obviously dangerous legacy ports detected in listener list"
        fi
    else
        print_skip "'ss' not available — install iproute2 for port enumeration"
    fi

    # Telnet server — transmits credentials in plaintext; never acceptable
    if rpm -q telnet-server &>/dev/null 2>&1 \
       || systemctl is-enabled --quiet telnet.socket 2>/dev/null; then
        print_fail "Telnet server is installed or enabled"
        print_rec  "dnf remove telnet-server"
    else
        print_pass "Telnet server is not installed"
    fi

    # Network interfaces in promiscuous mode
    # Promiscuous mode captures all packets on the segment, not just those
    # addressed to this host. Normal for packet capture tools; abnormal in
    # production — may indicate a sniffer or a compromised host.
    local promisc
    promisc=$(ip link 2>/dev/null | grep -i 'PROMISC' | awk -F: '{print $2}' | xargs || true)
    if [[ -z "${promisc}" ]]; then
        print_pass "No network interfaces are in promiscuous mode"
    else
        print_fail "Interface(s) in promiscuous mode: ${promisc}"
        print_rec  "Investigate — an active packet sniffer or misconfiguration is suspected"
    fi

    # IPv6 status (informational — not scored)
    local ipv6_dis
    ipv6_dis=$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo "unknown")
    if [[ "${ipv6_dis}" == "1" ]]; then
        print_info "IPv6 is disabled system-wide"
    elif [[ "${ipv6_dis}" == "0" ]]; then
        print_info "IPv6 is enabled — verify firewall rules cover IPv6 interfaces too"
    fi
}

# ==============================================================================
# MODULE 4 — FILE & PERMISSION AUDITING
# ==============================================================================
# Checks for dangerous file permission configurations. SUID/SGID bits on
# unexpected binaries and world-writable files in system directories are
# classic persistence and privilege-escalation vectors. The filesystem scan
# may take a few seconds on large systems.
# Reference: CIS RHEL Benchmark §6.x

check_file_permissions() {
    print_header "4/8" "File & Permission Auditing"

    print_info "Scanning filesystem for permission issues (may take a moment)..."
    echo ""

    # /tmp sticky bit
    # Without the sticky bit (mode 1777), any user can delete or rename other
    # users' files in /tmp — a trivial denial-of-service or race-condition vector.
    local tmp_perms
    tmp_perms=$(stat -c '%a' /tmp 2>/dev/null || echo "unknown")
    if [[ "${tmp_perms}" == "1777" ]]; then
        print_pass "/tmp has sticky bit and correct permissions (1777)"
    else
        print_fail "/tmp permissions are ${tmp_perms} (expected 1777 with sticky bit)"
        print_rec  "chmod 1777 /tmp"
    fi

    # /var/tmp sticky bit — persistent temp dir, same requirements as /tmp
    local vartmp_perms
    vartmp_perms=$(stat -c '%a' /var/tmp 2>/dev/null || echo "unknown")
    if [[ "${vartmp_perms}" == "1777" ]]; then
        print_pass "/var/tmp has sticky bit and correct permissions (1777)"
    else
        print_warn "/var/tmp permissions are ${vartmp_perms} (expected 1777)"
        print_rec  "chmod 1777 /var/tmp"
    fi

    # /root home directory
    # Only root should be able to enter or list the root home directory.
    local root_perms
    root_perms=$(stat -c '%a' /root 2>/dev/null || echo "unknown")
    if [[ "${root_perms}" == "700" ]]; then
        print_pass "/root directory permissions are 700 (root-only access)"
    else
        print_warn "/root directory permissions are ${root_perms} (expected 700)"
        print_rec  "chmod 700 /root"
    fi

    # /etc/crontab permissions
    # A world-writable crontab lets any user schedule arbitrary commands as root.
    if [[ -f /etc/crontab ]]; then
        local crontab_perms
        crontab_perms=$(stat -c '%a' /etc/crontab 2>/dev/null || echo "unknown")
        if [[ "${crontab_perms}" =~ ^(600|640|644)$ ]]; then
            print_pass "/etc/crontab permissions are ${crontab_perms}"
        else
            print_fail "/etc/crontab permissions are ${crontab_perms} — too permissive"
            print_rec  "chmod 600 /etc/crontab"
        fi
    fi

    # SUID binaries
    # SUID causes a binary to run with its owner's privileges (usually root)
    # regardless of who invokes it. Legitimate ones exist (passwd, sudo) but
    # any unexpected SUID binary is a critical finding — easy privilege escalation.
    if [[ "$EUID" -eq 0 ]]; then
        # Common legitimate SUID binaries on Fedora — anything else is suspicious
        local suid_whitelist
        suid_whitelist='/usr/bin/passwd|/usr/bin/sudo|/usr/bin/su|/usr/bin/newgrp'
        suid_whitelist+='|/usr/bin/gpasswd|/usr/bin/chsh|/usr/bin/chfn|/usr/bin/crontab'
        suid_whitelist+='|/usr/bin/mount|/usr/bin/umount|/usr/bin/pkexec|/usr/bin/write'
        suid_whitelist+='|/usr/bin/fusermount3|/usr/bin/ssh-agent'
        suid_whitelist+='|/usr/sbin/unix_chkpwd|/usr/lib/polkit-1/polkit-agent-helper-1'
        suid_whitelist+='|/usr/lib/openssh/ssh-keysign'

        local -a unexpected_suid
        mapfile -t unexpected_suid < <(
            find / -xdev -perm -4000 -type f 2>/dev/null \
            | grep -vE "${suid_whitelist}" || true
        )

        if [[ "${#unexpected_suid[@]}" -eq 0 ]]; then
            print_pass "No unexpected SUID binaries found"
        else
            print_warn "${#unexpected_suid[@]} unexpected SUID binary/binaries found:"
            for f in "${unexpected_suid[@]}"; do
                echo -e "         ${DIM}${f}${RESET}"
            done
            print_rec  "Review each one — remove SUID if not required: chmod u-s <file>"
        fi
    else
        print_skip "Full SUID scan skipped (requires root)"
    fi

    # World-writable files in sensitive system directories
    # A world-writable file in /etc, /usr, or /lib can be modified by any user
    # to inject malicious code or configuration that runs with elevated privilege.
    if [[ "$EUID" -eq 0 ]]; then
        local -a ww_files
        mapfile -t ww_files < <(
            find /etc /bin /sbin /usr /lib /lib64 -xdev -perm -002 -type f 2>/dev/null \
            | head -20 || true
        )
        if [[ "${#ww_files[@]}" -eq 0 ]]; then
            print_pass "No world-writable files found in sensitive system directories"
        else
            print_fail "${#ww_files[@]} world-writable file(s) in sensitive directories:"
            for f in "${ww_files[@]}"; do
                echo -e "         ${DIM}${f}${RESET}"
            done
            print_rec  "chmod o-w <file> for each entry above"
        fi
    else
        print_skip "World-writable file scan skipped (requires root)"
    fi

    # Unowned files (no valid uid/gid in the user database)
    # Leftover from deleted users or copied from another system. Can indicate
    # tampering — e.g. files planted before the owning account was removed.
    if [[ "$EUID" -eq 0 ]]; then
        local unowned_count
        unowned_count=$(find / -xdev \( -nouser -o -nogroup \) -type f 2>/dev/null | wc -l || echo 0)
        if [[ "${unowned_count}" -eq 0 ]]; then
            print_pass "No unowned files found"
        else
            print_warn "${unowned_count} unowned file(s) found (no valid uid/gid)"
            print_rec  "Investigate: find / -xdev \\( -nouser -o -nogroup \\) -type f 2>/dev/null"
        fi
    fi

    # .rhosts / .netrc files
    # .rhosts enables passwordless trust between hosts (rsh/rlogin legacy).
    # .netrc stores plaintext credentials for ftp/curl. Both must not exist.
    local rhost_found
    rhost_found=$(find /home /root -maxdepth 2 \( -name '.rhosts' -o -name '.netrc' \) \
                  2>/dev/null | head -10 || true)
    if [[ -z "${rhost_found}" ]]; then
        print_pass "No .rhosts or .netrc files found"
    else
        print_fail ".rhosts or .netrc files detected:"
        echo "${rhost_found}" | while IFS= read -r f; do
            echo -e "         ${DIM}${f}${RESET}"
        done
        print_rec  "Remove immediately — these files enable passwordless auth or store plaintext credentials"
    fi
}

# ==============================================================================
# MODULE 5 — PACKAGE & SOFTWARE SECURITY
# ==============================================================================
# Checks for pending security patches, installed but dangerous packages, and
# unnecessary services. Unpatched software is among the most reliably exploited
# vulnerability classes in real-world incidents.
# Reference: CIS RHEL Benchmark §1.x, §2.x

check_packages() {
    print_header "5/8" "Package & Software Security"

    # Security-classified updates (dnf updateinfo)
    # dnf distinguishes security updates from general updates. Security updates
    # patch known CVEs — these are the highest-priority patches to apply.
    # Note: dnf check-update exits 100 when updates are available (not an error).
    if command -v dnf &>/dev/null; then
        print_info "Querying for available security updates (may take a moment)..."
        local sec_count
        # -q suppresses the "Last metadata expiration check" noise line on stdout.
        # wc -l always exits 0, so no || echo 0 needed.
        sec_count=$(dnf -q updateinfo list security 2>/dev/null | wc -l)

        if [[ "${sec_count}" -eq 0 ]]; then
            print_pass "No pending security updates"
        elif [[ "${sec_count}" -le 5 ]]; then
            print_warn "${sec_count} security update(s) available"
            print_rec  "sudo dnf update --security"
        else
            print_fail "${sec_count} security updates pending — system is behind on patches"
            print_rec  "sudo dnf update --security  (then review and apply all pending)"
        fi
    else
        print_skip "dnf not found — skipping package update check"
    fi

    # Dangerous / legacy packages
    # These packages are either plaintext-protocol services, unauthenticated
    # remote services, or known-insecure directory services. None should be
    # installed on a hardened modern system.
    local -a DANGEROUS_PKGS=(
        "telnet:Telnet client — plaintext protocol"
        "telnet-server:Telnet server — plaintext remote shell"
        "rsh:RSH client — no encryption or strong auth"
        "rsh-server:RSH server — unauthenticated remote shell"
        "ypbind:NIS client — legacy insecure directory service"
        "ypserv:NIS server — legacy insecure directory service"
        "tftp:TFTP client — no authentication"
        "tftp-server:TFTP server — no authentication"
        "xinetd:xinetd super-server — unnecessary attack surface"
        "talk:Talk daemon — legacy chat service"
        "talk-server:Talk server — legacy chat service"
    )

    local found_dangerous=0
    for pkg_entry in "${DANGEROUS_PKGS[@]}"; do
        local pkg="${pkg_entry%%:*}"
        local desc="${pkg_entry#*:}"
        if rpm -q "${pkg}" &>/dev/null 2>&1; then
            print_fail "Dangerous package installed: ${pkg} — ${desc}"
            print_rec  "sudo dnf remove ${pkg}"
            found_dangerous=1
        fi
    done

    if [[ "${found_dangerous}" -eq 0 ]]; then
        print_pass "No known dangerous or legacy packages are installed"
    fi

    # Unnecessary running services
    # Services that are running but not needed expand the attack surface.
    # Each one listed here is commonly found on default installs but is
    # rarely needed and should be disabled on hardened systems.
    local -a UNNECESSARY_SVCS=(
        "cups:Print spooler — disable if no printing needed"
        "avahi-daemon:mDNS/Zeroconf — disable if no local service discovery needed"
        "bluetooth:Bluetooth stack — disable if no BT hardware in use"
        "rpcbind:RPC portmapper — disable if no NFS/NIS in use"
        "nfs-server:NFS server — disable if not sharing filesystems"
    )

    local found_unnecessary=0
    for svc_entry in "${UNNECESSARY_SVCS[@]}"; do
        local svc="${svc_entry%%:*}"
        local desc="${svc_entry#*:}"
        if systemctl is-active --quiet "${svc}" 2>/dev/null; then
            print_warn "Potentially unnecessary service running: ${svc} — ${desc}"
            print_rec  "sudo systemctl disable --now ${svc}"
            found_unnecessary=1
        fi
    done

    if [[ "${found_unnecessary}" -eq 0 ]]; then
        print_pass "No commonly unnecessary services detected as running"
    fi

    # RPM database integrity — spot-check core packages
    # The RPM database stores checksums for all installed files. If core binaries
    # (bash, coreutils, sudo) fail verification, something has been tampered with.
    if command -v rpm &>/dev/null; then
        local rpm_issues
        # RPM -V output key: each char position is a test. '.' = passed, '?' = test
        # could not run (e.g. permission denied). Only letters (S M 5 D L U G T P)
        # indicate actual failures. Filter out all-dot/all-question lines and noise.
        rpm_issues=$(rpm -V coreutils bash sudo 2>/dev/null \
                     | grep -v '^$' \
                     | grep -v 'Permission denied' \
                     | grep -vE '^[.?]{9}' \
                     || true)
        if [[ -z "${rpm_issues}" ]]; then
            print_pass "Core package integrity check (coreutils, bash, sudo) passed"
        else
            print_fail "RPM verification found discrepancies in core packages:"
            echo "${rpm_issues}" | head -10 | while IFS= read -r line; do
                echo -e "         ${DIM}${line}${RESET}"
            done
            print_rec  "Investigate immediately — this may indicate binary tampering"
        fi
    fi
}

# ==============================================================================
# MODULE 6 — LOGGING & AUDIT
# ==============================================================================
# Verifies that the logging and audit infrastructure is healthy. Without logs
# you have no forensic trail — you cannot detect or investigate a breach.
# auditd captures kernel-level events; journald/rsyslog capture application events.
# Reference: CIS RHEL Benchmark §4.x, NIST SP 800-123 §4.5

check_logging_audit() {
    print_header "6/8" "Logging & Audit"

    # auditd — Linux Audit Daemon
    # auditd records security-relevant system calls and events to
    # /var/log/audit/audit.log. Required by most security frameworks (PCI-DSS,
    # HIPAA, CIS). Without it there is no record of privileged-command use.
    if systemctl is-active --quiet auditd 2>/dev/null; then
        print_pass "auditd is active and running"
    else
        print_fail "auditd is not running"
        print_rec  "sudo systemctl enable --now auditd"
    fi

    # Audit rules
    # Without meaningful rules, auditd runs but captures little of value.
    # We check the count and look for rules covering the most critical events.
    if command -v auditctl &>/dev/null && [[ "$EUID" -eq 0 ]]; then
        local audit_rules
        audit_rules=$(auditctl -l 2>/dev/null || echo "")
        local rule_count
        rule_count=$(echo "${audit_rules}" | grep -c '^-')

        if [[ "${rule_count}" -le 2 ]]; then
            print_warn "auditd has very few rules loaded (${rule_count}) — few events will be captured"
            print_rec  "Install a baseline ruleset from /usr/share/audit/sample-rules/"
        else
            print_pass "auditd has ${rule_count} rule(s) loaded"
        fi

        # Check for passwd/shadow access monitoring
        if echo "${audit_rules}" | grep -q '/etc/passwd\|/etc/shadow'; then
            print_pass "Audit rules monitor changes to /etc/passwd and /etc/shadow"
        else
            print_warn "No audit rules for /etc/passwd or /etc/shadow modifications"
            print_rec  "Add: -w /etc/passwd -p wa -k identity  (and similarly for /etc/shadow)"
        fi

        # Check for privileged command monitoring
        if echo "${audit_rules}" | grep -qE '/usr/bin/sudo|/usr/bin/su'; then
            print_pass "Audit rules monitor sudo and su usage"
        else
            print_warn "No audit rules for sudo or su invocation"
            print_rec  "Add: -w /usr/bin/sudo -p x -k privileged"
        fi
    elif [[ "$EUID" -ne 0 ]]; then
        print_skip "Audit rule inspection skipped (requires root to run auditctl -l)"
    fi

    # journald configuration
    if [[ -f /etc/systemd/journald.conf ]]; then
        # SystemMaxUse — caps disk usage to prevent log-flood from filling /var
        local sys_max
        sys_max=$(grep -oP '^\s*SystemMaxUse=\K.+' /etc/systemd/journald.conf 2>/dev/null || echo "")
        if [[ -n "${sys_max}" ]]; then
            print_pass "journald SystemMaxUse is set to ${sys_max}"
        else
            print_warn "journald SystemMaxUse is not configured — disk could fill under log flood"
            print_rec  "Set 'SystemMaxUse=500M' in /etc/systemd/journald.conf"
        fi

        # Storage=persistent — ensures logs survive reboots for forensic use
        local storage
        storage=$(grep -oP '^\s*Storage=\K.+' /etc/systemd/journald.conf 2>/dev/null || echo "")
        if [[ "${storage}" == "volatile" ]]; then
            print_warn "journald Storage=volatile — all logs are lost on reboot"
            print_rec  "Set 'Storage=persistent' in /etc/systemd/journald.conf"
        else
            print_pass "journald log storage is persistent (logs survive reboots)"
        fi
    fi

    # /var/log/secure — authentication event log on Fedora/RHEL
    # This file captures login attempts, sudo use, and PAM events.
    if [[ -f /var/log/secure ]]; then
        local secure_perms
        secure_perms=$(stat -c '%a' /var/log/secure 2>/dev/null || echo "unknown")
        if systemctl is-active --quiet rsyslog 2>/dev/null; then
            print_pass "/var/log/secure exists and rsyslog is active"
        else
            print_pass "/var/log/secure exists"
        fi
        if [[ "${secure_perms}" =~ ^(600|640)$ ]]; then
            print_pass "/var/log/secure permissions are ${secure_perms}"
        else
            print_warn "/var/log/secure permissions are ${secure_perms} (expected 600 or 640)"
            print_rec  "chmod 600 /var/log/secure"
        fi
    elif [[ -f /var/log/auth.log ]]; then
        print_pass "/var/log/auth.log exists (auth event logging is active)"
    else
        print_warn "No authentication log found (/var/log/secure or /var/log/auth.log)"
        print_rec  "Verify rsyslog or journald is configured to capture auth.* events"
    fi

    # logrotate — prevents /var/log from filling indefinitely
    if [[ -f /etc/logrotate.conf ]]; then
        print_pass "logrotate is configured (/etc/logrotate.conf exists)"
    else
        print_warn "logrotate.conf not found — logs may grow without limit"
        print_rec  "sudo dnf install logrotate"
    fi
}

# ==============================================================================
# MODULE 7 — BOOT & INTEGRITY
# ==============================================================================
# Checks that the boot process and firmware layer are protected. An attacker
# with physical access or UEFI write access can compromise the system before
# the OS ever starts, bypassing all OS-level security controls entirely.
# Reference: CIS RHEL Benchmark §1.4–1.5, NIST SP 800-147

check_boot_integrity() {
    print_header "7/8" "Boot & Integrity"

    # Secure Boot (UEFI)
    # Secure Boot validates the cryptographic signature of the bootloader and
    # kernel before executing them, preventing unsigned or tampered boot code.
    # Essential for physical-access threat models.
    if command -v mokutil &>/dev/null; then
        local sb_state
        sb_state=$(mokutil --sb-state 2>/dev/null || echo "unknown")
        if echo "${sb_state}" | grep -qi 'SecureBoot enabled'; then
            print_pass "Secure Boot is enabled"
        elif echo "${sb_state}" | grep -qi 'SecureBoot disabled'; then
            print_warn "Secure Boot is disabled"
            print_rec  "Enable Secure Boot in your UEFI/BIOS firmware settings"
        else
            print_info "Secure Boot state: ${sb_state}"
        fi
    elif [[ -d /sys/firmware/efi ]]; then
        # Read the Secure Boot EFI variable directly from the kernel interface
        local sb_efi="/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
        if [[ -f "${sb_efi}" ]]; then
            # Byte 4 (0-indexed) of the EFI variable holds the boolean state
            local sb_byte
            sb_byte=$(od -An -tx1 "${sb_efi}" 2>/dev/null | awk '{print $5}' | head -1 || echo "")
            if [[ "${sb_byte}" == "01" ]]; then
                print_pass "Secure Boot is enabled (EFI variable)"
            else
                print_warn "Secure Boot appears disabled (EFI variable)"
                print_rec  "Enable Secure Boot in UEFI firmware settings"
            fi
        else
            print_info "UEFI system detected — Secure Boot EFI variable not readable"
        fi
    else
        print_info "Non-UEFI (legacy BIOS) system — Secure Boot is not applicable"
    fi

    # GRUB configuration file permissions
    # The GRUB config contains the boot menu and kernel command-line parameters.
    # World-readable: leaks kernel params. Writable by non-root: can alter boot.
    local grub_cfg=""
    for path in /boot/grub2/grub.cfg \
                /boot/grub/grub.cfg \
                /boot/efi/EFI/fedora/grub.cfg; do
        if [[ -f "${path}" ]]; then
            grub_cfg="${path}"
            break
        fi
    done

    if [[ -n "${grub_cfg}" ]]; then
        local grub_perms
        grub_perms=$(stat -c '%a' "${grub_cfg}" 2>/dev/null || echo "unknown")
        if [[ "${grub_perms}" =~ ^(600|400)$ ]]; then
            print_pass "GRUB config permissions are ${grub_perms} (${grub_cfg})"
        else
            print_warn "GRUB config permissions are ${grub_perms} (expected 600)"
            print_rec  "chmod 600 ${grub_cfg}"
        fi

        # GRUB password
        # Without a GRUB password, anyone with physical access can edit the kernel
        # command line at boot (e.g. add 'single' or 'init=/bin/sh') to gain root.
        if grep -q 'password_pbkdf2\|password --md5' "${grub_cfg}" 2>/dev/null; then
            print_pass "GRUB bootloader password is configured"
        else
            print_warn "No GRUB password detected"
            print_rec  "Set a GRUB password to block physical-access boot editing: grub2-setpassword"
        fi
    else
        print_info "GRUB config not found in standard paths"
    fi

    # /boot directory permissions
    # /boot contains the kernel and initramfs — should not be world-writable.
    local boot_perms
    boot_perms=$(stat -c '%a' /boot 2>/dev/null || echo "unknown")
    local boot_other="${boot_perms: -1}"
    if [[ "${boot_other}" =~ ^[0145]$ ]]; then
        print_pass "/boot permissions are ${boot_perms} (no world-write)"
    else
        print_warn "/boot permissions are ${boot_perms} — world-writable bit may be set"
        print_rec  "chmod o-w /boot"
    fi

    # initramfs permissions
    # The initial RAM disk is the first code that runs after the kernel loads.
    # It should be readable only by root — world-readable exposes kernel internals.
    local initramfs
    initramfs=$(find /boot -maxdepth 1 -name 'initramfs-*.img' 2>/dev/null | head -1 || echo "")
    if [[ -n "${initramfs}" ]]; then
        local init_perms
        init_perms=$(stat -c '%a' "${initramfs}" 2>/dev/null || echo "unknown")
        if [[ "${init_perms}" =~ ^(600|400)$ ]]; then
            print_pass "initramfs permissions are ${init_perms}"
        else
            print_warn "initramfs permissions are ${init_perms} (expected 600)"
            print_rec  "chmod 600 /boot/initramfs-*.img"
        fi
    fi

    # Running kernel version — informational; cross-check against kernel CVE lists
    local kver
    kver=$(uname -r 2>/dev/null || echo "unknown")
    print_info "Running kernel: ${kver}"
}

# ==============================================================================
# MODULE 8 — CONTAINER / VM SURFACE & SELinux
# ==============================================================================
# SELinux is the most impactful single security control on Fedora/RHEL systems.
# In Enforcing mode it confines every process — including root — to only the
# resources it is explicitly permitted to access. We also check Docker security
# configuration if Docker is present on this system.
# Reference: SELinux Project docs, CIS Docker Benchmark

check_containers() {
    print_header "8/8" "Container / VM Surface & SELinux"

    # SELinux status and enforcement mode
    # Enforcing = policies are active and block violations.
    # Permissive = policies log violations but do not block (training mode only).
    # Disabled = mandatory access control is completely inactive.
    if command -v sestatus &>/dev/null; then
        local selinux_enabled selinux_mode selinux_policy
        selinux_enabled=$(sestatus 2>/dev/null | grep -oP '(?<=SELinux status:\s{1,20})\S+' || echo "unknown")
        selinux_mode=$(sestatus 2>/dev/null | grep -oP '(?<=Current mode:\s{1,20})\S+' || echo "unknown")
        selinux_policy=$(sestatus 2>/dev/null | grep -oP '(?<=Loaded policy name:\s{1,20})\S+' || echo "unknown")

        if [[ "${selinux_enabled}" == "enabled" && "${selinux_mode}" == "enforcing" ]]; then
            print_pass "SELinux is enabled and Enforcing (policy: ${selinux_policy})"
        elif [[ "${selinux_enabled}" == "enabled" && "${selinux_mode}" == "permissive" ]]; then
            print_warn "SELinux is enabled but in Permissive mode — violations are logged, not blocked"
            print_rec  "setenforce 1  (immediate) and set SELINUX=enforcing in /etc/selinux/config"
        else
            print_fail "SELinux is disabled — mandatory access control is entirely inactive"
            print_rec  "Set SELINUX=enforcing in /etc/selinux/config and reboot"
        fi
    else
        print_warn "sestatus not found — SELinux may not be installed"
        print_rec  "sudo dnf install selinux-policy selinux-policy-targeted"
    fi

    # SELinux AVC (denial) count for today
    # High AVC counts indicate either an application misbehaving or active
    # attacks being blocked by the policy. Either warrants investigation.
    if command -v ausearch &>/dev/null && [[ "$EUID" -eq 0 ]]; then
        local avc_count
        avc_count=$(ausearch -m avc -ts today 2>/dev/null | grep -c '^----')
        if [[ "${avc_count}" -eq 0 ]]; then
            print_pass "No SELinux AVC denials recorded today"
        elif [[ "${avc_count}" -lt 10 ]]; then
            print_info "${avc_count} SELinux AVC denial(s) today — review if unexpected"
        else
            print_warn "${avc_count} SELinux AVC denials today — investigation recommended"
            print_rec  "ausearch -m avc -ts today | audit2why"
        fi
    fi

    # Docker security checks (only if Docker is present)
    if command -v docker &>/dev/null; then
        print_info "Docker is installed — checking daemon security configuration..."
        echo ""

        if systemctl is-active --quiet docker 2>/dev/null; then
            print_pass "Docker daemon is active"

            # Docker socket permissions
            # /var/run/docker.sock is equivalent to passwordless root access.
            # If it's world-accessible, any user can control Docker and escape to the host.
            if [[ -S /var/run/docker.sock ]]; then
                local sock_perms
                sock_perms=$(stat -c '%a' /var/run/docker.sock 2>/dev/null || echo "unknown")
                if [[ "${sock_perms}" =~ ^(660|600)$ ]]; then
                    print_pass "Docker socket permissions are ${sock_perms}"
                else
                    print_fail "Docker socket permissions are ${sock_perms} — may be too permissive"
                    print_rec  "Docker socket = root access; restrict to the docker group only"
                fi
            fi

            # Docker group membership
            # Members of the docker group can mount the host filesystem into a
            # container and read/write any file — this is root-equivalent access.
            if getent group docker &>/dev/null; then
                local docker_members
                docker_members=$(getent group docker 2>/dev/null | cut -d: -f4)
                if [[ -z "${docker_members}" ]]; then
                    print_pass "Docker group has no members (only root accesses Docker)"
                else
                    print_warn "Docker group members: ${docker_members}"
                    print_rec  "Docker group membership = root equivalence — ensure all members are trusted"
                fi
            fi

            # Content Trust — ensures only cryptographically signed images can be pulled
            if [[ "$EUID" -eq 0 ]]; then
                local docker_info
                docker_info=$(docker info 2>/dev/null || echo "")
                if echo "${docker_info}" | grep -qi 'Content Trust: true'; then
                    print_pass "Docker Content Trust (image signing) is enabled"
                else
                    print_warn "Docker Content Trust is not enabled — unsigned images can be pulled"
                    print_rec  "Set DOCKER_CONTENT_TRUST=1 in environment or daemon config"
                fi
            fi
        else
            print_info "Docker is installed but daemon is not running"
        fi
    else
        print_info "Docker is not installed — container surface check skipped"
    fi

    # Podman — Fedora's default rootless container tool
    # Podman runs containers as the invoking user with no privileged daemon,
    # making container escapes far less impactful than with Docker.
    if command -v podman &>/dev/null; then
        local podman_ver
        podman_ver=$(podman --version 2>/dev/null | awk '{print $3}' || echo "unknown")
        print_pass "Podman is available (rootless containers supported) — v${podman_ver}"
    fi
}

# ==============================================================================
# ── SECTION 5: FINAL SCORE & SUMMARY ──────────────────────────────────────────
# ==============================================================================

# ------------------------------------------------------------------------------
# print_summary — Compute the risk score and display the final graded report.
# Called once, after all 8 modules have completed.
# ------------------------------------------------------------------------------
print_summary() {
    # Risk score: percentage of max possible risk points actually accumulated.
    # MAX_RISK_POINTS = (number of checks × 3), i.e. every check could be a FAIL.
    local score=0
    if [[ "${MAX_RISK_POINTS}" -gt 0 ]]; then
        score=$(( (RISK_POINTS * 100) / MAX_RISK_POINTS ))
    fi
    [[ "${score}" -gt 100 ]] && score=100

    # Map score to letter grade, colour, and label
    local grade grade_color label
    if   [[ "${score}" -le 20 ]]; then grade="A"; grade_color="${GREEN}";  label="Hardened"
    elif [[ "${score}" -le 40 ]]; then grade="B"; grade_color="${GREEN}";  label="Acceptable"
    elif [[ "${score}" -le 60 ]]; then grade="C"; grade_color="${YELLOW}"; label="Needs Attention"
    elif [[ "${score}" -le 80 ]]; then grade="D"; grade_color="${RED}";    label="Vulnerable"
    else                               grade="F"; grade_color="${RED}";    label="Critical"
    fi

    local sep
    sep=$(printf '─%.0s' {1..62})

    echo ""
    echo -e "${CYAN}${sep}${RESET}"
    echo -e "${CYAN}  AUDIT COMPLETE — RESULTS SUMMARY${RESET}"
    echo -e "${CYAN}${sep}${RESET}"
    echo ""
    printf "  ${GREEN}%-8s${RESET} %d checks passed\n"           "PASS" "${PASS_COUNT}"
    printf "  ${YELLOW}%-8s${RESET} %d warnings  (+1 risk point each)\n" "WARN" "${WARN_COUNT}"
    printf "  ${RED}%-8s${RESET} %d failures  (+3 risk points each)\n"   "FAIL" "${FAIL_COUNT}"
    echo ""
    echo -e "${CYAN}${sep}${RESET}"
    printf "  Risk Score : ${grade_color}%d / 100${RESET}\n" "${score}"
    printf "  Grade      : ${grade_color}%s — %s${RESET}\n"  "${grade}" "${label}"
    echo -e "${CYAN}${sep}${RESET}"
    echo ""
    echo -e "  ${DIM}Grade buckets:${RESET}"
    echo -e "  ${DIM}  A 0–20   Hardened        B 21–40  Acceptable${RESET}"
    echo -e "  ${DIM}  C 41–60  Needs Attention  D 61–80  Vulnerable  F 81–100 Critical${RESET}"
    echo ""
    echo -e "  ${DIM}vulnScan is read-only — no changes were made to your system.${RESET}"
    echo -e "  ${DIM}Review each ${MAGENTA}[REC]${RESET}${DIM} item above and apply fixes manually.${RESET}"
    echo ""
}

# ==============================================================================
# ── SECTION 6: MAIN ENTRY POINT ───────────────────────────────────────────────
# ==============================================================================

main() {
    # Require bash 5+ for associative arrays (declare -A) and mapfile features
    if [[ "${BASH_VERSINFO[0]}" -lt 5 ]]; then
        echo "ERROR: vulnScan requires bash 5.0 or newer (running: bash ${BASH_VERSION})" >&2
        exit 1
    fi

    # Fedora/RHEL family detection — warn if the OS family doesn't match
    if [[ -f /etc/os-release ]]; then
        local os_id os_like
        os_id=$(grep -oP '(?<=^ID=)[^"]*' /etc/os-release 2>/dev/null | tr -d '"' || echo "")
        os_like=$(grep -oP '(?<=^ID_LIKE=)[^"]*' /etc/os-release 2>/dev/null | tr -d '"' || echo "")
        if ! echo "${os_id} ${os_like}" | grep -qiE 'fedora|rhel|centos|rocky|alma'; then
            echo ""
            echo -e "${YELLOW}WARNING: OS does not appear to be Fedora/RHEL-based (detected: ${os_id}).${RESET}"
            echo -e "${YELLOW}         Some checks (firewalld, dnf, sestatus) may fail or be skipped.${RESET}"
            echo ""
            echo -ne "  Continue anyway? [y/N]: "
            read -r _os_ans
            [[ "${_os_ans}" =~ ^[Yy]$ ]] || exit 0
        fi
    fi

    print_banner
    check_privileges

    echo ""
    echo -e "  ${WHITE}Starting audit across 8 categories.${RESET}"
    echo -e "  ${WHITE}Press [Enter] after each section to advance.${RESET}"
    echo ""
    echo -ne "  ${BLUE}Press [Enter] to begin...${RESET}"
    read -r _start_dummy

    check_system_hardening;  pause
    check_user_auth;         pause
    check_network_firewall;  pause
    check_file_permissions;  pause
    check_packages;          pause
    check_logging_audit;     pause
    check_boot_integrity;    pause
    check_containers

    print_summary
}

# ── Entry point ─────────────────────────────────────────────────────────────
main "$@"
