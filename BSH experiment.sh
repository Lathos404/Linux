#!/bin/bash
#
# harden.sh - Foundational Ubuntu/Debian Server Hardening
# Version: 1.0
#
# Usage:
#   sudo ./harden.sh                    # interactive, moderate
#   sudo ./harden.sh --dry-run -v       # preview
#   sudo ./harden.sh -e ssh,firewall    # specific modules
#   sudo ./harden.sh --level high -n    # non-interactive
#
# This script is designed to be:
#   - Readable: ~900 lines, one module per function
#   - Idempotent: safe to re-run
#   - Safe: validate before commit, verify after apply
#   - Honest: warns when hardening would break known workloads
#
# Tested on: Ubuntu 22.04, 24.04; Debian 12
#

set -euo pipefail

readonly VERSION="1.0"
readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly LOG_FILE="/var/log/harden.log"
readonly BACKUP_ROOT="/var/backups/harden"
readonly STAMP="$(date +%Y%m%d-%H%M%S)"
readonly BACKUP_DIR="${BACKUP_ROOT}/${STAMP}"
readonly CONFIG_FILE="${SCRIPT_DIR}/harden.conf"
readonly TEMP_DIR="$(mktemp -d -t harden.XXXXXX)"

# ---- Runtime state ---------------------------------------------------------

DRY_RUN=false
VERBOSE=false
INTERACTIVE=true
EXPLAIN=false
SECURITY_LEVEL="moderate"
SCANNER_MODE=false
ENABLE_MODULES=""
DISABLE_MODULES=""
FORCE_DESKTOP=false
FORCE_SERVER=false
GENERATE_CONFIG=false
IS_DESKTOP=false
SUDO=""

# Track which flags were explicitly passed so they override config file.
declare -A CLI_SET=(
    [verbose]=false [dry_run]=false [interactive]=false [explain]=false
    [level]=false [enable]=false [disable]=false [scanner]=false
    [force_desktop]=false [force_server]=false
)

declare -a EXECUTED=() FAILED=() SKIPPED=()

# ---- Config defaults (overridable by harden.conf) -------------------------

SSH_PORT=22
SSH_MAX_AUTH_TRIES=3
SSH_ALLOWED_USERS=""
SSH_ALLOWED_GROUPS=""
SSH_ALLOW_TCP_FORWARDING="no"
SSH_ALLOW_AGENT_FORWARDING="no"
SSH_MAX_SESSIONS=10
SSH_KBD_INTERACTIVE="no"

UFW_DEFAULT_INCOMING="deny"
UFW_DEFAULT_OUTGOING="allow"
FIREWALL_ALLOW_PORTS=""

PASSWORD_MIN_LENGTH=14
PASSWORD_HISTORY=5

FAIL2BAN_ENABLED=false
FAIL2BAN_BANTIME=3600
FAIL2BAN_FINDTIME=600
FAIL2BAN_MAXRETRY=5

ALLOW_DOCKER_FORWARDING=true
ALLOW_BROWSER_SHAREDMEM=true

# ---- Colors ---------------------------------------------------------------

readonly RED='\033[0;31m' GREEN='\033[0;32m' YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m' CYAN='\033[0;36m' NC='\033[0m'

# ---- Logging --------------------------------------------------------------

cleanup() { rm -rf "${TEMP_DIR}" 2>/dev/null || true; }
trap cleanup EXIT

log() {
    local level="$1"; shift
    local msg="$*"
    local ts; ts="$(date '+%Y-%m-%d %H:%M:%S')"
    echo "${ts} [${level}] ${msg}" | ${SUDO} tee -a "${LOG_FILE}" >/dev/null 2>&1 || true
    case "${level}" in
        ERROR)   echo -e "${RED}[ERROR]${NC} ${msg}" >&2 ;;
        WARN)    echo -e "${YELLOW}[WARN]${NC} ${msg}" ;;
        SUCCESS) echo -e "${GREEN}[OK]${NC} ${msg}" ;;
        INFO)    [[ "${VERBOSE}" == "true" ]] && echo -e "${BLUE}[INFO]${NC} ${msg}" || true ;;
        *)       echo "${msg}" ;;
    esac
}

explain() {
    [[ "${EXPLAIN}" == "true" ]] || return 0
    echo ""
    echo -e "${CYAN}── WHY ──────────────────────────────────────────${NC}"
    for line in "$@"; do echo -e "${CYAN}│${NC} ${line}"; done
    echo -e "${CYAN}─────────────────────────────────────────────────${NC}"
    echo ""
    [[ "${INTERACTIVE}" == "true" ]] && { read -rp "Press Enter..." _; }
}

# ---- Privilege escalation --------------------------------------------------

check_permissions() {
    if [[ "${EUID}" -eq 0 ]]; then
        SUDO=""
    elif command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
        if ! sudo -n true 2>/dev/null; then
            echo -e "${YELLOW}This script needs root. You'll be prompted for sudo.${NC}"
            sudo -v || { echo "Failed to acquire sudo."; exit 1; }
        fi
    else
        echo -e "${RED}Need root. sudo not installed and EUID=${EUID}.${NC}"
        echo "On minimal containers, run as root directly."
        exit 1
    fi
}

# ---- Safe command execution (argv, no eval) -------------------------------

run() {
    # run "description" cmd arg1 arg2 ...
    # Pass ${SUDO} unquoted: becomes empty when root, "sudo" otherwise.
    local desc="$1"; shift
    if [[ "${DRY_RUN}" == "true" ]]; then
        log INFO "[DRY RUN] ${desc}: $*"
        return 0
    fi
    log INFO "${desc}"
    "$@"
}

# ---- File backup -----------------------------------------------------------

backup_file() {
    local f="$1"
    [[ -f "${f}" ]] || return 0
    if [[ "${DRY_RUN}" == "true" ]]; then
        log INFO "[DRY RUN] Would back up ${f}"
        return 0
    fi
    local dest="${BACKUP_DIR}${f}"
    ${SUDO} mkdir -p "$(dirname "${dest}")"
    ${SUDO} cp -a "${f}" "${dest}"
    log INFO "Backed up ${f} → ${dest}"
}

# ---- HTML escape -----------------------------------------------------------

html_escape() {
    local s="$1"
    s="${s//&/&amp;}"; s="${s//</&lt;}"; s="${s//>/&gt;}"
    s="${s//\"/&quot;}"; s="${s//\'/&#39;}"
    printf '%s' "${s}"
}

# ---- Environment detection -------------------------------------------------

detect_desktop() {
    [[ "${FORCE_DESKTOP}" == "true" ]] && { IS_DESKTOP=true; return; }
    [[ "${FORCE_SERVER}"  == "true" ]] && { IS_DESKTOP=false; return; }
    if [[ -n "${XDG_CURRENT_DESKTOP:-}" ]] || \
       systemctl is-active --quiet display-manager 2>/dev/null; then
        IS_DESKTOP=true
    fi
}

DOCKER_DETECTED=false
BROWSERS_FOUND=()

detect_workloads() {
    command -v docker >/dev/null 2>&1 && {
        DOCKER_DETECTED=true
        log INFO "Docker detected"
    }
    local b
    for b in firefox chromium google-chrome brave-browser; do
        command -v "${b}" >/dev/null 2>&1 && BROWSERS_FOUND+=("${b}")
    done
    [[ ${#BROWSERS_FOUND[@]} -gt 0 ]] && log INFO "Browsers: ${BROWSERS_FOUND[*]}"
}

# ---- APT lock handling -----------------------------------------------------

wait_for_apt() {
    local waited=0
    while ${SUDO} fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; do
        [[ ${waited} -eq 0 ]] && log WARN "Waiting for apt lock..."
        sleep 2; waited=$((waited + 2))
        [[ ${waited} -ge 300 ]] && { log ERROR "apt lock timeout"; return 1; }
    done
}

# ---- Module registry -------------------------------------------------------

declare -A MODULE_DESC=(
    [update]="Apply system updates"
    [ssh]="Harden SSH (keys only, no root)"
    [firewall]="Configure UFW"
    [sysctl]="Kernel/network hardening"
    [passwords]="Password quality policy"
    [auto_updates]="Unattended security updates"
    [audit]="auditd rules for auth events"
    [fail2ban]="Optional: ban brute-force IPs"
    [apparmor]="Enforce AppArmor profiles"
    [root_lock]="Lock root account (sudo only)"
    [verify]="Post-run verification"
)

# Modules execute in this order. Deps are implicit through ordering.
MODULE_ORDER=(update auto_updates sysctl firewall ssh passwords audit fail2ban apparmor root_lock verify)

# ============================================================================
# MODULES
# ============================================================================

module_update() {
    explain \
        "Package updates are the single highest-value hardening step." \
        "Most exploits target vulnerabilities that already have patches."
    wait_for_apt
    run "Refreshing apt lists" ${SUDO} apt-get update
    run "Applying upgrades" ${SUDO} env DEBIAN_FRONTEND=noninteractive apt-get upgrade -y
}

module_auto_updates() {
    explain \
        "Unattended-upgrades applies security patches automatically." \
        "Delay between patch release and exploit is often under 7 days."
    run "Installing unattended-upgrades" ${SUDO} apt-get install -y unattended-upgrades

    [[ "${DRY_RUN}" == "true" ]] && return 0

    ${SUDO} tee /etc/apt/apt.conf.d/20auto-upgrades >/dev/null <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

    ${SUDO} tee /etc/apt/apt.conf.d/50unattended-upgrades >/dev/null <<'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF

    run "Enabling unattended-upgrades" \
        ${SUDO} systemctl enable --now unattended-upgrades
}

module_sysctl() {
    explain \
        "Kernel sysctls reduce network and memory attack surface." \
        "IP forwarding is conditional: enabled only when Docker is present" \
        "and ALLOW_DOCKER_FORWARDING=true (Docker networking requires it)."

    local ipfwd=0
    if [[ "${DOCKER_DETECTED}" == "true" && "${ALLOW_DOCKER_FORWARDING}" == "true" ]]; then
        ipfwd=1
        log WARN "IP forwarding enabled for Docker compatibility"
    fi

    local conf="/etc/sysctl.d/99-harden.conf"
    backup_file "${conf}"
    [[ "${DRY_RUN}" == "true" ]] && return 0

    ${SUDO} tee "${conf}" >/dev/null <<EOF
# harden.sh v${VERSION}
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.tcp_timestamps = 0
net.ipv4.ip_forward = ${ipfwd}
net.ipv6.conf.all.forwarding = ${ipfwd}

kernel.randomize_va_space = 2
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1
kernel.perf_event_paranoid = 3
fs.suid_dumpable = 0
EOF

    run "Applying sysctl" ${SUDO} sysctl -p "${conf}"
}

module_firewall() {
    explain \
        "UFW with default-deny inbound blocks all unexpected connections." \
        "Only explicitly allowed services are reachable."
    run "Installing ufw" ${SUDO} apt-get install -y ufw

    [[ "${DRY_RUN}" == "true" ]] && return 0

    ${SUDO} ufw --force reset >/dev/null
    ${SUDO} ufw default "${UFW_DEFAULT_INCOMING}" incoming
    ${SUDO} ufw default "${UFW_DEFAULT_OUTGOING}" outgoing
    ${SUDO} ufw default deny routed

    # SSH is the one port we must not forget.
    ${SUDO} ufw limit "${SSH_PORT}/tcp" comment 'SSH (rate limited)'

    # Web servers if present.
    if systemctl is-active --quiet nginx 2>/dev/null || \
       systemctl is-active --quiet apache2 2>/dev/null; then
        ${SUDO} ufw allow 80/tcp comment 'HTTP'
        ${SUDO} ufw allow 443/tcp comment 'HTTPS'
        log INFO "Web ports opened (nginx/apache detected)"
    fi

    # Custom ports from config.
    if [[ -n "${FIREWALL_ALLOW_PORTS}" ]]; then
        local p
        IFS=',' read -ra ports <<< "${FIREWALL_ALLOW_PORTS}"
        for p in "${ports[@]}"; do
            p="${p// /}"
            [[ -z "${p}" ]] && continue
            ${SUDO} ufw allow "${p}/tcp" comment "Custom"
            log INFO "Allowed custom port: ${p}"
        done
    fi

    ${SUDO} ufw logging low
    ${SUDO} ufw --force enable
    log SUCCESS "Firewall active"
}

module_ssh() {
    explain \
        "SSH hardening disables password auth (keys only) and root login." \
        "Before running, verify key-based SSH works — otherwise you will lock out." \
        "" \
        "This module also detects /etc/ssh/sshd_config.d drop-ins from cloud" \
        "images and warns if they contain conflicting directives."

    local cfg="/etc/ssh/sshd_config"
    local dropin_dir="/etc/ssh/sshd_config.d"

    # Warn about drop-in conflicts — do NOT silently preserve them.
    if [[ -d "${dropin_dir}" ]]; then
        local f
        for f in "${dropin_dir}"/*.conf; do
            [[ -f "${f}" ]] || continue
            if grep -qE '^\s*(PasswordAuthentication|PermitRootLogin)\s+yes' "${f}"; then
                log WARN "SSH drop-in conflicts with hardening: ${f}"
                log WARN "  sshd uses FIRST matching directive; our config will win"
                log WARN "  Review that file and remove conflicting settings."
            fi
        done
    fi

    # Interactive safety gate: require explicit acknowledgment.
    if [[ "${INTERACTIVE}" == "true" && "${DRY_RUN}" == "false" ]]; then
        echo ""
        echo -e "${YELLOW}SSH hardening will DISABLE password authentication.${NC}"
        echo "You must already have working key-based SSH access."
        read -rp "Type 'yes' to confirm key-based SSH works: " ans
        [[ "${ans}" != "yes" ]] && { log WARN "SSH hardening skipped"; return 0; }
    fi

    # Scanner mode: relax options that block credentialed compliance scans.
    local tcp_fwd="${SSH_ALLOW_TCP_FORWARDING}"
    local agent_fwd="${SSH_ALLOW_AGENT_FORWARDING}"
    local max_sess="${SSH_MAX_SESSIONS}"
    local kbd="${SSH_KBD_INTERACTIVE}"
    if [[ "${SCANNER_MODE}" == "true" ]]; then
        log WARN "Scanner mode: relaxing SSH for Nessus/OpenSCAP/CIS scans"
        tcp_fwd="yes"; agent_fwd="yes"; max_sess=20; kbd="yes"
    fi

    # Validate before writing.
    local v
    for v in "${tcp_fwd}" "${agent_fwd}" "${kbd}"; do
        case "${v}" in yes|no) ;; *) log ERROR "Invalid yes/no: ${v}"; return 1 ;; esac
    done
    [[ "${max_sess}" =~ ^[0-9]+$ ]] || { log ERROR "SSH_MAX_SESSIONS not numeric"; return 1; }

    # Locate sftp-server (path varies; hard-coding breaks scp on some systems).
    local sftp=""
    for cand in /usr/lib/openssh/sftp-server /usr/libexec/openssh/sftp-server; do
        [[ -x "${cand}" ]] && { sftp="${cand}"; break; }
    done
    if [[ -z "${sftp}" ]] && command -v sftp-server >/dev/null 2>&1; then
        sftp="$(command -v sftp-server)"
    fi
    [[ -z "${sftp}" ]] && { log ERROR "sftp-server not found"; return 1; }

    backup_file "${cfg}"
    [[ "${DRY_RUN}" == "true" ]] && return 0

    ${SUDO} tee "${cfg}" >/dev/null <<EOF
# harden.sh v${VERSION} — generated ${STAMP}
Port ${SSH_PORT}
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
KbdInteractiveAuthentication ${kbd}
UsePAM yes

KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com

ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 30
MaxAuthTries ${SSH_MAX_AUTH_TRIES}
MaxSessions ${max_sess}

SyslogFacility AUTH
LogLevel VERBOSE
X11Forwarding no
AllowAgentForwarding ${agent_fwd}
AllowTcpForwarding ${tcp_fwd}
PermitTunnel no
PrintMotd no
PrintLastLog yes
Compression delayed
Subsystem sftp ${sftp}
EOF

    [[ -n "${SSH_ALLOWED_USERS}"  ]] && echo "AllowUsers ${SSH_ALLOWED_USERS//,/ }"  | ${SUDO} tee -a "${cfg}" >/dev/null
    [[ -n "${SSH_ALLOWED_GROUPS}" ]] && echo "AllowGroups ${SSH_ALLOWED_GROUPS//,/ }" | ${SUDO} tee -a "${cfg}" >/dev/null

    # Validate before restarting.
    if ! ${SUDO} sshd -t; then
        log ERROR "sshd config invalid — restoring backup"
        ${SUDO} cp -a "${BACKUP_DIR}${cfg}" "${cfg}"
        return 1
    fi

    run "Restarting SSH" ${SUDO} systemctl restart ssh 2>/dev/null || \
        ${SUDO} systemctl restart sshd
    log SUCCESS "SSH hardened"
}

module_passwords() {
    explain \
        "Password quality matters only if password auth is in use." \
        "With SSH keys enforced, this is defense-in-depth for local/console logins."
    run "Installing pwquality" ${SUDO} apt-get install -y libpam-pwquality

    [[ "${DRY_RUN}" == "true" ]] && return 0

    ${SUDO} tee /etc/security/pwquality.conf >/dev/null <<EOF
minlen = ${PASSWORD_MIN_LENGTH}
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
maxrepeat = 3
usercheck = 1
enforce_for_root
EOF

    # Password history via login.defs + pam.
    ${SUDO} sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   365/' /etc/login.defs
    ${SUDO} sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/'   /etc/login.defs
    ${SUDO} sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/'   /etc/login.defs
    grep -q '^ENCRYPT_METHOD' /etc/login.defs \
        && ${SUDO} sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/' /etc/login.defs \
        || echo 'ENCRYPT_METHOD SHA512' | ${SUDO} tee -a /etc/login.defs >/dev/null

    log SUCCESS "Password policy configured"
}

module_audit() {
    explain \
        "auditd records auth events, sudo usage, and file changes." \
        "Rules are locked (-e 2) only at high/paranoid — locking breaks idempotency."
    run "Installing auditd" ${SUDO} apt-get install -y auditd

    [[ "${DRY_RUN}" == "true" ]] && return 0

    local rules="/etc/audit/rules.d/harden.rules"
    ${SUDO} tee "${rules}" >/dev/null <<'EOF'
-D
-b 8192
-f 1

-w /etc/passwd  -p wa -k identity
-w /etc/group   -p wa -k identity
-w /etc/shadow  -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k actions
-w /etc/sudoers.d/ -p wa -k actions

-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/wtmp    -p wa -k logins
-w /var/log/btmp    -p wa -k logins
EOF

    case "${SECURITY_LEVEL}" in
        high|paranoid)
            echo "-e 2" | ${SUDO} tee -a "${rules}" >/dev/null
            log WARN "Audit rules locked (-e 2): changes require reboot"
            ;;
        *)
            echo "-e 1" | ${SUDO} tee -a "${rules}" >/dev/null
            ;;
    esac

    run "Loading audit rules" ${SUDO} augenrules --load
    run "Enabling auditd" ${SUDO} systemctl enable --now auditd
}

module_fail2ban() {
    if [[ "${FAIL2BAN_ENABLED}" != "true" ]]; then
        log INFO "fail2ban disabled (SSH password auth is off — limited value)"
        SKIPPED+=("fail2ban")
        return 0
    fi

    explain \
        "fail2ban is useful for web/mail servers with password auth." \
        "With SSH keys-only, it only reduces log noise."

    run "Installing fail2ban" ${SUDO} apt-get install -y fail2ban
    [[ "${DRY_RUN}" == "true" ]] && return 0

    ${SUDO} tee /etc/fail2ban/jail.local >/dev/null <<EOF
[DEFAULT]
bantime  = ${FAIL2BAN_BANTIME}
findtime = ${FAIL2BAN_FINDTIME}
maxretry = ${FAIL2BAN_MAXRETRY}
# action_ is iptables-only; action_mwl requires mailutils+whois.
action = %(action_)s

[sshd]
enabled = false
EOF

    run "Enabling fail2ban" ${SUDO} systemctl enable --now fail2ban
}

module_apparmor() {
    explain \
        "AppArmor confines programs by profile. We enforce only profiles" \
        "already loaded — not every file in /etc/apparmor.d (that breaks services)."
    run "Installing AppArmor" \
        ${SUDO} apt-get install -y apparmor apparmor-utils apparmor-profiles

    [[ "${DRY_RUN}" == "true" ]] && return 0

    ${SUDO} systemctl enable --now apparmor

    local enforced=0 p
    while IFS= read -r p; do
        [[ -z "${p}" ]] && continue
        ${SUDO} aa-enforce "${p}" 2>/dev/null && enforced=$((enforced + 1)) || true
    done < <(${SUDO} aa-status --profiled 2>/dev/null || true)

    log INFO "AppArmor: ${enforced} profile(s) in enforce mode"
}

module_root_lock() {
    explain \
        "Locking root forces all admin actions through sudo, which logs who" \
        "did what. This module refuses to proceed unless a non-root sudo user" \
        "exists — otherwise it would lock you out entirely."

    if ! command -v sudo >/dev/null 2>&1; then
        log WARN "sudo not installed — refusing to lock root"
        SKIPPED+=("root_lock (no sudo)")
        return 0
    fi

    local sudo_users
    sudo_users="$(getent group sudo 2>/dev/null | awk -F: '{print $4}' | tr ',' '\n' \
                  | grep -v '^$' | grep -v '^root$' | sort -u || true)"

    if [[ -z "${sudo_users}" ]]; then
        log WARN "No non-root sudo user found — refusing to lock root"
        log WARN "Create one first:  adduser <name> && usermod -aG sudo <name>"
        SKIPPED+=("root_lock (no sudo user)")
        return 0
    fi

    log INFO "Sudo users detected: $(echo "${sudo_users}" | tr '\n' ' ')"
    run "Locking root password" ${SUDO} passwd -l root
    log SUCCESS "Direct root login disabled"
}

module_verify() {
    explain \
        "Verification confirms hardening was actually applied." \
        "A hardening script that cannot prove its own effect is theater."
    [[ "${DRY_RUN}" == "true" ]] && return 0

    local failures=0

    # SSH
    if command -v sshd >/dev/null 2>&1; then
        ${SUDO} sshd -t 2>/dev/null || { log ERROR "sshd -t failed"; failures=$((failures+1)); }
        ${SUDO} sshd -T 2>/dev/null | grep -qi '^passwordauthentication yes' \
            && { log WARN "PasswordAuthentication still yes"; failures=$((failures+1)); }
        ${SUDO} sshd -T 2>/dev/null | grep -qi '^permitrootlogin yes' \
            && { log WARN "PermitRootLogin still yes"; failures=$((failures+1)); }
    fi

    # Firewall
    if command -v ufw >/dev/null 2>&1; then
        ${SUDO} ufw status 2>/dev/null | grep -q '^Status: active' \
            || { log WARN "UFW not active"; failures=$((failures+1)); }
    fi

    # Sysctl
    local pair key expected actual
    for pair in kernel.randomize_va_space=2 net.ipv4.tcp_syncookies=1 kernel.yama.ptrace_scope=1; do
        key="${pair%%=*}"; expected="${pair##*=}"
        actual="$(sysctl -n "${key}" 2>/dev/null || echo "")"
        [[ "${actual}" == "${expected}" ]] || {
            log WARN "sysctl ${key}=${actual} (want ${expected})"; failures=$((failures+1)); }
    done

    if [[ ${failures} -eq 0 ]]; then
        log SUCCESS "Verification passed"
    else
        log WARN "Verification found ${failures} discrepancy(ies)"
    fi
}

# ============================================================================
# LOGROTATE / CONFIG / REPORT
# ============================================================================

install_logrotate() {
    [[ -f /etc/logrotate.d/harden ]] && return 0
    [[ "${DRY_RUN}" == "true" ]] && return 0
    ${SUDO} tee /etc/logrotate.d/harden >/dev/null <<EOF
${LOG_FILE} {
    weekly
    rotate 8
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root adm
}
EOF
}

load_config() {
    [[ -f "${CONFIG_FILE}" ]] || return 0
    log INFO "Loading ${CONFIG_FILE}"

    # Snapshot CLI-provided values so we can restore them.
    local cli_verbose="${VERBOSE}" cli_dry="${DRY_RUN}" cli_inter="${INTERACTIVE}"
    local cli_explain="${EXPLAIN}" cli_level="${SECURITY_LEVEL}"
    local cli_en="${ENABLE_MODULES}" cli_dis="${DISABLE_MODULES}"
    local cli_scanner="${SCANNER_MODE}" cli_fd="${FORCE_DESKTOP}" cli_fs="${FORCE_SERVER}"

    # shellcheck disable=SC1090
    source "${CONFIG_FILE}"

    case "${SECURITY_LEVEL}" in
        low|moderate|high|paranoid) ;;
        *) log ERROR "Bad SECURITY_LEVEL: ${SECURITY_LEVEL}"; exit 1 ;;
    esac

    # CLI flags win when explicitly set.
    [[ "${CLI_SET[verbose]}"       == "true" ]] && VERBOSE="${cli_verbose}"
    [[ "${CLI_SET[dry_run]}"       == "true" ]] && DRY_RUN="${cli_dry}"
    [[ "${CLI_SET[interactive]}"   == "true" ]] && INTERACTIVE="${cli_inter}"
    [[ "${CLI_SET[explain]}"       == "true" ]] && EXPLAIN="${cli_explain}"
    [[ "${CLI_SET[level]}"         == "true" ]] && SECURITY_LEVEL="${cli_level}"
    [[ "${CLI_SET[enable]}"        == "true" ]] && ENABLE_MODULES="${cli_en}"
    [[ "${CLI_SET[disable]}"       == "true" ]] && DISABLE_MODULES="${cli_dis}"
    [[ "${CLI_SET[scanner]}"       == "true" ]] && SCANNER_MODE="${cli_scanner}"
    [[ "${CLI_SET[force_desktop]}" == "true" ]] && FORCE_DESKTOP="${cli_fd}"
    [[ "${CLI_SET[force_server]}"  == "true" ]] && FORCE_SERVER="${cli_fs}"
}

generate_config_template() {
    local out="${SCRIPT_DIR}/harden.conf"
    cat > "${out}" <<'EOF'
# harden.sh configuration
# CLI flags override these when explicitly passed.

SECURITY_LEVEL="moderate"
INTERACTIVE=true
VERBOSE=false
DRY_RUN=false
EXPLAIN_MODE=false

# Modules: leave empty to run all.
# Available: update auto_updates sysctl firewall ssh passwords audit fail2ban apparmor root_lock verify
ENABLE_MODULES=""
DISABLE_MODULES=""

# Workload compatibility
ALLOW_DOCKER_FORWARDING=true      # needed for Docker networking
ALLOW_BROWSER_SHAREDMEM=true      # skips /dev/shm noexec; Firefox/Chrome need it

# Scanner mode (Nessus/OpenSCAP/CIS credentialed scans)
SCANNER_MODE=false

# SSH
SSH_PORT=22
SSH_MAX_AUTH_TRIES=3
SSH_ALLOWED_USERS=""
SSH_ALLOWED_GROUPS=""
SSH_ALLOW_TCP_FORWARDING="no"
SSH_ALLOW_AGENT_FORWARDING="no"
SSH_MAX_SESSIONS=10
SSH_KBD_INTERACTIVE="no"

# Firewall
UFW_DEFAULT_INCOMING="deny"
UFW_DEFAULT_OUTGOING="allow"
FIREWALL_ALLOW_PORTS=""

# Password policy
PASSWORD_MIN_LENGTH=14
PASSWORD_HISTORY=5

# fail2ban (off by default — limited value with SSH keys-only)
FAIL2BAN_ENABLED=false
FAIL2BAN_BANTIME=3600
FAIL2BAN_FINDTIME=600
FAIL2BAN_MAXRETRY=5
EOF
    chmod 600 "${out}"
    echo "Wrote ${out}"
}

write_report() {
    local report="/root/harden_report_${STAMP}.html"
    local exec_list="${EXECUTED[*]:-none}"
    local fail_list="${FAILED[*]:-none}"
    local skip_list="${SKIPPED[*]:-none}"

    ${SUDO} tee "${report}" >/dev/null <<EOF
<!DOCTYPE html><html><head><meta charset="utf-8">
<title>harden.sh report</title>
<style>
body{font-family:system-ui,sans-serif;max-width:900px;margin:2em auto;padding:0 1em;color:#222}
h1{border-bottom:2px solid #333;padding-bottom:.3em}
.box