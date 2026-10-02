#!/bin/bash
# basic-harden.sh - Foundational Ubuntu Server Hardening
# Run as root on a fresh Ubuntu 22.04/24.04 server
# REVIEW EVERY LINE BEFORE EXECUTION

set -e  # Exit on error

echo "=== Starting foundational hardening ==="

# --- 1. System Updates & Unattended Upgrades ---
echo "[*] Configuring automatic security updates..."
apt-get update
apt-get install -y unattended-upgrades apt-listchanges
dpkg-reconfigure -plow unattended-upgrades

# --- 2. SSH Hardening ---
echo "[*] Hardening SSH configuration..."
SSHD_CONFIG="/etc/ssh/sshd_config"

# Backup original
cp "$SSHD_CONFIG" "${SSHD_CONFIG}.bak.$(date +%s)"

# Apply hardened settings
sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' "$SSHD_CONFIG"
sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' "$SSHD_CONFIG"
sed -i 's/^#*PermitEmptyPasswords.*/PermitEmptyPasswords no/' "$SSHD_CONFIG"
sed -i 's/^#*X11Forwarding.*/X11Forwarding no/' "$SSHD_CONFIG"
sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 4/' "$SSHD_CONFIG"
sed -i 's/^#*ClientAliveInterval.*/ClientAliveInterval 300/' "$SSHD_CONFIG"
sed -i 's/^#*ClientAliveCountMax.*/ClientAliveCountMax 2/' "$SSHD_CONFIG"

# Ensure settings exist even if not previously present
grep -q "^PermitRootLogin" "$SSHD_CONFIG" || echo "PermitRootLogin no" >> "$SSHD_CONFIG"
grep -q "^PasswordAuthentication" "$SSHD_CONFIG" || echo "PasswordAuthentication no" >> "$SSHD_CONFIG"
grep -q "^PermitEmptyPasswords" "$SSHD_CONFIG" || echo "PermitEmptyPasswords no" >> "$SSHD_CONFIG"

# WARNING: Password auth is now disabled. Ensure your SSH keys are working
# before you close this session, or you will be locked out.

systemctl restart sshd

# --- 3. Kernel & Network Hardening (sysctl) ---
echo "[*] Applying kernel hardening parameters..."
SYSCTL_FILE="/etc/sysctl.d/99-hardening.conf"

cat > "$SYSCTL_FILE" << 'EOF'
# Network Security
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

# Memory/Process Protection
kernel.randomize_va_space = 2
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1
fs.suid_dumpable = 0
kernel.core_pattern = /dev/null
EOF

sysctl -p "$SYSCTL_FILE"

# --- 4. Firewall (UFW) ---
echo "[*] Configuring UFW firewall..."
apt-get install -y ufw

# Default policies: deny incoming, allow outgoing
ufw default deny incoming
ufw default allow outgoing

# Allow SSH (critical - do this before enabling)
ufw allow 22/tcp

# Enable without prompting
echo "y" | ufw enable

# --- 5. Account & Password Policies ---
echo "[*] Setting password policies..."

# Password aging in login.defs
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   365/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs

# Ensure SHA-512 hashing
grep -q "^ENCRYPT_METHOD" /etc/login.defs && \
  sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/' /etc/login.defs || \
  echo "ENCRYPT_METHOD SHA512" >> /etc/login.defs

# Login banner
echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue
echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue.net
cp /etc/issue /etc/motd

# --- 6. Remove Unnecessary Services ---
echo "[*] Removing unnecessary services..."
apt-get purge -y avahi-daemon cups isc-dhcp-server rpcbind rsync snmpd 2>/dev/null || true

# --- 7. Audit Logging ---
echo "[*] Installing and configuring auditd..."
apt-get install -y auditd
systemctl enable --now auditd

# --- 8. Disable Unused Filesystems ---
echo "[*] Disabling unused filesystem modules..."
cat > /etc/modprobe.d/hardening-filesystems.conf << 'EOF'
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install udf /bin/true
EOF

# --- 9. Secure Permissions ---
echo "[*] Setting secure file permissions..."
chmod 600 /etc/ssh/sshd_config
chmod 644 /etc/passwd
chmod 640 /etc/shadow
chmod 644 /etc/group

echo ""
echo "=== Basic hardening complete ==="
echo ""
echo "IMPORTANT:"
echo "1. SSH password authentication is now DISABLED."
echo "   Verify your key-based access works before closing this session."
echo "2. UFW is enabled with only SSH (22/tcp) allowed."
echo "3. Review /etc/ssh/sshd_config and the backup file for details."
echo "4. Run 'lynis audit system' to see your hardening index and remaining gaps."