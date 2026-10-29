#!/usr/bin/env bash
# ==============================================================================
# Ubuntu/Debian Host & SSH Hardening Script (CIS Benchmark Aligned)
# Author: Rahul Khurana
# Description: Automates SSH daemon lockdown, kernel sysctl network hardening,
#              and least-privilege file permission enforcement on Linux nodes.
# ==============================================================================

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
   echo "[ERROR] This script must be executed with root/sudo privileges."
   exit 1
fi

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
SSHD_CONFIG="/etc/ssh/sshd_config"
SYSCTL_CONF="/etc/sysctl.d/99-secops-hardening.conf"

echo "[INFO] Starting CIS-aligned Linux host hardening ($TIMESTAMP)..."

# 1. Backup existing SSH configuration
cp "$SSHD_CONFIG" "${SSHD_CONFIG}.bak_${TIMESTAMP}"
echo "[INFO] Backed up sshd_config to ${SSHD_CONFIG}.bak_${TIMESTAMP}"

# 2. Enforce SSH Cryptographic & Access Controls (CIS 5.2)
echo "[INFO] Applying strict SSH daemon security parameters..."
sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' "$SSHD_CONFIG"
sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' "$SSHD_CONFIG"
sed -i 's/^#*PermitEmptyPasswords.*/PermitEmptyPasswords no/' "$SSHD_CONFIG"
sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 3/' "$SSHD_CONFIG"
sed -i 's/^#*ClientAliveInterval.*/ClientAliveInterval 300/' "$SSHD_CONFIG"
sed -i 's/^#*ClientAliveCountMax.*/ClientAliveCountMax 2/' "$SSHD_CONFIG"
sed -i 's/^#*X11Forwarding.*/X11Forwarding no/' "$SSHD_CONFIG"

# 3. Kernel Network Stack Hardening via sysctl (CIS 3.1 / 3.2)
echo "[INFO] Configuring kernel network protection parameters..."
cat <<EOF > "$SYSCTL_CONF"
# Enable TCP SYN Cookie Protection against SYN flood attacks
net.ipv4.tcp_syncookies = 1

# Disable IP source routing and ICMP redirects
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0

# Enable Reverse Path Filtering (Anti-Spoofing)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Log Martians (packets with impossible addresses)
net.ipv4.conf.all.log_martians = 1
EOF

sysctl --system > /dev/null

# 4. Enforce Least-Privilege Permissions on Critical Identity Files (CIS 6.1)
echo "[INFO] Locking down permissions on /etc/passwd, /etc/shadow, and /etc/ssh/sshd_config..."
chmod 600 "$SSHD_CONFIG"
chmod 644 /etc/passwd
chmod 640 /etc/shadow
chown root:shadow /etc/shadow

# 5. Validate and Reload SSH Service
if sshd -t; then
    systemctl reload sshd
    echo "[SUCCESS] SSH configuration validated and service reloaded."
else
    echo "[CRITICAL] sshd_config validation failed! Restoring backup..."
    cp "${SSHD_CONFIG}.bak_${TIMESTAMP}" "$SSHD_CONFIG"
    exit 1
fi

echo "[SUCCESS] Host hardening completed successfully."
