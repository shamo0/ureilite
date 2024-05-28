#!/bin/bash

# Function to update the system
update_system() {
    echo "Updating system..."
    apt-get update -y && apt-get upgrade -y
}

# Function to disable core dumps
disable_core_dumps() {
    echo "Disabling core dumps..."
    echo "* hard core 0" >> /etc/security/limits.conf
}

# Function to configure password hashing rounds
configure_password_hashing() {
    echo "Configuring password hashing rounds..."
    echo "PASS_MAX_DAYS 90" >> /etc/login.defs
    echo "PASS_MIN_DAYS 7" >> /etc/login.defs
    echo "PASS_WARN_AGE 14" >> /etc/login.defs
}

# Function to install PAM modules for password strength testing
install_pam_modules() {
    echo "Installing PAM modules..."
    apt-get install -y libpam-cracklib
    echo "password requisite pam_cracklib.so retry=3 minlen=8 difok=3" >> /etc/pam.d/common-password
}

# Function to enforce minimum and maximum password age
enforce_password_age() {
    echo "Enforcing password aging..."
    echo "PASS_MAX_DAYS 90" >> /etc/login.defs
    echo "PASS_MIN_DAYS 7" >> /etc/login.defs
    echo "PASS_WARN_AGE 14" >> /etc/login.defs
}

# Function to set default umask values
set_umask() {
    echo "Setting default umask..."
    echo "UMASK 027" >> /etc/login.defs
    echo "umask 027" >> /etc/profile
    echo "umask 027" >> /etc/bash.bashrc
}

# Function to harden SSH configuration
harden_ssh() {
    echo "Hardening SSH configuration..."
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/#MaxAuthTries 6/MaxAuthTries 3/' /etc/ssh/sshd_config
    sed -i 's/#ClientAliveInterval 0/ClientAliveInterval 300/' /etc/ssh/sshd_config
    sed -i 's/#ClientAliveCountMax 3/ClientAliveCountMax 0/' /etc/ssh/sshd_config
    echo "AllowUsers youruser" >> /etc/ssh/sshd_config
    sed -i 's/#AllowTcpForwarding yes/AllowTcpForwarding no/' /etc/ssh/sshd_config
    sed -i 's/#LogLevel INFO/LogLevel VERBOSE/' /etc/ssh/sshd_config
    sed -i 's/#MaxSessions 10/MaxSessions 2/' /etc/ssh/sshd_config
    sed -i 's/#TCPKeepAlive yes/TCPKeepAlive no/' /etc/ssh/sshd_config
    sed -i 's/#X11Forwarding yes/X11Forwarding no/' /etc/ssh/sshd_config
    sed -i 's/#AllowAgentForwarding yes/AllowAgentForwarding no/' /etc/ssh/sshd_config
    systemctl restart sshd
}

# Function to configure sysctl parameters
configure_sysctl() {
    echo "Configuring sysctl parameters..."
    cat <<EOF >> /etc/sysctl.conf
kernel.core_uses_pid = 1
kernel.kptr_restrict = 2
kernel.randomize_va_space = 2
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.default.log_martians = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.tcp_syncookies = 1
EOF
    sysctl -p
}

# Function to restrict file permissions
restrict_file_permissions() {
    echo "Restricting file permissions..."
    chmod 600 /etc/crontab
    chmod 600 /etc/cron.hourly
    chmod 600 /etc/cron.daily
    chmod 600 /etc/cron.weekly
    chmod 600 /etc/cron.monthly
    chmod 600 /etc/cron.d
    chmod 600 /etc/ssh/sshd_config
}

# Function to install PCI DSS packages
install_pci_dss_packages() {
    echo "Installing packages required for PCI DSS compliance..."
    apt-get install -y auditd audispd-plugins
    apt-get install -y ufw
    apt-get install -y aide
}

# Function to configure auditd
configure_auditd() {
    echo "Configuring auditd..."
    cat <<EOF >> /etc/audit/rules.d/audit.rules
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -k time-change
EOF
    systemctl restart auditd
}

# Function to configure the firewall
configure_firewall() {
    echo "Configuring firewall..."
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh
    ufw enable
}

# Function to disable USB storage
disable_usb_storage() {
    echo "Disabling USB storage..."
    echo "install usb-storage /bin/true" >> /etc/modprobe.d/blacklist.conf
}

# Function to set legal banners
set_legal_banners() {
    echo "Setting legal banners..."
    echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue
    echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue.net
}

# Function to configure log forwarding
configure_log_forwarding() {
    echo "Configuring log forwarding..."
    echo "*.* @@logserver.example.com:514" >> /etc/rsyslog.conf
    systemctl restart rsyslog
}

# Function to install file integrity tools
install_file_integrity_tools() {
    echo "Installing file integrity tools..."
    apt-get install -y aide
    aideinit
    mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
}

# Function to disable unnecessary services
disable_unnecessary_services() {
    echo "Disabling unnecessary services..."
    systemctl disable avahi-daemon
    systemctl disable cups
    systemctl disable isc-dhcp-server
    systemctl disable isc-dhcp-server6
    systemctl disable slapd
    systemctl disable nfs-server
    systemctl disable rpcbind
    systemctl disable bind9
    systemctl disable vsftpd
    systemctl disable apache2
    systemctl disable dovecot
    systemctl disable smb
    systemctl disable squid
    systemctl disable snmpd
}

# Function to configure hosts
configure_hosts() {
    echo "Configuring /etc/hosts..."
    sed -i '/^127.0.0.1/d' /etc/hosts
    echo "127.0.0.1 localhost" >> /etc/hosts
    hostname=$(hostname)
    echo "127.0.1.1 $hostname" >> /etc/hosts
}

# Function to configure postfix
configure_postfix() {
    echo "Configuring postfix..."
    postconf -e "smtpd_banner = \$myhostname ESMTP"
    postconf -e "disable_vrfy_command = yes"
    systemctl restart postfix
}

# Function to enable accounting
enable_accounting() {
    echo "Enabling accounting..."
    apt-get install -y acct
    systemctl enable acct
    systemctl start acct
}

# Function to install malware scanner
install_malware_scanner() {
    echo "Installing malware scanner..."
    apt-get install -y rkhunter
    rkhunter --update
    rkhunter --propupd
    echo "0 0 * * * root rkhunter --check --cronjob" >> /etc/crontab
}

# Main script execution
main() {
    update_system
    disable_core_dumps
    configure_password_hashing
    install_pam_modules
    enforce_password_age
    set_umask
    harden_ssh
    configure_sysctl
    restrict_file_permissions
    install_pci_dss_packages
    configure_auditd
    configure_firewall
    disable_usb_storage
    set_legal_banners
    configure_log_forwarding
    install_file_integrity_tools
    disable_unnecessary_services
    configure_hosts
    configure_postfix
    enable_accounting
    install_malware_scanner
}

main
