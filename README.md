# PCI DSS Compliance Script
This repository contains a script designed to enhance the security and compliance of an Ubuntu system to meet PCI DSS requirements. The script automates various security configurations and installations based on the results of a Lynis audit.

Features
- Automates security configurations to meet PCI DSS requirements.
- Installs necessary security tools such as AIDE, Rootkit Hunter, and PAM modules.
- Configures SSH settings to enhance security.
- Updates system kernel and packages to ensure the latest security patches are applied.
- Sets up iptables rules to configure a host-based firewall.
- Configures sysctl parameters to harden the kernel.
- Adds legal banners to warn unauthorized users.
- Configures auditd for auditing and logging.
- Prerequisites
- Ubuntu 20.04 or higher (Tested on Ubuntu 24.04 LTS)
- Root or sudo privileges
- Installation

1. Clone the repository:

```
git clone https://github.com/yourusername/pci-dss-compliance-script.git
cd pci-dss-compliance-script
```

2. Make the script executable:

```chmod +x pci_dss_compliance.sh```

3. Run the script:

```sudo ./pci_dss_compliance.sh```

## Script Contents

```
#!/bin/bash

# Update and upgrade the system
sudo apt-get update -y && sudo apt-get upgrade -y

# Install necessary tools
sudo apt-get install -y aide rkhunter libpam-cracklib ufw apt-show-versions

# Initialize AIDE
sudo aideinit && sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# Configure SSH settings
sudo sed -i 's/#Port 22/Port 2222/' /etc/ssh/sshd_config
sudo sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config
sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo sed -i 's/#AllowTcpForwarding yes/AllowTcpForwarding no/' /etc/ssh/sshd_config
sudo sed -i 's/#MaxAuthTries 6/MaxAuthTries 3/' /etc/ssh/sshd_config
sudo sed -i 's/#MaxSessions 10/MaxSessions 2/' /etc/ssh/sshd_config
sudo sed -i 's/#LogLevel INFO/LogLevel VERBOSE/' /etc/ssh/sshd_config
sudo sed -i 's/#TCPKeepAlive yes/TCPKeepAlive no/' /etc/ssh/sshd_config
sudo sed -i 's/#X11Forwarding yes/X11Forwarding no/' /etc/ssh/sshd_config
sudo sed -i 's/#AllowAgentForwarding yes/AllowAgentForwarding no/' /etc/ssh/sshd_config
sudo systemctl restart sshd

# Configure sysctl parameters
sudo bash -c 'cat >> /etc/sysctl.conf <<EOL
kernel.core_uses_pid = 1
kernel.kptr_restrict = 2
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
EOL'
sudo sysctl -p

# Configure UFW
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 2222/tcp
sudo ufw enable

# Configure auditd
sudo apt-get install -y auditd
sudo systemctl enable auditd
sudo systemctl start auditd

# Configure AIDE
sudo aide --init && sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# Configure rkhunter
sudo rkhunter --update
sudo rkhunter --propupd

# Set up legal banners

echo "Authorized users only. All activity may be monitored and reported." | sudo tee /etc/issue
echo "Authorized users only. All activity may be monitored and reported." | sudo tee /etc/issue.net

echo "PCI DSS Compliance Script completed successfully!"
```
## Running the Script

After ensuring you have the prerequisites and have made the script executable, you can run the script using:

```sudo ./pci_dss_compliance.sh```

The script will perform the following actions:

- Update and upgrade the system packages.
- Install necessary security tools.
- Initialize and configure AIDE.
- Harden SSH configuration.
- Set sysctl parameters for kernel hardening.
- Configure UFW for firewall settings.
- Set up auditd for logging.
- Add legal banners for unauthorized access warning.
