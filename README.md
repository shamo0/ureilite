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
git clone https://github.com/shamo0/ureilite
cd ureilite
```

2. Make the script executable:

```chmod +x harden.sh```



## Running the Script

After ensuring you have the prerequisites and have made the script executable, you can run the script using:

```sudo ./harden.sh```

The script will perform the following actions:

- Update and upgrade the system packages.
- Install necessary security tools.
- Initialize and configure AIDE.
- Harden SSH configuration.
- Set sysctl parameters for kernel hardening.
- Configure UFW for firewall settings.
- Set up auditd for logging.
- Add legal banners for unauthorized access warning.
