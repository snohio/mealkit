#!/bin/bash
dpkg -s auditd || DEBIAN_FRONTEND=noninteractive apt-get -y install auditd
if [ ! -f /etc/audit/rules.d/stig.rules ]; then
    touch /etc/audit/rules.d/stig.rules
fi
egrep "^-w\s+/etc/security/opasswd\s+-p\s+wa\s+-k\s+usergroup_modification\s*$" /etc/audit/rules.d/stig.rules || echo "-w /etc/security/opasswd -p wa -k usergroup_modification" >> /etc/audit/rules.d/stig.rules
sudo augenrules --load