#!/bin/bash
dpkg -s auditd || DEBIAN_FRONTEND=noninteractive apt-get -y install auditd
if [ ! -f /etc/audit/rules.d/stig.rules ]; then
    touch /etc/audit/rules.d/stig.rules
fi
egrep -q "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+delete_module\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+module_chng\s*$" /etc/audit/rules.d/stig.rules || echo "-a always,exit -F arch=b32 -S delete_module -F auid>=1000 -F auid!=4294967295 -k module_chng" >> /etc/audit/rules.d/stig.rules
uname -p | grep -q 'x86_64' && ( egrep -q "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+delete_module\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+module_chng\s*$" /etc/audit/rules.d/stig.rules || echo "-a always,exit -F arch=b64 -S delete_module -F auid>=1000 -F auid!=4294967295 -k module_chng" >> /etc/audit/rules.d/stig.rules )
sudo augenrules --load