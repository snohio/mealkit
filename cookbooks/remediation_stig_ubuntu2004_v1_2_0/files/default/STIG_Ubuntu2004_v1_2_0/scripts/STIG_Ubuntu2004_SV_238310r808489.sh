#!/bin/bash
dpkg -s auditd || DEBIAN_FRONTEND=noninteractive apt-get -y install auditd
test ! -f /etc/audit/rules.d/stig.rules && touch /etc/audit/rules.d/stig.rules
egrep -q "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+unlink,unlinkat,rename,renameat,rmdir\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+delete\s*$" /etc/audit/rules.d/stig.rules || echo "-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat,rmdir -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/stig.rules
uname -p | grep -q 'x86_64' && ( egrep -q "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+unlink,unlinkat,rename,renameat,rmdir\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+delete\s*$" /etc/audit/rules.d/stig.rules || echo "-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat,rmdir -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/stig.rules )
sudo augenrules --load