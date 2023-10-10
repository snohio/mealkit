#!/bin/bash
dpkg -s auditd || DEBIAN_FRONTEND=noninteractive apt-get -y install auditd
test ! -f /etc/audit/rules.d/stig.rules && touch /etc/audit/rules.d/stig.rules
egrep -q "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+execve\s+-C\s+uid!=euid\s+-F\s+euid=0\s+-F\s+key=execpriv\s*$" /etc/audit/rules.d/stig.rules || echo "-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -F key=execpriv" >> /etc/audit/rules.d/stig.rules
uname -p | grep -q 'x86_64' && ( egrep -q "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+execve\s+-C\s+uid!=euid\s+-F\s+euid=0\s+-F\s+key=execpriv\s*$" /etc/audit/rules.d/stig.rules || echo "-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -F key=execpriv" >> /etc/audit/rules.d/stig.rules )
egrep -q "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+execve\s+-C\s+gid!=egid\s+-F\s+egid=0\s+-F\s+key=execpriv\s*$" /etc/audit/rules.d/stig.rules || echo "-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -F key=execpriv" >> /etc/audit/rules.d/stig.rules
uname -p | grep -q 'x86_64' && ( egrep -q "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+execve\s+-C\s+gid!=egid\s+-F\s+egid=0\s+-F\s+key=execpriv\s*$" /etc/audit/rules.d/stig.rules || echo "-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -F key=execpriv" >> /etc/audit/rules.d/stig.rules )
sudo augenrules --load