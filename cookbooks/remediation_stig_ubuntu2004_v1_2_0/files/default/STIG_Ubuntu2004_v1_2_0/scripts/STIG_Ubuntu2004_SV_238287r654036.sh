#!/bin/bash
dpkg -s auditd || DEBIAN_FRONTEND=noninteractive apt-get -y install auditd
if [ ! -f /etc/audit/rules.d/stig.rules ]; then
    touch /etc/audit/rules.d/stig.rules
fi
egrep -q '^\s*-w /var/log/lastlog -p wa -k logins' /etc/audit/rules.d/stig.rules; lastlog=$?
if [ $lastlog -eq 0 ];
then
  echo "rules are set as expected"
else
  echo "-w /var/log/lastlog -p wa -k logins" >> /etc/audit/rules.d/stig.rules
  sudo augenrules --load
fi