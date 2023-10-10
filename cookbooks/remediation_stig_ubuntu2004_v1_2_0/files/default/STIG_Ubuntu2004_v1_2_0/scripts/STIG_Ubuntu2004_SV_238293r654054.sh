#!/bin/bash
dpkg -s auditd || DEBIAN_FRONTEND=noninteractive apt-get -y install auditd
if [ ! -f /etc/audit/rules.d/stig.rules ]; then
    touch /etc/audit/rules.d/stig.rules
fi
egrep -q '^\s*-a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-crontab' /etc/audit/rules.d/stig.rules; crontab=$?
if [ $crontab -eq 0 ];
then
  echo "rules are set as expected"
else
  echo "-a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-crontab" >> /etc/audit/rules.d/stig.rules
  sudo augenrules --load
fi