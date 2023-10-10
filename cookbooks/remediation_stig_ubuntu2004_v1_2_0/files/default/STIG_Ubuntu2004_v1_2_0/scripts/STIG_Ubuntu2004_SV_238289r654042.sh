#!/bin/bash
dpkg -s auditd || DEBIAN_FRONTEND=noninteractive apt-get -y install auditd
if [ ! -f /etc/audit/rules.d/stig.rules ]; then
    touch /etc/audit/rules.d/stig.rules
fi
egrep -q '^\s*-a always,exit -F path=/sbin/unix_update -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-unix-update' /etc/audit/rules.d/stig.rules; unix_update=$?
if [ $unix_update -eq 0 ];
then
  echo "rules are set as expected"
else
  echo "-a always,exit -F path=/sbin/unix_update -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-unix-update" >> /etc/audit/rules.d/stig.rules
  sudo augenrules --load
fi