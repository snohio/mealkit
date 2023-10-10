#!/bin/bash
dpkg -s auditd || DEBIAN_FRONTEND=noninteractive apt-get -y install auditd
test ! -f /etc/audit/rules.d/stig.rules && touch /etc/audit/rules.d/stig.rules
egrep -q '^\s*-w /var/run/wtmp -p wa -k logins' /etc/audit/rules.d/stig.rules; run_wtmp=$?
if [ $run_wtmp -eq 0 ];
then
  echo " $run_wtmp command value is set as expected"
else
  if egrep -q ".\s* /var/run/wtmp" /etc/audit/rules.d/stig.rules; then
    sed -i "s|.*/var/run/wtmp.*|-w /var/run/wtmp -p wa -k logins|g" /etc/audit/rules.d/stig.rules
  else
    echo "-w /var/run/wtmp -p wa -k logins" >> /etc/audit/rules.d/stig.rules
  fi
  sudo augenrules --load
fi