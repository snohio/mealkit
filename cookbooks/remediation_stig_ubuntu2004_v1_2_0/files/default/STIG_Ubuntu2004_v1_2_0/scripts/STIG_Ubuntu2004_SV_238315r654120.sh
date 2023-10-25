#!/bin/bash
dpkg -s auditd || DEBIAN_FRONTEND=noninteractive apt-get -y install auditd
test ! -f /etc/audit/rules.d/stig.rules && touch /etc/audit/rules.d/stig.rules
egrep -q '^\s*-w /var/log/wtmp -p wa -k logins' /etc/audit/rules.d/stig.rules; log_wtmp=$?
if [ $log_wtmp -eq 0 ];
then
  echo " $log_wtmp command value is set as expected"
else
  if egrep -q ".\s* /var/log/wtmp" /etc/audit/rules.d/stig.rules; then
    sed -i "s|.*/var/log/wtmp.*|-w /var/log/wtmp -p wa -k logins|g" /etc/audit/rules.d/stig.rules
  else
    echo "-w /var/log/wtmp -p wa -k logins" >> /etc/audit/rules.d/stig.rules
  fi
  sudo augenrules --load
fi