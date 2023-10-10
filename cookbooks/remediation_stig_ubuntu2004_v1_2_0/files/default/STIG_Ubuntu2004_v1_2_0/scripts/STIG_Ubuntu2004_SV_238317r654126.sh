#!/bin/bash
dpkg -s auditd || DEBIAN_FRONTEND=noninteractive apt-get -y install auditd
test ! -f /etc/audit/rules.d/stig.rules && touch /etc/audit/rules.d/stig.rules
egrep -q '^\s*-w /var/log/btmp -p wa -k logins' /etc/audit/rules.d/stig.rules; log_btmp=$?
if [ $log_btmp -eq 0 ];
then
  echo " $log_btmp command value is set as expected"
else
  if egrep -q ".\s* /var/log/btmp" /etc/audit/rules.d/stig.rules; then
    sed -i "s|.*/var/log/btmp.*|-w /var/log/btmp -p wa -k logins|g" /etc/audit/rules.d/stig.rules
  else
    echo "-w /var/log/btmp -p wa -k logins" >> /etc/audit/rules.d/stig.rules
  fi
  sudo augenrules --load
fi