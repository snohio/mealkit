#!/bin/bash
dpkg -s auditd || DEBIAN_FRONTEND=noninteractive apt-get -y install auditd
test ! -f /etc/audit/rules.d/stig.rules && touch /etc/audit/rules.d/stig.rules
egrep -q '^\s*-w /bin/kmod -p x -k modules' /etc/audit/rules.d/stig.rules; bin_kmod=$?
if [ $bin_kmod -eq 0 ];
then
  echo " $bin_kmod command value is set as expected"
else
  if egrep -q ".\s* /bin/kmod" /etc/audit/rules.d/stig.rules; then
    sed -i "s|.*/bin/kmod.*|-w /bin/kmod -p x -k modules|g" /etc/audit/rules.d/stig.rules
  else
    echo "-w /bin/kmod -p x -k modules " >> /etc/audit/rules.d/stig.rules
  fi
  sudo augenrules --load
fi