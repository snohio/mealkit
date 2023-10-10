#!/bin/bash
dpkg -s auditd || DEBIAN_FRONTEND=noninteractive apt-get -y install auditd
test ! -f /etc/audit/rules.d/stig.rules && touch /etc/audit/rules.d/stig.rules
egrep -q '^\s*-w /sbin/modprobe -p x -k modules' /etc/audit/rules.d/stig.rules; sbin_modprobe=$?
if [ $sbin_modprobe -eq 0 ];
then
  echo " $sbin_modprobe command value is set as expected"
else
  if egrep -q ".\s* /sbin/modprobe" /etc/audit/rules.d/stig.rules; then
    sed -i "s|.*/sbin/modprobe.*|-w /sbin/modprobe -p x -k modules|g" /etc/audit/rules.d/stig.rules
  else
    echo "-w /sbin/modprobe -p x -k modules" >> /etc/audit/rules.d/stig.rules
  fi
  sudo augenrules --load
fi