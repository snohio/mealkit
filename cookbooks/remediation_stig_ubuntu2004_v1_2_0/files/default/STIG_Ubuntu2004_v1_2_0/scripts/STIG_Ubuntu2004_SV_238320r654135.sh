#!/bin/bash
dpkg -s auditd || DEBIAN_FRONTEND=noninteractive apt-get -y install auditd
test ! -f /etc/audit/rules.d/stig.rules && touch /etc/audit/rules.d/stig.rules
egrep -q '^\s*-w /bin/fdisk -p x -k fdisk' /etc/audit/rules.d/stig.rules; bin_fdisk=$?
if [ $bin_fdisk -eq 0 ];
then
  echo " $bin_fdisk command value is set as expected"
else
  if egrep -q ".\s* /bin/fdisk" /etc/audit/rules.d/stig.rules; then
    sed -i "s|.*/bin/fdisk.*|-w /bin/fdisk -p x -k fdisk|g" /etc/audit/rules.d/stig.rules
  else
    echo "-w /bin/fdisk -p x -k fdisk" >> /etc/audit/rules.d/stig.rules
  fi
  sudo augenrules --load
fi