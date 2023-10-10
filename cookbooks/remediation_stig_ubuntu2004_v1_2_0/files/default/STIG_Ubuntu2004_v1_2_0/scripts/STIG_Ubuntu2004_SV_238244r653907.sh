#!/bin/bash
dpkg -s auditd || DEBIAN_FRONTEND=noninteractive apt-get -y install auditd
egrep -q "^(\s*)disk_full_action\s*=\s*\S+(\s*#.*)?\s*$" /etc/audit/auditd.conf && sed -ri "s/^(\s*)disk_full_action\s*=\s*\S+(\s*#.*)?\s*$/\1disk_full_action = HALT\2/" /etc/audit/auditd.conf || echo "disk_full_action = HALT" >> /etc/audit/auditd.conf
sudo systemctl restart auditd.service