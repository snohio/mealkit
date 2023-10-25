#!/bin/bash
sudo apt-get update && sudo apt-get install auditd audispd-plugins -y
sudo test -f /etc/audit/rules.d/stig.rules || sudo touch /etc/audit/rules.d/stig.rules
sudo chmod -R a+X /etc
sudo chmod 777 /etc/audit/rules.d/stig.rules
sudo egrep "^-w\s+/etc/passwd\s+-p\s+wa\s+-k\s+usergroup_modification\s*$" /etc/audit/rules.d/stig.rules || sudo echo "-w /etc/passwd -p wa -k usergroup_modification" >> /etc/audit/rules.d/stig.rules
sudo augenrules --load