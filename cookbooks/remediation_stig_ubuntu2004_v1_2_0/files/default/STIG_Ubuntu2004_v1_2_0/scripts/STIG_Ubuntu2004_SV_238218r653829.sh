#!/bin/bash
egrep -q '(^#*\s*)PermitEmptyPasswords\s+(yes|no)(\s+.*)?$' /etc/ssh/sshd_config && sed -ri 's/(^#*\s*)PermitEmptyPasswords\s+(yes|no)(\s+.*)?$/PermitEmptyPasswords no\3/' /etc/ssh/sshd_config || echo 'PermitEmptyPasswords no' >> /etc/ssh/sshd_config 
egrep -q '(^#*\s*)PermitUserEnvironment\s+(yes|no)(\s+.*)?$' /etc/ssh/sshd_config && sed -ri 's/(^#*\s*)PermitUserEnvironment\s+(yes|no)(\s+.*)?$/PermitUserEnvironment no\3/' /etc/ssh/sshd_config || echo 'PermitUserEnvironment no' >> /etc/ssh/sshd_config 
sudo systemctl restart sshd.service