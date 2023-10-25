#!/bin/bash
egrep -q '(^#*\s*)ClientAliveCountMax\s+[0-9]+(\s+.*)?$' /etc/ssh/sshd_config && sed -ri 's/(^#*\s*)ClientAliveCountMax\s+[0-9]+(\s+.*)?$/ClientAliveCountMax 1\2/' /etc/ssh/sshd_config || echo 'ClientAliveCountMax 1' >> /etc/ssh/sshd_config
sudo systemctl restart sshd.service