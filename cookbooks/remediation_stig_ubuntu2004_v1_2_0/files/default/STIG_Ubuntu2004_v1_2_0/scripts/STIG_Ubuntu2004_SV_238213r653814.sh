#!/bin/bash
egrep -q '(^#*\s*)ClientAliveInterval\s+[0-9]+(\s+.*)?$' /etc/ssh/sshd_config && sed -ri 's/(^#*\s*)ClientAliveInterval\s+[0-9]+(\s+.*)?$/ClientAliveInterval 600\2/' /etc/ssh/sshd_config || echo 'ClientAliveInterval 600' >> /etc/ssh/sshd_config
sudo systemctl restart sshd.service