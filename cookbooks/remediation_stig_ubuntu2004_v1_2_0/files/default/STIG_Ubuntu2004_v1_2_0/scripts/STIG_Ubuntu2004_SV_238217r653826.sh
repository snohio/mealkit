#!/bin/bash
egrep -q '(^#*\s*)Ciphers\s*(\s+.*)?$' /etc/ssh/sshd_config && sed -ri 's/(^#*\s*)Ciphers\s*(\s+.*)?$/Ciphers aes256-ctr,aes192-ctr,aes128-ctr/' /etc/ssh/sshd_config || echo 'Ciphers aes256-ctr,aes192-ctr,aes128-ctr' >> /etc/ssh/sshd_config
sudo systemctl restart sshd.service