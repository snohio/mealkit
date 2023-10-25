#!/bin/bash
egrep -q '(^#*\s*)MACs\s*(\s+.*)?$' /etc/ssh/sshd_config && sed -ri 's/(^#*\s*)MACs\s*(\s+.*)?$/MACs hmac-sha2-512,hmac-sha2-256/' /etc/ssh/sshd_config || echo 'MACs hmac-sha2-512,hmac-sha2-256' >> /etc/ssh/sshd_config 
sudo systemctl restart sshd.service