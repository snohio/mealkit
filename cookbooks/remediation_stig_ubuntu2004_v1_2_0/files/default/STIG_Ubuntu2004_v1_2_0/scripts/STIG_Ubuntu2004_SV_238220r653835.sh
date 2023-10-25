#!/bin/bash
egrep -q '(^#*\s*)X11UseLocalhost\s+(yes|no)(\s+.*)?$' /etc/ssh/sshd_config && sed -ri 's/(^#*\s*)X11UseLocalhost\s+(yes|no)(\s+.*)?$/X11UseLocalhost yes\3/' /etc/ssh/sshd_config || echo 'X11UseLocalhost yes' >> /etc/ssh/sshd_config 
sudo systemctl restart sshd.service