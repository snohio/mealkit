#!/bin/bash
if egrep -q "^X11Forwarding" /etc/ssh/sshd_config; then
  if egrep -q "^#X11Forwarding" /etc/ssh/sshd_config; then
    echo 'X11Forwarding no' >> /etc/ssh/sshd_config
  else
    sed -i "s|^X11Forwarding|X11Forwarding no|g" /etc/ssh/sshd_config
  fi
else
  echo 'X11Forwarding no' >> /etc/ssh/sshd_config
fi
sudo systemctl restart sshd.service