#!/bin/bash
if grep -q "^password" /boot/grub/grub.cfg; then
  echo 'Nothing to do, bootloader password is set'
else
  if [ -n $GRUB_PASSWORD ]; then
    encrypted_password="$(echo -e "${GRUB_PASSWORD}\n${GRUB_PASSWORD}" | grub-mkpasswd-pbkdf2 | awk '/grub.pbkdf/{print$NF}')"
    echo "password_pbkdf2 root ${encrypted_password}" >> /etc/grub.d/40_custom
    sudo update-grub 2>/dev/null
  else
    echo 'To configure bootloader password, the following environment variable must be set: $GRUB_PASSWORD'
  fi
fi