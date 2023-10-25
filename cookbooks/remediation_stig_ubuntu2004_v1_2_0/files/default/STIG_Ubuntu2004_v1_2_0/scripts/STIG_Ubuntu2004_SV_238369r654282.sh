#!/bin/bash
if egrep -q "kernel.randomize_va_space" /etc/sysctl.conf; then
  sed -i "s|^kernel.randomize_va_space.*||g" /etc/sysctl.conf
  sudo sysctl --system
fi
for file in /etc/sysctl.d/*.conf; do
  if egrep -q "kernel.randomize_va_space" $file; then
    sed -i "s|^kernel.randomize_va_space.*||g" $file
    sudo sysctl --system
  fi
done 