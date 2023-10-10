#!/bin/bash
if egrep -q "^net\.ipv4\.tcp_syncookies" /etc/sysctl.conf; then
    sed -i "s|*.net\.ipv4\.tcp_syncookies.*|net.ipv4.tcp_syncookies=1|g" /etc/sysctl.conf
else
  echo 'net.ipv4.tcp_syncookies = 1' >> /etc/sysctl.conf
fi
sudo sysctl -w net.ipv4.tcp_syncookies=1;