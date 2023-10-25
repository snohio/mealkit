#!/bin/bash
grep usb-storage /etc/modprobe.d/* | grep "/bin/true" || sudo touch /etc/modprobe.d/DISASTIG.conf && sudo su -c "echo install usb-storage /bin/true >> /etc/modprobe.d/DISASTIG.conf"
grep usb-storage /etc/modprobe.d/* | grep -i "blacklist" || sudo touch /etc/modprobe.d/DISASTIG.conf && sudo su -c "echo blacklist usb-storage >> /etc/modprobe.d/DISASTIG.conf"