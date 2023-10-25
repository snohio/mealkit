#!/bin/bash
dpkg -s libpam-pwquality || apt install -y libpam-pwquality
egrep -q '(^#*\s*)lcredit\s*=\s*-*[0-9]+(\s+.*)?$' /etc/security/pwquality.conf && sed -ri 's/(^#*\s*)lcredit\s*=\s*-*[0-9]+(\s+.*)?$/lcredit=-1\2/' /etc/security/pwquality.conf || echo 'lcredit=-1' >> /etc/security/pwquality.conf 