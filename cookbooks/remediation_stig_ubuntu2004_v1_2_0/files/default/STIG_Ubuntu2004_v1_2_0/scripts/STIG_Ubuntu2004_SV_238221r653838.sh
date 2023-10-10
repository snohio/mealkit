#!/bin/bash
dpkg -s libpam-pwquality || apt install -y libpam-pwquality
egrep -q '(^#*\s*)ucredit\s*=\s*-*[0-9]+(\s+.*)?$' /etc/security/pwquality.conf && sed -ri 's/(^#*\s*)ucredit\s*=\s*-*[0-9]+(\s+.*)?$/ucredit=-1\2/' /etc/security/pwquality.conf || echo 'ucredit=-1' >> /etc/security/pwquality.conf 