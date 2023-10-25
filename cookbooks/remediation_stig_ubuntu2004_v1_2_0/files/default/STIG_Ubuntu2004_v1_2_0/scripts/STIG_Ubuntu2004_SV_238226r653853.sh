#!/bin/bash
dpkg -s libpam-pwquality || apt install -y libpam-pwquality
egrep -q '(^#*\s*)ocredit\s*=\s*-*[0-9]+(\s+.*)?$' /etc/security/pwquality.conf && sed -ri 's/(^#*\s*)ocredit\s*=\s*-*[0-9]+(\s+.*)?$/ocredit=-1\2/' /etc/security/pwquality.conf || echo 'ocredit=-1' >> /etc/security/pwquality.conf 