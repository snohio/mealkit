#!/bin/bash
dpkg -s libpam-pwquality || sudo apt-get update && apt install -y libpam-pwquality
egrep -q '(^#*\s*)minlen\s*=\s*-*[0-9]+(\s+.*)?$' /etc/security/pwquality.conf && sed -ri 's/(^#*\s*)minlen\s*=\s*-*[0-9]+(\s+.*)?$/minlen=15\2/' /etc/security/pwquality.conf || echo 'minlen=15' >> /etc/security/pwquality.conf