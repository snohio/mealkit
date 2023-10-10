#!/bin/bash
dpkg -s libpam-pwquality || sudo apt-get update && apt install -y libpam-pwquality
egrep -q '(^#*\s*)difok\s*=\s*-*[0-9]+(\s+.*)?$' /etc/security/pwquality.conf && sed -ri 's/(^#*\s*)difok\s*=\s*-*[0-9]+(\s+.*)?$/difok=8\2/' /etc/security/pwquality.conf || echo 'difok=8' >> /etc/security/pwquality.conf