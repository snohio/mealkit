#!/bin/bash
dpkg -s libpam-pwquality || apt install -y libpam-pwquality
egrep -q '(^#*\s*)dictcheck\s*=\s*[0-9]+(\s+.*)?$' /etc/security/pwquality.conf && sed -ri 's/(^#*\s*)dictcheck\s*=\s*[0-9]+(\s+.*)?$/dictcheck=1\2/' /etc/security/pwquality.conf || echo 'dictcheck=1' >> /etc/security/pwquality.conf 