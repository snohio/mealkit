#!/bin/bash
dpkg -s libpam-pwquality || apt install -y libpam-pwquality
egrep -q '(^#*\s*)dcredit\s*=\s*-*[0-9]+(\s+.*)?$' /etc/security/pwquality.conf && sed -ri 's/(^#*\s*)dcredit\s*=\s*-*[0-9]+(\s+.*)?$/dcredit=-1\2/' /etc/security/pwquality.conf || echo 'dcredit=-1' >> /etc/security/pwquality.conf 