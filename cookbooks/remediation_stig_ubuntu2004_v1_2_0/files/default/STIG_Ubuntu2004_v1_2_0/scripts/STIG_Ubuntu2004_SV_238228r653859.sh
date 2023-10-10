#!/bin/bash
dpkg -s libpam-pwquality || apt install -y libpam-pwquality
egrep -q '(^#*\s*)enforcing\s*=\s*[0-9]+(\s+.*)?$' /etc/security/pwquality.conf && sed -ri 's/(^#*\s*)enforcing\s*=\s*[0-9]+(\s+.*)?$/enforcing = 1\2/' /etc/security/pwquality.conf || echo 'enforcing = 1' >> /etc/security/pwquality.conf 
egrep -q '(^#*\s*)password requisite pam_pwquality\.so retry\s*=\s*[0-9]+(\s+.*)?$' /etc/pam.d/common-password && sed -ri 's/(^#*\s*)password requisite pam_pwquality\.so retry\s*=\s*(\s+.*)?$/password requisite pam_pwquality\.so retry=\2/' /etc/pam.d/common-password || echo 'password requisite pam_pwquality.so retry=3' >> /etc/pam.d/common-password
egrep -q '(^#*\s*)password requisite pam_pwquality\.so retry\s*=\s*[0-9]+(\s+.*)?$' /etc/pam.d/common-password && sed -ri 's/(^#*\s*)password requisite pam_pwquality\.so retry\s*=\s*(0|[4-9]|[0-9]{2,})(\s+.*)?$/password requisite pam_pwquality\.so retry=3\3/' /etc/pam.d/common-password || echo 'password requisite pam_pwquality.so retry=3' >> /etc/pam.d/common-password