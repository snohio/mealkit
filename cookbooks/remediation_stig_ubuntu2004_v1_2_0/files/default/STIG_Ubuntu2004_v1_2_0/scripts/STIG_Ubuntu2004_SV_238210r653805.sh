#!/bin/bash
dpkg -s libpam-pkcs11 || sudo apt-get update && apt install -y libpam-pkcs11
if egrep -q '(^#*\s*)auth\s+[success=2 default=ignore](\s+.*)?$' /etc/pam.d/common-auth
then
    if ! egrep -q '(^#*\s*)auth\s+[success=2 default=ignore](\s+.*)?pam_pkcs11.so(\s+.*)?$' /etc/pam.d/common-auth
    then
        sed -ri 's/(^#*\s*)auth\s+[success=2 default=ignore](\s*.*)?$/auth [success=2 default=ignore] pam_pkcs11.so \2/' /etc/pam.d/common-auth
    fi
else
    echo 'auth [success=2 default=ignore] pam_pkcs11.so' >> /etc/pam.d/common-auth
fi
egrep -q '(^#*\s*)PubkeyAuthentication\s+(yes|no)(\s+.*)?$' /etc/ssh/sshd_config && sed -ri 's/(^#*\s*)PubkeyAuthentication\s+(yes|no)(\s+.*)?$/PubkeyAuthentication yes\3/' /etc/ssh/sshd_config || echo 'PubkeyAuthentication yes' >> /etc/ssh/sshd_config