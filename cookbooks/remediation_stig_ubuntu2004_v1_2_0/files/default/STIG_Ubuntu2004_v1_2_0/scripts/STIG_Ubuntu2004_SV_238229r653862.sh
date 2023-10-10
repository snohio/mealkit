#!/bin/bash
if [ ! -d /etc/pam_pkcs11 ]; then
    mkdir /etc/pam_pkcs11
fi
if [ ! -f /etc/pam_pkcs11/pam_pkcs11.conf ]
then
    if [ -f /usr/share/doc/libpam-pkcs11/examples/pam_pkcs11.conf.example ]
    then
        cp /usr/share/doc/libpam-pkcs11/examples/pam_pkcs11.conf.example /etc/pam_pkcs11/pam_pkcs11.conf
    else
        touch /etc/pam_pkcs11/pam_pkcs11.conf
    fi
fi
if egrep -q '(^#*\s*)cert_policy\s*=(\s*.*)?$' /etc/pam_pkcs11/pam_pkcs11.conf
then
    sed -ri 's/(^#*\s*)cert_policy\s*=(\s*.*)?none(\s*.*)?$/cert_policy=\2\3/' /etc/pam_pkcs11/pam_pkcs11.conf
    sed -ri 's/(^#*\s*)cert_policy\s*=\s*(\s*[a-z_]*)(,*)ca(,*)(\s*.*)$/cert_policy=\2\5/' /etc/pam_pkcs11/pam_pkcs11.conf
    sed -ri 's/(^#*\s*)cert_policy\s*=(\s*.*)?$/cert_policy= ca,\2/' /etc/pam_pkcs11/pam_pkcs11.conf
    sed -ri 's/(^#*\s*)cert_policy\s*=(.*),\s*;$/cert_policy= \2;/' /etc/pam_pkcs11/pam_pkcs11.conf
else
    echo 'cert_policy= ca,signature,ocsp_on;' >> /etc/pam_pkcs11/pam_pkcs11.conf
fi