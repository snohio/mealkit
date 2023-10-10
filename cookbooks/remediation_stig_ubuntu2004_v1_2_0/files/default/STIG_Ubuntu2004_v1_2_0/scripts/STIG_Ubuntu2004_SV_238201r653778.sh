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
if egrep -q '(^#*\s*)use_mappers\s*=(\s*.*)?$' /etc/pam_pkcs11/pam_pkcs11.conf
then
    if egrep -q '(^#*\s*)use_mappers\s*=(\s*.*)?null(\s*.*)?$' /etc/pam_pkcs11/pam_pkcs11.conf
    then
        if egrep -q '(^#*\s*)use_mappers\s*=(\s*.*)?pwent(\s*.*)?$' /etc/pam_pkcs11/pam_pkcs11.conf
        then
            sed -ri 's/(^#*\s*)use_mappers\s*=(\s*.*)?null(\s*.*)?pwent(\s*.*)?$/use_mappers=\2pwent\3null\4/' /etc/pam_pkcs11/pam_pkcs11.conf
        else
            sed -ri 's/(^#*\s*)use_mappers\s*=(\s*.*)?null(\s*.*)?$/use_mappers=\2pwent, null\3/' /etc/pam_pkcs11/pam_pkcs11.conf
        fi
    else
        if ! egrep -q '(^#*\s*)use_mappers\s*=(\s*.*)?pwent(\s*.*)?$' /etc/pam_pkcs11/pam_pkcs11.conf
        then
            sed -ri 's/(^#*\s*)use_mappers\s*=(\s*.*)?$/use_mappers=pwent,\2/' /etc/pam_pkcs11/pam_pkcs11.conf
        fi
    fi
else
    echo 'use_mappers=pwent;' >> /etc/pam_pkcs11/pam_pkcs11.conf
fi