#!/bin/bash
sudo chmod 077 /etc/pam.d/common-auth
sudo egrep "^auth \s*required\s*pam_faildelay.so\s*delay\s*=\s*[4-9]|\d{6,}\." /etc/pam.d/common-auth || sudo echo -e "auth required pam_faildelay.so delay=4000000" >> /etc/pam.d/common-auth