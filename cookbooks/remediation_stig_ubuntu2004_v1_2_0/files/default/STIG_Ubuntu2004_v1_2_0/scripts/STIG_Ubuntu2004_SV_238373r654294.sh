#!/bin/bash
sudo chmod 077 /etc/pam.d/login
sudo egrep "^session\s*required\s*pam_lastlog.so\s*showfailed" /etc/pam.d/login || sudo echo -e "session required pam_lastlog.so showfailed" >> /etc/pam.d/login