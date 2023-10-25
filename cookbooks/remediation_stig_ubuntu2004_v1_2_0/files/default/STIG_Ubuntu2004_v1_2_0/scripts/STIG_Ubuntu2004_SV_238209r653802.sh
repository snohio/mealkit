#!/bin/bash
egrep -q '(^#*\s*)UMASK\s+[0-9]+(\s+.*)?$' /etc/login.defs && sed -ri 's/(^#*\s*)UMASK\s+[0-9]+(\s+.*)?$/UMASK 077\2/' /etc/login.defs || echo 'UMASK 077' >> /etc/login.defs