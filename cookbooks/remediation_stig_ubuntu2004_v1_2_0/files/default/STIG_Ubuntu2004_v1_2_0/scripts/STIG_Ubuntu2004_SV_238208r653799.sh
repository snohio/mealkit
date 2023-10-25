#!/bin/bash
sed -ri 's/(^#*\s*)(.*)(NOPASSWD|!authenticate)(.*)$/#\2\3\4/' /etc/sudoers /etc/sudoers.d/*