#!/bin/bash
sudo find /var/log -perm /137 -type f -exec chmod 640 '{}' \;