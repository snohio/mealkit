#!/bin/bash
sudo apt-get install auditd
sudo systemctl enable auditd.service
sudo augenrules --load