#!/bin/bash
for user in `awk -F: '($2 == "") { print $1 }' /etc/passwd`; do
  sudo passwd -l user
done