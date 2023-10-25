#!/bin/bash
dpkg -s chrony || DEBIAN_FRONTEND=noninteractive apt-get -y install chrony
if egrep -q "makestep" /etc/chrony/chrony.conf; then
  if egrep -q "#makestep" /etc/chrony/chrony.conf; then
    sed -i "s|^#makestep.*|makestep 1 -1|g" /etc/chrony/chrony.conf
  else
    sed -i "s|^makestep.*|makestep 1 -1|g" /etc/chrony/chrony.conf
  fi
else
  echo 'makestep 1 -1' >> /etc/chrony/chrony.conf
fi