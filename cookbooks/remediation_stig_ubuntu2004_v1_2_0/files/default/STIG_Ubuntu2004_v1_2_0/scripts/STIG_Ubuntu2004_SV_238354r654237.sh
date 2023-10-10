#!/bin/bash
dpkg -s ufw || DEBIAN_FRONTEND=noninteractive apt-get -y install ufw