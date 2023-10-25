#!/bin/bash
sudo dpkg -l | grep aide || sudo DEBIAN_FRONTEND=noninteractive apt-get -yq install aide