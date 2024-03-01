#!/bin/bash
export CHEF_PROFILE=tandori
knife bootstrap node-linux-03 -N node-linux-03 -x ubuntu -i ~/.ssh/sys_admin.pem --sudo -y
knife bootstrap node-linux-04 -N node-linux-04 -x ubuntu -i ~/.ssh/sys_admin.pem --sudo -y
knife client list
export CHEF_PROFILE=pizza
knife bootstrap node-linux-05 -N node-linux-05 -x ubuntu -i ~/.ssh/sys_admin.pem --sudo -y
knife bootstrap node-linux-06 -N node-linux-06 -x ubuntu -i ~/.ssh/sys_admin.pem --sudo -y
knife client list
export CHEF_PROFILE=potpie
knife bootstrap node-linux-07 -N node-linux-07 -x ubuntu -i ~/.ssh/sys_admin.pem --sudo -y
knife bootstrap node-linux-08 -N node-linux-08 -x ubuntu -i ~/.ssh/sys_admin.pem --sudo -y
knife client list
export CHEF_PROFILE=meatloaf
knife bootstrap node-linux-09 -N node-linux-09 -x ubuntu -i ~/.ssh/sys_admin.pem --sudo -y
knife bootstrap node-linux-10 -N node-linux-10 -x ubuntu -i ~/.ssh/sys_admin.pem --sudo -y
knife client list
export CHEF_PROFILE=quesadilla
knife bootstrap node-linux-11 -N node-linux-11 -x ubuntu -i ~/.ssh/sys_admin.pem --sudo -y
knife bootstrap node-linux-12 -N node-linux-12 -x ubuntu -i ~/.ssh/sys_admin.pem --sudo -y
knife client list
export CHEF_PROFILE=chili
knife bootstrap node-linux-13 -N node-linux-13 -x ubuntu -i ~/.ssh/sys_admin.pem --sudo -y
knife bootstrap node-linux-14 -N node-linux-14 -x ubuntu -i ~/.ssh/sys_admin.pem --sudo -y
knife client list
export CHEF_PROFILE=casserole
knife bootstrap node-linux-15 -N node-linux-15 -x ubuntu -i ~/.ssh/sys_admin.pem --sudo -y
knife bootstrap node-linux-16 -N node-linux-16 -x ubuntu -i ~/.ssh/sys_admin.pem --sudo -y
knife client list
export CHEF_PROFILE=sloppyjoe
knife bootstrap node-linux-17 -N node-linux-17 -x ubuntu -i ~/.ssh/sys_admin.pem --sudo -y
knife bootstrap node-linux-18 -N node-linux-18 -x ubuntu -i ~/.ssh/sys_admin.pem --sudo -y
knife client list
export CHEF_PROFILE=potroast
knife bootstrap node-linux-19 -N node-linux-19 -x ubuntu -i ~/.ssh/sys_admin.pem --sudo -y
knife bootstrap node-linux-20 -N node-linux-20 -x ubuntu -i ~/.ssh/sys_admin.pem --sudo -y
knife client list
