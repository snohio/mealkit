#!/bin/bash
test -e /etc/pam.d/common-password && sudo sed -e s/nullok//g -i /etc/pam.d/common-password