#!/bin/bash
dpkg -s opensc-pkcs11 || sudo apt-get update && apt install -y opensc-pkcs11