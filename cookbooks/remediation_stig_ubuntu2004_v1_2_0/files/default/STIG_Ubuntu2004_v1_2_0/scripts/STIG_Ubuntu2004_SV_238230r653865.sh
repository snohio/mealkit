#!/bin/bash
dpkg -s libpam-pkcs11 || sudo apt-get update && apt install -y libpam-pkcs11