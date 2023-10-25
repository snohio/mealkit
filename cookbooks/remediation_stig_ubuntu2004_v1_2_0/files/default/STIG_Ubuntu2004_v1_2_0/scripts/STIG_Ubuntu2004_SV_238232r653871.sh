#!/bin/bash
#!/bin/bash
sudo apt-get update
sudo apt-get install opensc-pkcs11 -y
sudo apt-get install libpam-pkcs11 -y
test -e /etc/pam_pkcs11/pam_pkcs11.conf || sudo cp /usr/share/doc/libpam-pkcs11/examples/pam_pkcs11.conf.example /etc/pam_pkcs11/pam_pkcs11.conf
sudo chmod 077 /etc/pam_pkcs11/pam_pkcs11.conf
if [[ ! $( sudo awk '//' /etc/pam_pkcs11/pam_pkcs11.conf | sudo grep cert_policy | sudo grep ocsp_on ) ]]; then
  if [[ $(sudo grep "cert_policy = " /etc/pam_pkcs11/pam_pkcs11.conf) ]]; then
      sudo sed -i '/cert_policy = /s/;$/,ocsp_on;/' /etc/pam_pkcs11/pam_pkcs11.conf 
  else
      sudo echo "cert_policy = ocsp_on;" >> /etc/pam_pkcs11/pam_pkcs11.conf
  fi
fi