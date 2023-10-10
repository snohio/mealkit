#!/bin/bash
#!/bin/bash
sudo chmod 077 /etc/apt/apt.conf.d/50unattended-upgrades
if [[ ! $( sudo awk '//' /etc/apt/apt.conf.d/50unattended-upgrades | sudo grep ^Unattended-Upgrade::Remove-Unused-Dependencies  | sudo grep true ) ]]; then
  if [[ $(sudo grep "^Unattended-Upgrade::Remove-Unused-Dependencies " /etc/apt/apt.conf.d/50unattended-upgrades) ]]; then
      sudo sed -i 's/^Unattended-Upgrade::Remove-Unused-Dependencies.*/Unattended-Upgrade::Remove-Unused-Dependencies "true";/' /etc/apt/apt.conf.d/50unattended-upgrades 
  else
      sudo echo 'Unattended-Upgrade::Remove-Unused-Dependencies "true";' >> /etc/apt/apt.conf.d/50unattended-upgrades
  fi
fi
if [[ ! $( sudo awk '//' /etc/apt/apt.conf.d/50unattended-upgrades | sudo grep ^Unattended-Upgrade::Remove-Unused-Kernel-Packages  | sudo grep true ) ]]; then
  if [[ $(sudo grep "^Unattended-Upgrade::Remove-Unused-Kernel-Packages " /etc/apt/apt.conf.d/50unattended-upgrades) ]]; then
      sudo sed -i 's/Unattended-Upgrade::Remove-Unused-Kernel-Packages.*/^Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";/' /etc/apt/apt.conf.d/50unattended-upgrades 
  else
      sudo echo 'Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";' >> /etc/apt/apt.conf.d/50unattended-upgrades
  fi
fi