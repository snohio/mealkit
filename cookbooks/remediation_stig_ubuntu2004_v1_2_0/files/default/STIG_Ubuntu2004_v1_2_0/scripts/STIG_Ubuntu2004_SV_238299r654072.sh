#!/bin/bash
grub_cmdline_linux_config=(`grep -E ^GRUB_CMDLINE_LINUX="(.*?)" /etc/default/grub | cut -d '"' -f2`)
if [[ ! ${grub_cmdline_linux_config[@]} =~ "audit=1" ]]; then
  grub_cmdline_linux_config+=("audit=1")
  sed -i '/GRUB_CMDLINE_LINUX=/d' /etc/default/grub; echo "GRUB_CMDLINE_LINUX=\"${grub_cmdline_linux_config[@]}\"" >> /etc/default/grub
fi
update-grub
update-grub