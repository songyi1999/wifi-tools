# -*- coding: utf-8 -*-
# build 58.1 kernel: extract, config, full build (Module.symvers needed for aic8800)
s = r'''
set -e
cd /root/kbuild
rm -rf linux58 linux-msft-wsl-6.18.58.1
mkdir linux58 && tar -xzf k58.tar.gz -C linux58 --strip-components=1
cd linux58
scripts/config --file Microsoft/config-wsl \
  -e CFG80211 -e MAC80211 -e WIRELESS -e NETDEVICES -e WLAN \
  -e WLAN_VENDOR_REALTEK -e RTL8XXXU -e RTL8XXXU_UNTESTED \
  -e WLAN_VENDOR_RALINK -e RT2X00 -e RT2800USB -e RT2800USB_RT3573
make KCONFIG_CONFIG=Microsoft/config-wsl olddefconfig >/dev/null 2>&1
grep -E "CONFIG_(RTL8XXXU|MAC80211)[= ]" Microsoft/config-wsl
nohup bash -c 'make KCONFIG_CONFIG=Microsoft/config-wsl -j$(nproc) bzImage modules > /root/kbuild/build58.log 2>&1; echo EXIT=$? >> /root/kbuild/build58.log' >/dev/null 2>&1 &
echo BUILD58_STARTED
'''
open(r'E:\WSL\dl\build58.sh', 'w', encoding='utf-8').write(s)
print("script written")
PYEOF
