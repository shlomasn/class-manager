#!/bin/sh
# Install only controller dependencies from configured Astra repositories.
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
[ "$(id -u)" = 0 ] || { echo 'Run: sudo sh Install-CM-Astra.sh'; exit 1; }
[ -r /etc/astra/build_version ] || { echo 'STOP: Astra Linux required'; exit 1; }
apt-get update
apt-get -o DPkg::Lock::Timeout=180 install -y python3 python3-tk python3-paramiko libsecret-tools gnome-keyring
python3 -c 'import tkinter,paramiko; assert tuple(map(int,paramiko.__version__.split(".")[:2])) >= (2,12)'
echo 'ГОТОВО. Под учительской учётной записью выполните python3 Start-CM.pyw --create-shortcut.'
echo 'Затем откройте CM Astra в меню приложений. Для диагностики: sh Start-CM.sh.'
echo 'Для сохранения пароля может потребоваться создать/разблокировать связку ключей.'
