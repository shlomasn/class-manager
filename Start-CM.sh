#!/bin/sh
set -eu
cd "$(dirname "$0")"
[ "$(id -u)" != 0 ] || { echo 'Запускайте CM под обычной учительской учётной записью, без sudo.'; exit 1; }
if ! python3 -c 'import tkinter,paramiko; assert tuple(map(int,paramiko.__version__.split(".")[:2])) >= (2,12)' 2>/dev/null; then
    echo 'Сначала подготовьте зависимости: sudo sh Install-CM-Astra.sh'
    exit 1
fi
exec python3 -B class_manager.py
