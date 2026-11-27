"""Graphical launcher for CM. Use --create-shortcut once on Astra."""
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent


def create_shortcut():
    if not sys.platform.startswith('linux'):
        raise RuntimeError('Этот способ создания ярлыка предназначен для Astra Linux.')
    if os.geteuid() == 0:
        raise RuntimeError('Создайте ярлык под своей учётной записью, без sudo.')
    data_home = Path(os.environ.get('XDG_DATA_HOME', ''))
    if not data_home.is_absolute():
        data_home = Path.home() / '.local' / 'share'
    destination = data_home / 'applications' / 'cm-astra.desktop'
    destination.parent.mkdir(parents=True, exist_ok=True)
    # Desktop Entry string escaping. Path sets the working directory, keeping Exec constant.
    directory = str(ROOT).translate(str.maketrans({'\\': r'\\', ' ': r'\s',
                                                  '\n': r'\n', '\r': r'\r', '\t': r'\t'}))
    destination.write_text(
        '[Desktop Entry]\nType=Application\nName=CM Astra\n'
        'Comment=Управление школьными компьютерами\nIcon=computer\n'
        'Exec=/usr/bin/python3 -B Start-CM.pyw\n'
        f'Path={directory}\nTerminal=false\nCategories=Education;\n',
        encoding='utf-8',
    )
    print('Готово. Откройте CM Astra в меню приложений.')


def windows_environment():
    environment = ROOT / '.venv-win'
    console_exe = environment / 'Scripts' / 'python.exe'
    window_exe = environment / 'Scripts' / 'pythonw.exe'
    flags = subprocess.CREATE_NO_WINDOW
    if not (console_exe.is_file() and window_exe.is_file()):
        subprocess.run([sys.executable, '-m', 'venv', str(environment)], check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, creationflags=flags)
    if not (console_exe.is_file() and window_exe.is_file()):
        raise RuntimeError('Не удалось подготовить окружение Python. Откройте Start-CM.cmd для диагностики.')
    dependency = (ROOT / 'requirements.txt').read_text(encoding='utf-8').strip()
    version = dependency.split('==', 1)[1]
    installed = subprocess.run(
        [str(console_exe), '-c', f'import paramiko; raise SystemExit(paramiko.__version__ != {version!r})'],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=flags,
    )
    if installed.returncode:
        subprocess.run([str(console_exe), '-m', 'pip', 'install', '--disable-pip-version-check', dependency],
                       check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       creationflags=flags)
    subprocess.Popen([str(window_exe), '-X', 'utf8', '-B', str(Path(__file__).resolve()), '--run'],
                     cwd=ROOT, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def show_error(error):
    detail = str(error)
    if isinstance(error, subprocess.CalledProcessError):
        detail = 'Не удалось подготовить Python для CM. Проверьте доступ к Интернету и запустите Start-CM.cmd для диагностики.'
    try:
        import tkinter as tk
        from tkinter import messagebox
        root = tk.Tk()
        root.withdraw()
        try:
            messagebox.showerror('CM Astra не запущен', detail, parent=root)
        finally:
            root.destroy()
    except Exception:
        if os.name == 'nt':
            import ctypes
            ctypes.windll.user32.MessageBoxW(None, detail, 'CM Astra не запущен', 0x10)
        elif sys.stderr is not None:
            print(detail, file=sys.stderr)


def main():
    if sys.argv[1:] == ['--create-shortcut']:
        try:
            create_shortcut()
        except (OSError, RuntimeError) as error:
            print(error, file=sys.stderr)
            return 1
        return 0
    try:
        if sys.version_info < (3, 9):
            raise RuntimeError('Установите Python 3.9 или новее с Tcl/Tk.')
        if os.name == 'nt' and sys.argv[1:] != ['--run']:
            windows_environment()
        else:
            if sys.platform.startswith('linux') and os.geteuid() == 0:
                raise RuntimeError('Запускайте CM из учительского сеанса, без sudo.')
            import paramiko
            from class_manager import main as start_cm
            if tuple(map(int, paramiko.__version__.split('.')[:2])) < (2, 12):
                raise RuntimeError('Требуется Paramiko 2.12 или новее. На Astra запустите Install-CM-Astra.sh.')
            start_cm()
    except ModuleNotFoundError as error:
        show_error('Проверьте зависимости CM. На Astra выполните sudo sh Install-CM-Astra.sh. '
                   'На Windows откройте Start-CM.cmd для диагностики.\n' + str(error))
        return 1
    except Exception as error:
        show_error(error)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
