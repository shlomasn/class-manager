"""Per-Windows-user generic credential; no plaintext password files."""
import ctypes
from ctypes import wintypes
import os
import shutil
import subprocess
from types import SimpleNamespace

TARGET = 'CM-Astra/SSH/user'
NOT_FOUND = 1168
MAX_BLOB = 2560


class Credential(ctypes.Structure):
    _fields_ = [('Flags', wintypes.DWORD), ('Type', wintypes.DWORD),
                ('TargetName', wintypes.LPWSTR), ('Comment', wintypes.LPWSTR),
                ('LastWritten', wintypes.FILETIME), ('CredentialBlobSize', wintypes.DWORD),
                ('CredentialBlob', ctypes.POINTER(wintypes.BYTE)), ('Persist', wintypes.DWORD),
                ('AttributeCount', wintypes.DWORD), ('Attributes', ctypes.c_void_p),
                ('TargetAlias', wintypes.LPWSTR), ('UserName', wintypes.LPWSTR)]


def api():
    if os.name != 'nt':
        raise RuntimeError('Сохранение пароля доступно в Windows')
    dll = ctypes.WinDLL('Advapi32.dll', use_last_error=True)
    pointer = ctypes.POINTER(Credential)
    dll.CredWriteW.argtypes = [pointer, wintypes.DWORD]
    dll.CredWriteW.restype = wintypes.BOOL
    dll.CredReadW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(pointer)]
    dll.CredReadW.restype = wintypes.BOOL
    dll.CredDeleteW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD]
    dll.CredDeleteW.restype = wintypes.BOOL
    dll.CredFree.argtypes = [ctypes.c_void_p]
    dll.CredFree.restype = None
    return SimpleNamespace(write=dll.CredWriteW, read=dll.CredReadW, delete=dll.CredDeleteW,
                           free=dll.CredFree, last_error=ctypes.get_last_error)


def validate(password):
    if not password or '\n' in password or '\r' in password or len(password.encode('utf-16-le')) > MAX_BLOB:
        raise ValueError('Некорректный или слишком длинный пароль')


def _windows_save(password):
    validate(password)
    backend = api()
    blob = password.encode('utf-16-le')
    buffer = (wintypes.BYTE * len(blob)).from_buffer_copy(blob)
    credential = Credential()
    credential.Type, credential.TargetName, credential.UserName = 1, TARGET, 'user'
    credential.CredentialBlobSize = len(blob)
    credential.CredentialBlob = ctypes.cast(buffer, ctypes.POINTER(wintypes.BYTE))
    credential.Persist = 2  # CRED_PERSIST_LOCAL_MACHINE: persists for this Windows user.
    try:
        if not backend.write(ctypes.byref(credential), 0):
            raise RuntimeError('Windows не сохранила пароль; код ' + str(backend.last_error()))
    finally:
        ctypes.memset(buffer, 0, len(blob))


def _windows_load():
    if os.name != 'nt':
        return None
    backend = api()
    pointer = ctypes.POINTER(Credential)()
    if not backend.read(TARGET, 1, 0, ctypes.byref(pointer)):
        if backend.last_error() == NOT_FOUND:
            return None
        raise RuntimeError('Не удалось прочитать пароль Windows; код ' + str(backend.last_error()))
    try:
        credential = pointer.contents
        size = credential.CredentialBlobSize
        if credential.UserName != 'user' or not 0 < size <= MAX_BLOB or size % 2 or not credential.CredentialBlob:
            raise ValueError('Неверный формат')
        password = ctypes.string_at(credential.CredentialBlob, size).decode('utf-16-le')
        validate(password)
        return password
    except (ValueError, UnicodeError):
        raise RuntimeError('Сохранённый пароль повреждён; сохраните его заново') from None
    finally:
        backend.free(pointer)


def _windows_delete():
    backend = api()
    if not backend.delete(TARGET, 1, 0) and backend.last_error() != NOT_FOUND:
        raise RuntimeError('Не удалось удалить пароль Windows; код ' + str(backend.last_error()))


def _secret(action, password=None):
    tool = shutil.which('secret-tool')
    if not tool:
        if action == 'lookup':
            return None
        raise RuntimeError('Для сохранения на Astra установите libsecret-tools и gnome-keyring; запустите CM в графическом сеансе')
    command = [tool, action]
    if action == 'store':
        command += ['--label=CM Astra: локальный user']
    command += ['application', 'CM-Astra', 'account', 'user']
    try:
        result = subprocess.run(command, input=password if password is not None else None,
                                capture_output=True, text=True, encoding='utf-8', timeout=60)
    except subprocess.TimeoutExpired:
        raise RuntimeError('Хранилище не ответило; разблокируйте связку ключей в графическом сеансе') from None
    if action == 'lookup' and result.returncode == 1:
        return None
    if result.returncode != 0:
        raise RuntimeError('Хранилище Secret Service недоступно; откройте или создайте связку ключей')
    return result.stdout if action == 'lookup' else None


def save(password):
    validate(password)
    if os.name == 'nt':
        _windows_save(password)
    else:
        _secret('store', password)


def load():
    if os.name == 'nt':
        return _windows_load()
    password = _secret('lookup')
    if password is not None:
        validate(password)
    return password


def delete():
    if os.name == 'nt':
        _windows_delete()
    else:
        _secret('clear')
