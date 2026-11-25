"""SSH power control. No shutdown commands run on import or during discovery."""
import base64
from dataclasses import dataclass, asdict
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import socket
import tempfile
import time
import threading
import uuid


@dataclass(frozen=True)
class Host:
    name: str
    ip: str
    room: str
    mode: str = 'dns'


def hostname(value):
    name = value.strip().lower().removesuffix('.534school.spb.ru')
    if re.fullmatch(r'\d{3}-[a-z0-9-]+', name):
        name = 'a' + name
    if not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', name):
        raise ValueError('Недопустимое имя компьютера: ' + value)
    return name


def load_hosts(path):
    path = Path(path)
    raw = path.read_bytes()
    if len(raw) > 1024 * 1024:
        raise ValueError('Слишком большой список компьютеров')
    if path.suffix.lower() == '.json':
        rows = json.loads(raw.decode('utf-8-sig'))
    else:
        try:
            text = raw.decode('utf-8-sig')
        except UnicodeError:
            text = raw.decode('cp1251')
        rows = []
        for n, line in enumerate(text.splitlines(), 1):
            if not line.strip() or line.lstrip().startswith(('#', ';')):
                continue
            columns = line.split(';')
            if len(columns) not in (2, 3):
                raise ValueError('Неверный формат строки ' + str(n))
            rows.append(dict(name=columns[0], ip=columns[1]))
    if not isinstance(rows, list) or not 1 <= len(rows) <= 250:
        raise ValueError('В списке должно быть от 1 до 250 компьютеров')
    return validate_hosts(rows)


def room_name(value):
    value = value.strip()
    if not value or len(value) > 40 or value == 'Все кабинеты' or any(ord(c) < 32 for c in value):
        raise ValueError('Введите название класса длиной от 1 до 40 символов')
    return value


def validate_hosts(rows):
    if not isinstance(rows, list) or len(rows) > 250:
        raise ValueError('Допускается до 250 компьютеров')
    result, names, fixed_ips = [], set(), set()
    for row in rows:
        name = hostname(row['name'])
        mode = row.get('mode', 'dns')
        if mode not in ('dns', 'fixed'):
            raise ValueError('Неизвестный режим адресации')
        value = row.get('ip', '').strip()
        ip = school_ip(value) if value else ''
        if mode == 'fixed' and not ip:
            raise ValueError('Для постоянного IP укажите адрес')
        if name in names or (mode == 'fixed' and ip in fixed_ips):
            raise ValueError('Повторное имя или постоянный адрес: ' + name)
        names.add(name)
        if mode == 'fixed':
            fixed_ips.add(ip)
        default_room = name[1:4] if re.match(r'a\d{3}-', name) else 'Без класса'
        result.append(Host(name, ip, room_name(row.get('room', default_room)), mode))
    return result


def school_ip(value):
    ip = ipaddress.IPv4Address(value)
    if ip not in ipaddress.ip_network('192.168.0.0/16'):
        raise ValueError('Адрес вне школьной сети: ' + str(ip))
    return str(ip)


def resolve(host):
    if host.mode == 'fixed':
        return school_ip(host.ip)
    answers = socket.getaddrinfo(host.name + '.534school.spb.ru', 22, socket.AF_INET, socket.SOCK_STREAM)
    addresses = sorted({school_ip(answer[4][0]) for answer in answers})
    if len(addresses) != 1:
        raise ValueError('DNS должен возвращать один школьный IPv4; проверьте записи компьютера')
    return addresses[0]


def load_inventory(path):
    data = json.loads(Path(path).read_text(encoding='utf-8'))
    if data.get('version') != 2:
        raise ValueError('Неизвестная версия списка')
    rooms = [room_name(value) for value in data['rooms']]
    if len(rooms) != len(set(rooms)) or len(rooms) > 100:
        raise ValueError('Повторные классы или более 100 классов')
    hosts = validate_hosts(data['hosts'])
    if any(host.room not in rooms for host in hosts):
        raise ValueError('Компьютер ссылается на отсутствующий класс')
    return rooms, hosts


def save_inventory(path, rooms, hosts):
    payload = dict(version=2, rooms=rooms, hosts=[asdict(host) for host in hosts])
    # Validate before replacing a valid configuration.
    validated = validate_hosts(payload['hosts'])
    clean_rooms = [room_name(value) for value in rooms]
    if len(clean_rooms) != len(set(clean_rooms)) or len(clean_rooms) > 100 or any(h.room not in clean_rooms for h in validated):
        raise ValueError('Некорректный список классов')
    atomic_json(path, payload)


def atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.cm-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def decode_key(pin):
    import paramiko
    data = base64.b64decode(pin['key'], validate=True)
    if hasattr(paramiko.PKey, 'from_type_string'):
        return paramiko.PKey.from_type_string(pin['type'], data)
    classes = {'ssh-ed25519': paramiko.Ed25519Key, 'ssh-rsa': paramiko.RSAKey}
    if pin['type'].startswith('ecdsa-sha2-'):
        return paramiko.ECDSAKey(data=data)
    if pin['type'] not in classes:
        raise ValueError('Неподдерживаемый тип SSH-ключа')
    return classes[pin['type']](data=data)


def fingerprint(key):
    return 'SHA256:' + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')


def probe(host):
    import paramiko
    transport = None
    try:
        ip = resolve(host)
        sock = socket.create_connection((ip, 22), timeout=3)
        transport = paramiko.Transport(sock)
        transport.start_client(timeout=6)
        key = transport.get_remote_server_key()
        return dict(name=host.name, ip=ip, ok=True, type=key.get_name(), key=key.get_base64(), fingerprint=fingerprint(key))
    except (socket.gaierror, ValueError) as error:
        return dict(name=host.name, ip='', ok=False, message='Не удалось найти адрес по имени: ' + str(error))
    except Exception:
        return dict(name=host.name, ip='', ok=False, message='SSH недоступен или не отвечает')
    finally:
        if transport:
            transport.close()


def same_key(left, right):
    return left['type'] == right['type'] and left['key'] == right['key']


def classify_key(row, trusted, catalog):
    # Trust follows the computer name and key, never a DHCP address.
    previous = trusted.get(row['name']) or catalog.get(row['name'])
    if previous and not same_key(previous, row):
        return 'changed'
    return 'trusted' if previous else 'new'


def run(client, command, password=None, timeout=25):
    channel = client.get_transport().open_session(timeout=8)
    try:
        channel.exec_command(command)
        # Do not request a PTY. Never put the password in command arguments.
        if password is not None:
            channel.sendall((password + '\n').encode('utf-8'))
        channel.shutdown_write()
        deadline = time.monotonic() + timeout
        output = bytearray()
        while time.monotonic() < deadline:
            while channel.recv_ready():
                output.extend(channel.recv(8192))
                if len(output) > 64 * 1024:
                    raise RuntimeError('Слишком большой ответ; результат требует проверки')
            while channel.recv_stderr_ready():
                output.extend(channel.recv_stderr(8192))
                if len(output) > 64 * 1024:
                    raise RuntimeError('Слишком большой ответ; результат требует проверки')
            if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                return channel.recv_exit_status(), output.decode('utf-8', errors='replace')
            time.sleep(.04)
        raise RuntimeError('Время ожидания истекло; результат не подтверждён. Проверьте ПК перед повтором')
    finally:
        channel.close()


def power_command(action, minutes):
    if action not in ('off', 'reboot', 'cancel'):
        raise ValueError('Неизвестное действие')
    if type(minutes) is not int or not 0 <= minutes <= 30:
        raise ValueError('Задержка должна быть от 0 до 30 минут')
    command = "LC_ALL=C sudo -k -S -p '' /usr/sbin/shutdown "
    if action == 'cancel':
        return command + '-c'
    flag = '-P' if action == 'off' else '-r'
    text = 'По команде учителя: ' + ('выключение' if action == 'off' else 'перезагрузка') + '. Сохраните работу.'
    return command + flag + ' ' + ('now' if minutes == 0 else '+' + str(minutes)) + ' ' + shlex.quote(text)


def execute(host, pin, password, action, minutes):
    import paramiko
    if not password or '\n' in password or '\r' in password:
        raise ValueError('Некорректный пароль')
    command = power_command(action, minutes)
    ip = school_ip(pin.get('ip', host.ip))
    result = dict(name=host.name, ip=ip, action=action, ok=False)
    power_started = False
    client = paramiko.SSHClient()
    try:
        key = decode_key(pin)
        client.get_host_keys().add(ip, pin['type'], key)
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        client.connect(ip, username='user', password=password, look_for_keys=False,
                       allow_agent=False, timeout=4, banner_timeout=6, auth_timeout=8)
        code, actual = run(client, '/bin/hostname -s')
        if code != 0 or actual.strip().lower() != host.name:
            raise RuntimeError('Имя ПК не совпало; команда питания не отправлена')
        code, version = run(client, '/usr/bin/cat /etc/astra/build_version')
        if code != 0 or not version.strip().startswith('1.8.4.'):
            raise RuntimeError('Не подтверждена Astra Linux 1.8.4; команда не отправлена')
        power_started = True
        code, text = run(client, command, password=password)
        if code == -1:
            raise RuntimeError('Соединение закрыто без подтверждения; ПК мог уже выключиться или перезагрузиться. Проверьте перед повтором')
        if code != 0:
            if 'incorrect password' in text.lower() or 'authentication failure' in text.lower():
                result['stop'] = True
                raise RuntimeError('Неверный пароль sudo; дальнейшие попытки остановлены')
            raise RuntimeError('Команда не выполнена: ' + text.strip()[:1200])
        result.update(ok=True, message='Отмена отправлена' if action == 'cancel' else
                      ('Команда выключения' if action == 'off' else 'Команда перезагрузки') + (' принята; немедленно' if minutes == 0 else ' принята; через ' + str(minutes) + ' мин.'))
    except paramiko.AuthenticationException:
        result.update(stop=True, message='Неверный пароль SSH или вход user запрещён; дальнейшие попытки остановлены')
    except paramiko.BadHostKeyException:
        result['message'] = 'SSH-ключ изменился; пароль не отправлен'
    except (paramiko.SSHException, EOFError, OSError) as error:
        result['message'] = ('Связь прервалась после отправки команды; результат не подтверждён. Проверьте ПК перед повтором' if power_started else str(error).replace(password, '[СКРЫТО]'))
    except Exception as error:
        result['message'] = str(error).replace(password, '[СКРЫТО]')
    finally:
        client.close()
    return result


def connect_verified(host, pin, password):
    """Pinned SSH and host/OS checks shared by upload and command operations."""
    import paramiko
    if not password or '\n' in password or '\r' in password:
        raise ValueError('Некорректный пароль')
    ip = school_ip(pin['ip'])
    client = paramiko.SSHClient()
    try:
        key = decode_key(pin)
        client.get_host_keys().add(ip, pin['type'], key)
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        client.connect(ip, username='user', password=password, look_for_keys=False,
                       allow_agent=False, timeout=4, banner_timeout=6, auth_timeout=8)
        code, actual = run(client, '/bin/hostname -s')
        if code != 0 or actual.strip().lower() != host.name:
            raise RuntimeError('Имя ПК не совпало; операция не выполнялась')
        code, version = run(client, '/usr/bin/cat /etc/astra/build_version')
        if code != 0 or not version.strip().startswith('1.8.4.'):
            raise RuntimeError('Не подтверждена Astra Linux 1.8.4; операция не выполнялась')
        return client
    except BaseException:
        client.close()
        raise


def operation_error(result, error, password):
    import paramiko
    if isinstance(error, paramiko.AuthenticationException):
        result.update(stop=True, message='Ошибка доступа SSH; дальнейшие попытки остановлены')
    elif isinstance(error, paramiko.BadHostKeyException):
        result['message'] = 'SSH-ключ изменился; пароль не отправлен'
    else:
        result['message'] = (str(error) or type(error).__name__).replace(password, '[СКРЫТО]')
    return result


def remote_path(value):
    """Validate a Linux path without expanding shell syntax or other users' homes."""
    import posixpath
    if not isinstance(value, str) or not value or any(c in value for c in '\x00\r\n'):
        raise ValueError('Укажите папку на ученическом ПК: /полный/путь или ~/папка')
    if not (value.startswith('/') or value == '~' or value.startswith('~/')):
        raise ValueError('Путь должен начинаться с / или ~/ (домашняя папка user)')
    if '..' in value.split('/'):
        raise ValueError('Укажите путь без ..')
    return posixpath.normpath(value)


def shell_directory(value):
    value = remote_path(value)
    if value == '~':
        return '"$HOME"'
    if value.startswith('~/'):
        return '"$HOME"/' + shlex.quote(value[2:])
    return shlex.quote(value)


DEFAULT_INBOX = '~/Desktops/Desktop1/CM-Inbox'


def file_launch_spec(path, sha256):
    import posixpath
    path = remote_path(path)
    if not re.fullmatch(r'[0-9a-f]{64}', sha256):
        raise ValueError('Нет корректной контрольной суммы переданного файла')
    name = posixpath.basename(path)
    if name.lower().endswith('.sh'):
        script, sudo = '/bin/bash ' + shlex.quote('./' + name), False
    elif name.lower().endswith('.deb'):
        script, sudo = 'apt-get -o DPkg::Lock::Timeout=180 install -y ' + shlex.quote('./' + name), True
    else:
        raise ValueError('Выберите переданный .sh или .deb')
    return dict(script=script, sudo=sudo, cwd=posixpath.dirname(path),
                expected_file=dict(path=path, sha256=sha256))


def ensure_remote_directory(sftp, destination, reject_existing=False):
    import posixpath
    import stat
    current = '/'
    for part in destination.strip('/').split('/'):
        if not part:
            continue
        current = posixpath.join(current, part)
        try:
            info = sftp.lstat(current)
            if not stat.S_ISDIR(info.st_mode):
                raise RuntimeError('Путь не является обычным каталогом: ' + current)
            if current == destination and reject_existing:
                raise RuntimeError('Каталог отправки уже существует; выберите новую папку')
        except FileNotFoundError:
            sftp.mkdir(current, 0o700)


def execute_command(host, pin, password, script, sudo=False, timeout=300, cwd=None, expected_file=None):
    if not script.strip() or len(script.encode('utf-8')) > 32 * 1024 or '\x00' in script:
        raise ValueError('Введите команду длиной до 32 КБ без NUL')
    if type(timeout) is not int or not 10 <= timeout <= 1800:
        raise ValueError('Ожидание команды: от 10 до 1800 секунд')
    if cwd is not None:
        cwd = remote_path(cwd)
    if expected_file is not None:
        file_launch_spec(expected_file['path'], expected_file['sha256'])
    result = dict(name=host.name, ip=pin['ip'], action='command', ok=False, cwd=cwd or '~')
    client = None
    try:
        client = connect_verified(host, pin, password)
        if expected_file is not None:
            check = '/usr/bin/sha256sum -- ' + shell_directory(expected_file['path'])
            code, digest = run(client, check)
            if code != 0 or digest.split()[:1] != [expected_file['sha256']]:
                raise RuntimeError('Переданный файл отсутствует или изменился; запуск отменён')
            result['expected_file'] = expected_file
        command = ('LC_ALL=C sudo -k -S -p \'\' ' if sudo else '') + '/bin/bash -c ' + shlex.quote(script)
        if cwd is not None:
            command = '/bin/bash -c ' + shlex.quote('cd -- ' + shell_directory(cwd) + ' && ' + command)
        code, output = run(client, command, password=password if sudo else None, timeout=timeout)
        output = output.replace(password, '[СКРЫТО]')
        result.update(ok=code == 0, exit=code, output=output,
                      command=script.replace(password, '[СКРЫТО]'), sudo=sudo,
                      message='Команда завершена, код ' + str(code))
        if code == -1:
            result['message'] = 'Соединение закрыто; результат команды не подтверждён'
        if sudo and code != 0 and ('incorrect password' in output.lower() or 'authentication failure' in output.lower()):
            result.update(stop=True, message='Ошибка пароля sudo; дальнейшие попытки остановлены')
    except Exception as error:
        operation_error(result, error, password)
    finally:
        if client:
            client.close()
    return result


def _digest_stream(stream, progress=None):
    digest = hashlib.sha256()
    while True:
        chunk = stream.read(1024 * 1024)
        if not chunk:
            return digest.hexdigest()
        digest.update(chunk)
        if progress:
            progress(len(chunk))


def transfer_files(host, pin, password, paths, batch, destination=None, progress=None, on_conflict=None):
    import posixpath
    import stat
    if not re.fullmatch(r'[A-Za-z0-9-]{1,80}', batch) or not 1 <= len(paths) <= 20:
        raise ValueError('Некорректная передача файлов')
    sources = [Path(value) for value in paths]
    names = [p.name for p in sources]
    if len(set(names)) != len(names) or any(not n or n in ('.', '..') or any(c in n for c in '\x00\r\n/\\') for n in names):
        raise ValueError('Повторные или недопустимые имена файлов')
    if any(not p.is_file() for p in sources):
        raise ValueError('Выберите существующие файлы')
    requested = remote_path(destination) if destination is not None else DEFAULT_INBOX
    result = dict(name=host.name, ip=pin['ip'], action='upload', ok=False, files=[], skipped=[], destination=requested)
    total = sum(p.stat().st_size for p in sources) * 3
    done = 0
    def notify(phase, filename='', delta=0):
        nonlocal done
        done += delta
        if progress:
            progress(dict(phase=phase, file=filename, done=done, total=total, destination=result['destination']))
    notify('Подключение и проверка имени/ОС')
    client = None
    sftp = None
    try:
        client = connect_verified(host, pin, password)
        sftp = client.open_sftp()
        sftp.get_channel().settimeout(60)
        home = sftp.normalize('.')
        if not home.startswith('/') or home == '/':
            raise RuntimeError('Не подтверждён домашний каталог user')
        destination = home if requested == '~' else (posixpath.join(home, requested[2:]) if requested.startswith('~/') else requested)
        result['destination'] = destination
        ensure_remote_directory(sftp, destination)
        for source in sources:
            before = source.stat()
            target = posixpath.join(destination, source.name)
            overwrite = False
            try:
                existing = sftp.lstat(target)
            except FileNotFoundError:
                pass
            else:
                if not stat.S_ISREG(existing.st_mode):
                    raise RuntimeError('Нельзя заменить каталог или ссылку: ' + target)
                if on_conflict is None:
                    raise RuntimeError('Файл уже существует; требуется подтверждение перезаписи: ' + target)
                if not on_conflict(target):
                    result['skipped'].append(target)
                    notify('Пропущен без перезаписи', source.name, before.st_size * 3)
                    continue
                overwrite = True
            notify('Подготовка SHA-256', source.name)
            with source.open('rb') as stream:
                local_hash = _digest_stream(stream, lambda n: notify('Подготовка SHA-256', source.name, n))
            temporary = target + '.' + batch + '.part'
            try:
                sftp.lstat(temporary)
            except FileNotFoundError:
                pass
            else:
                raise RuntimeError('Временный файл уже существует; выберите новую отправку: ' + temporary)
            try:
                notify('Передача', source.name)
                previous = 0
                def transferred(count, size):
                    nonlocal previous
                    notify('Передача', source.name, count - previous)
                    previous = count
                sftp.put(str(source), temporary, callback=transferred, confirm=True)
                sftp.chmod(temporary, 0o600)
                notify('Проверка SHA-256 на ПК', source.name)
                with sftp.open(temporary, 'rb') as stream:
                    remote_hash = _digest_stream(stream, lambda n: notify('Проверка SHA-256 на ПК', source.name, n))
                after = source.stat()
                if local_hash != remote_hash or (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                    raise RuntimeError('Файл изменился или контрольная сумма не совпала: ' + source.name)
                if overwrite:
                    current = sftp.lstat(target)
                    if not stat.S_ISREG(current.st_mode) or (current.st_size, current.st_mtime) != (existing.st_size, existing.st_mtime):
                        raise RuntimeError('Файл изменился после подтверждения; перезапись отменена: ' + target)
                    sftp.posix_rename(temporary, target)
                else:
                    sftp.rename(temporary, target)
            except BaseException:
                try:
                    sftp.remove(temporary)
                except Exception:
                    pass
                raise
            result['files'].append(dict(path=target, sha256=local_hash, bytes=before.st_size))
        notify('Готово')
        result.update(ok=True, message='Передано файлов: ' + str(len(result['files'])) + ', пропущено: ' + str(len(result['skipped'])), output='\n'.join(item['path'] for item in result['files']))
    except Exception as error:
        operation_error(result, error, password)
        # Keep already verified files and list them in the report on partial failure.
    finally:
        if sftp:
            sftp.close()
        if client:
            client.close()
    return result


def parse_addresses(text, limit=512):
    """Comma/newline-separated IPv4, full ranges, or CIDR; bounded before enumeration."""
    addresses = set()
    tokens = [x for x in re.split(r'[,;\s]+', text.strip()) if x]
    if not tokens:
        raise ValueError('Укажите IP, диапазон или подсеть')
    for token in tokens:
        if '/' in token:
            network = ipaddress.IPv4Network(token, strict=False)
            if not network.subnet_of(ipaddress.ip_network('192.168.0.0/16')) or network.num_addresses > limit + 2:
                raise ValueError('Диапазон вне школьной сети или более ' + str(limit) + ' адресов')
            values = network.hosts()
        elif '-' in token:
            first, last = token.split('-', 1)
            start, end = int(ipaddress.IPv4Address(school_ip(first))), int(ipaddress.IPv4Address(school_ip(last)))
            if start > end or end - start + 1 > limit:
                raise ValueError('Некорректный или слишком большой диапазон')
            values = (ipaddress.IPv4Address(n) for n in range(start, end + 1))
        else:
            values = [ipaddress.IPv4Address(school_ip(token))]
        for value in values:
            addresses.add(school_ip(str(value)))
            if len(addresses) > limit:
                raise ValueError('За раз допускается до ' + str(limit) + ' адресов')
    return sorted(addresses, key=lambda value: int(ipaddress.IPv4Address(value)))


def probe_address(ip):
    # No authentication or mutation during the first scan phase.
    import paramiko
    transport = None
    try:
        ip = school_ip(ip)
        transport = paramiko.Transport(socket.create_connection((ip, 22), timeout=1.5))
        transport.start_client(timeout=4)
        key = transport.get_remote_server_key()
        return dict(ip=ip, ok=True, type=key.get_name(), key=key.get_base64(), fingerprint=fingerprint(key))
    except Exception:
        return dict(ip=ip, ok=False)
    finally:
        if transport:
            transport.close()


def inspect_address(pin, password):
    """Get the actual hostname through pinned SSH; never trust PTR as identity."""
    if not password or "\n" in password or "\r" in password:
        raise ValueError("Некорректный пароль")
    import paramiko
    client = paramiko.SSHClient()
    result = dict(pin, ok=False)
    try:
        key = decode_key(pin)
        client.get_host_keys().add(pin['ip'], pin['type'], key)
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        client.connect(pin['ip'], username='user', password=password, look_for_keys=False,
                       allow_agent=False, timeout=4, banner_timeout=5, auth_timeout=8)
        code, actual = run(client, '/bin/hostname -s')
        name = hostname(actual.strip())
        if code != 0 or name != actual.strip().lower():
            raise RuntimeError('Имя ПК не подходит; требуется проверка имени')
        code, version = run(client, '/usr/bin/cat /etc/astra/build_version')
        if code != 0 or not version.strip().startswith('1.8.4.'):
            raise RuntimeError('Не подтверждена Astra Linux 1.8.4')
        mode = 'fixed'
        try:
            if resolve(Host(name, '', 'Найденные')) == pin['ip']:
                mode = 'dns'
        except (OSError, ValueError):
            pass
        result.update(name=name, mode=mode, ok=True, message='Astra Linux 1.8.4')
    except Exception as error:
        operation_error(result, error, password)
    finally:
        client.close()
    return result


def _serve_file_channel(channel, source, token, size, progress):
    """Serve one exact file over an SSH-forwarded channel, never a directory."""
    try:
        channel.settimeout(60)
        request = b''
        while b'\r\n\r\n' not in request:
            chunk = channel.recv(1024)
            if not chunk:
                return
            request += chunk
            if len(request) > 8192:
                return
        if request.split(b'\r\n', 1)[0] != ('GET /' + token + ' HTTP/1.1').encode('ascii'):
            channel.sendall(b'HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
            return
        channel.sendall(('HTTP/1.1 200 OK\r\nContent-Length: ' + str(size) +
                         '\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n').encode('ascii'))
        with source.open('rb') as stream:
            remaining = size
            while remaining:
                chunk = stream.read(min(256 * 1024, remaining))
                if not chunk:
                    return
                channel.sendall(chunk)
                remaining -= len(chunk)
                progress(len(chunk))
    except Exception:
        # The requesting process reports incomplete data or SHA-256 mismatch.
        pass
    finally:
        channel.close()


def download_script(url, destination, name, sha256, size, overwrite):
    """Python stdlib downloader; its content is never executed as a program."""
    config = dict(url=url, destination=destination, name=name, sha256=sha256,
                  size=size, overwrite=overwrite)
    script = '''import os, stat, json, hashlib, urllib.request, pathlib, uuid
cfg = json.loads(CONFIG)
directory = pathlib.Path(cfg['destination']).expanduser()
current = pathlib.Path('/')
for part in directory.parts[1:]:
    current = current / part
    try:
        info = current.lstat()
    except FileNotFoundError:
        current.mkdir(mode=0o700)
    else:
        if not stat.S_ISDIR(info.st_mode):
            raise RuntimeError('Путь не является обычной папкой: ' + str(current))
target = directory / cfg['name']
try:
    previous = target.lstat()
except FileNotFoundError:
    previous = None
if previous is not None:
    if not stat.S_ISREG(previous.st_mode) or not cfg['overwrite']:
        raise RuntimeError('Перезапись не разрешена: ' + str(target))
temporary = directory / ('.cm-' + uuid.uuid4().hex + '.part')
try:
    digest = hashlib.sha256()
    size = 0
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with temporary.open('xb') as output:
        os.chmod(temporary, 0o600)
        with opener.open(cfg['url'], timeout=60) as response:
            while True:
                chunk = response.read(256 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > cfg['size']:
                    raise RuntimeError('Размер файла изменился')
                digest.update(chunk)
                output.write(chunk)
    if size != cfg['size'] or digest.hexdigest() != cfg['sha256']:
        raise RuntimeError('Размер или SHA-256 не совпали')
    if previous is None:
        os.link(temporary, target)  # Atomic refusal to overwrite an existing file.
        temporary.unlink()
    else:
        current = target.lstat()
        if (current.st_ino, current.st_mtime_ns, current.st_size, current.st_mode) != (previous.st_ino, previous.st_mtime_ns, previous.st_size, previous.st_mode):
            raise RuntimeError('Файл изменился после подтверждения')
        os.replace(temporary, target)
    print(json.dumps(dict(path=str(target), sha256=digest.hexdigest(), bytes=size)))
finally:
    if temporary.exists():
        temporary.unlink()
'''
    return script.replace('CONFIG', repr(json.dumps(config, ensure_ascii=False)), 1)


class DownloadStopped(RuntimeError):
    pass


class DownloadAccessGate:
    """Serialize password attempts only; file downloads run concurrently."""
    def __init__(self):
        self.lock = threading.Lock()
        self.stopped = threading.Event()

    def check(self):
        if self.stopped.is_set():
            raise DownloadStopped('Пропущен после ошибки доступа; повторных попыток нет')

    def connect(self, host, pin, password):
        import paramiko
        with self.lock:
            self.check()
            try:
                return connect_verified(host, pin, password)
            except paramiko.AuthenticationException:
                self.stopped.set()
                raise


def prepare_download(path, progress=None):
    source = Path(path)
    if not source.is_file():
        raise ValueError('Выберите существующий файл')
    before = source.stat()
    with source.open('rb') as stream:
        digest = _digest_stream(stream, progress)
    after = source.stat()
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise RuntimeError('Исходный файл изменился во время подготовки; отправка не начата')
    return dict(path=str(source.resolve()), size=before.st_size, mtime_ns=before.st_mtime_ns, sha256=digest)


def download_from_teacher(host, pin, password, path, destination=DEFAULT_INBOX, progress=None, on_conflict=None, access_gate=None, prepared=None):
    import posixpath
    import stat
    source = Path(path)
    destination = remote_path(destination)
    if not source.is_file() or any(c in source.name for c in '\x00\r\n/\\'):
        raise ValueError('Выберите существующий файл с допустимым именем')
    result = dict(name=host.name, ip=pin['ip'], action='download', ok=False, files=[], skipped=[], destination=destination)
    client = sftp = transport = None
    port = None
    done = 0
    before = source.stat()
    total = before.st_size if prepared else before.st_size * 2
    def notify(phase, delta=0):
        nonlocal done
        done += delta
        if progress:
            progress(dict(phase=phase, file=source.name, done=done, total=total,
                          destination=result['destination'], description=('скачивание; SHA-256 на ПК' if prepared else 'подготовка + скачивание; SHA-256 на ПК')))
    notify('Подключение и проверка имени/ОС')
    try:
        if prepared and (str(source.resolve()), before.st_size, before.st_mtime_ns) != (prepared['path'], prepared['size'], prepared['mtime_ns']):
            raise RuntimeError('Исходный файл изменился после подготовки; скачивание не начато')
        client = access_gate.connect(host, pin, password) if access_gate else connect_verified(host, pin, password)
        sftp = client.open_sftp()
        sftp.get_channel().settimeout(60)
        home = sftp.normalize('.')
        if not home.startswith('/') or home == '/':
            raise RuntimeError('Не подтверждён домашний каталог user')
        folder = home if destination == '~' else (posixpath.join(home, destination[2:]) if destination.startswith('~/') else destination)
        result['destination'] = folder
        # Only inspect here: downloader creates the directory after confirmation.
        target = posixpath.join(folder, source.name)
        overwrite = False
        try:
            existing = sftp.lstat(target)
        except FileNotFoundError:
            pass
        else:
            if not stat.S_ISREG(existing.st_mode):
                raise RuntimeError('Нельзя заменить каталог или ссылку: ' + target)
            if on_conflict is None:
                raise RuntimeError('Файл уже существует; требуется подтверждение перезаписи: ' + target)
            if not on_conflict(target):
                result.update(ok=True, message='Файл пропущен без перезаписи', skipped=[target])
                return result
            overwrite = True
        if prepared:
            digest = prepared['sha256']
        else:
            notify('Подготовка SHA-256')
            with source.open('rb') as stream:
                digest = _digest_stream(stream, lambda n: notify('Подготовка SHA-256', n))
        if access_gate:
            access_gate.check()
        token = uuid.uuid4().hex
        transport = client.get_transport()
        def handler(channel, origin, server):
            threading.Thread(target=_serve_file_channel,
                             args=(channel, source, token, before.st_size, lambda n: notify('Скачивание с учительского ПК', n)),
                             daemon=True).start()
        try:
            port = transport.request_port_forward('127.0.0.1', 0, handler=handler)
        except Exception as error:
            raise RuntimeError('SSH-сервер не разрешил канал скачивания. Используйте «Передать файлы». Причина: ' + str(error))
        script = download_script('http://127.0.0.1:' + str(port) + '/' + token,
                                 folder, source.name, digest, before.st_size, overwrite)
        notify('Ожидание скачивания и проверки SHA-256')
        if access_gate:
            access_gate.check()
        code, output = run(client, '/usr/bin/python3 -c ' + shlex.quote(script), timeout=1800)
        if code != 0:
            raise RuntimeError('Скачивание не подтверждено; проверьте ПК перед повтором. ' + output)
        item = json.loads(output)
        if item.get('sha256') != digest or item.get('path') != target or item.get('bytes') != before.st_size:
            raise RuntimeError('Не подтверждён результат скачивания')
        result['files'].append(item)
        after = source.stat()
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise RuntimeError('Исходный файл изменился во время скачивания; проверьте результат')
        notify('Готово')
        result.update(ok=True, message='Файл скачан и проверен SHA-256', output=target)
    except DownloadStopped as error:
        result.update(message=str(error), cancelled=True)
    except Exception as error:
        operation_error(result, error, password)
    finally:
        if port is not None and transport:
            try:
                transport.cancel_port_forward('127.0.0.1', port)
            except Exception:
                pass
        if sftp:
            sftp.close()
        if client:
            client.close()
    return result
