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


def execute_command(host, pin, password, script, sudo=False, timeout=300):
    if not script.strip() or len(script.encode('utf-8')) > 32 * 1024 or '\x00' in script:
        raise ValueError('Введите команду длиной до 32 КБ без NUL')
    if type(timeout) is not int or not 10 <= timeout <= 1800:
        raise ValueError('Ожидание команды: от 10 до 1800 секунд')
    result = dict(name=host.name, ip=pin['ip'], action='command', ok=False)
    client = None
    try:
        client = connect_verified(host, pin, password)
        command = ('LC_ALL=C sudo -k -S -p \'\' ' if sudo else '') + '/bin/bash -c ' + shlex.quote(script)
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


def _digest_stream(stream):
    digest = hashlib.sha256()
    while True:
        chunk = stream.read(1024 * 1024)
        if not chunk:
            return digest.hexdigest()
        digest.update(chunk)


def transfer_files(host, pin, password, paths, batch):
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
    result = dict(name=host.name, ip=pin['ip'], action='upload', ok=False, files=[])
    client = None
    sftp = None
    try:
        client = connect_verified(host, pin, password)
        sftp = client.open_sftp()
        sftp.get_channel().settimeout(60)
        home = sftp.normalize('.')
        if not home.startswith('/') or home == '/':
            raise RuntimeError('Не подтверждён домашний каталог user')
        parent = posixpath.join(home, 'CM-Inbox')
        try:
            info = sftp.lstat(parent)
            if not stat.S_ISDIR(info.st_mode):
                raise RuntimeError('CM-Inbox не является обычным каталогом')
        except FileNotFoundError:
            sftp.mkdir(parent, 0o700)
        destination = posixpath.join(parent, batch)
        sftp.mkdir(destination, 0o700)  # Never overwrite an existing batch.
        for source in sources:
            before = source.stat()
            with source.open('rb') as stream:
                local_hash = _digest_stream(stream)
            target = posixpath.join(destination, source.name)
            temporary = target + '.part'
            try:
                sftp.put(str(source), temporary, confirm=True)
                sftp.chmod(temporary, 0o600)
                with sftp.open(temporary, 'rb') as stream:
                    remote_hash = _digest_stream(stream)
                after = source.stat()
                if local_hash != remote_hash or (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                    raise RuntimeError('Файл изменился или контрольная сумма не совпала: ' + source.name)
                sftp.rename(temporary, target)
            except BaseException:
                try:
                    sftp.remove(temporary)
                except Exception:
                    pass
                raise
            result['files'].append(dict(path=target, sha256=local_hash, bytes=before.st_size))
        result.update(ok=True, message='Передано файлов: ' + str(len(sources)), output='\n'.join(item['path'] for item in result['files']))
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
