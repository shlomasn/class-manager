"""SSH power control. No shutdown commands run on import or during discovery."""
import base64
from dataclasses import dataclass, asdict
import hashlib
import ipaddress
import csv
import io
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


class OperationCancelled(RuntimeError):
    pass


class OperationControl:
    """Close live connections and stop queued work when the user exits."""
    def __init__(self, parent=None, reason='Операция остановлена при закрытии CM; проверьте ПК перед повтором'):
        self.parent, self.reason = parent, reason
        self.cancelled = threading.Event()
        self.lock = threading.Lock()
        self.clients = {}

    def check(self):
        if self.cancelled.is_set():
            raise OperationCancelled(self.reason)
        if self.parent:
            self.parent.check()

    # Register at both levels so app shutdown closes all sessions while a host stop stays local.
    def add(self, client):
        if self.parent:
            self.parent.add(client)
        with self.lock:
            stopped = self.cancelled.is_set()
            if not stopped:
                self.clients[id(client)] = client
        if stopped:
            if self.parent:
                self.parent.discard(client)
            client.close()
            self.check()
        self.check()

    def discard(self, client):
        with self.lock:
            self.clients.pop(id(client), None)
        if self.parent:
            self.parent.discard(client)

    def cancel(self):
        with self.lock:
            self.cancelled.set()
            clients = list(self.clients.values())
            self.clients.clear()
        for client in clients:
            if self.parent:
                self.parent.discard(client)
            try:
                client.close()
            except Exception:
                pass


@dataclass(frozen=True)
class Host:
    name: str
    ip: str
    room: str
    mode: str = 'dns'
    username: str = 'user'
    credential_mode: str = 'shared'
    domain: str = ''
    mac: str = ''
    wol_broadcast: str = ''
    mac_type: str = ''
    mac_interface: str = ''


def login_name(value):
    value = value.strip()
    if not re.fullmatch(r'[a-zA-Z_][a-zA-Z0-9_.-]{0,63}[$]?', value):
        raise ValueError('Недопустимый логин SSH')
    return value


def load_csv(path):
    raw = Path(path).read_bytes()
    if len(raw) > 1024 * 1024:
        raise ValueError('Слишком большой CSV')
    try:
        text = raw.decode('utf-8-sig')
    except UnicodeError:
        text = raw.decode('cp1251')
    reader = csv.DictReader(io.StringIO(text), delimiter=';')
    if reader.fieldnames != ['кабинет', 'компьютер', 'логин']:
        raise ValueError('Заголовок CSV: кабинет;компьютер;логин. Паролей в CSV быть не должно.')
    rows = []
    for row in reader:
        if None in row or any(value is None for value in row.values()):
            raise ValueError('Неверное количество колонок CSV')
        login = login_name(row['логин'] or 'user')
        rows.append(dict(name=row['компьютер'], room=row['кабинет'], username=login,
                         credential_mode='host', mode='dns'))
    if not rows:
        raise ValueError('CSV не содержит компьютеров')
    return validate_hosts(rows)


def dns_domain(value):
    value = value.strip().lower().strip('.')
    if value and (len(value) > 253 or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in value.split('.'))):
        raise ValueError('Недопустимый домен')
    return value


def hostname(value):
    name = value.strip().lower()
    if re.fullmatch(r'\d{3}-[a-z0-9-]+', name):
        name = 'a' + name
    if not name or len(name) > 253 or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in name.split('.')):
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
    if not isinstance(rows, list) or len(rows) > 250 or (not rows and path.suffix.lower() != '.json'):
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
        login = login_name(row.get('username', 'user'))
        credentials = row.get('credential_mode', 'shared' if login == 'user' else 'host')
        if credentials not in ('shared', 'host') or (credentials == 'shared' and login != 'user'):
            raise ValueError('Общий пароль доступен только для user')
        kind = row.get('mac_type', '')
        interface = row.get('mac_interface', '')
        if kind not in ('', 'manual', 'ethernet', 'wifi') or not isinstance(interface, str) or len(interface) > 64 or any(ord(c) < 32 for c in interface):
            raise ValueError('Некорректный тип или имя MAC-адаптера')
        result.append(Host(name, ip, room_name(row.get('room', default_room)), mode, login, credentials, dns_domain(row.get('domain', '')),
                           mac_address(row['mac']) if row.get('mac') else '',
                           school_ip(row['wol_broadcast']) if row.get('wol_broadcast') else '', kind, interface))
    return result


def school_ip(value):
    ip = ipaddress.IPv4Address(value)
    if not any(ip in ipaddress.ip_network(network) for network in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')):
        raise ValueError('Требуется локальный IPv4 (10.*, 172.16–31.* или 192.168.*): ' + str(ip))
    return str(ip)


def resolve(host):
    if host.mode == 'fixed':
        return school_ip(host.ip)
    query = host.name + '.' + host.domain if host.domain and '.' not in host.name else host.name
    answers = socket.getaddrinfo(query, 22, socket.AF_INET, socket.SOCK_STREAM)
    addresses = sorted({school_ip(answer[4][0]) for answer in answers})
    if len(addresses) != 1:
        raise ValueError('Имя должно разрешаться в один локальный IPv4; проверьте сеть или задайте постоянный IP')
    return addresses[0]


def load_inventory(path, default_domain=''):
    rooms, hosts, _ = load_profile_inventory(path, default_domain=default_domain)
    return rooms, hosts


def load_profile_inventory(path, default_domain=None, legacy_network=None):
    data = json.loads(Path(path).read_text(encoding='utf-8-sig'))
    if not isinstance(data, dict) or data.get('version') != 2:
        raise ValueError('Неизвестная версия списка')
    if 'domain' in data:
        domain = dns_domain(data['domain'])
    elif legacy_network is not None and legacy_network.exists():
        domain = dns_domain(json.loads(legacy_network.read_text(encoding='utf-8')).get('domain', ''))
    else:
        domain = default_domain
    rooms = [room_name(value) for value in data['rooms']]
    if len(rooms) != len(set(rooms)) or len(rooms) > 100:
        raise ValueError('Повторные классы или более 100 классов')
    rows = data['hosts']
    for row in rows:
        row.setdefault('domain', domain or '')  # Legacy entries can use the profile's configured domain.
    hosts = validate_hosts(rows)
    if any(host.room not in rooms for host in hosts):
        raise ValueError('Компьютер ссылается на отсутствующий класс')
    return rooms, hosts, domain if domain is not None else (hosts[0].domain if hosts else '')


def save_inventory(path, rooms, hosts, *, domain=None):
    payload = dict(version=2, rooms=rooms, hosts=[asdict(host) for host in hosts])
    if domain is not None:
        payload['domain'] = dns_domain(domain)
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


def probe(host, control=None):
    import paramiko
    transport = None
    try:
        if control:
            control.check()
        ip = resolve(host)
        sock = socket.create_connection((ip, 22), timeout=3)
        transport = paramiko.Transport(sock)
        if control:
            control.add(transport)
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
            if control:
                control.discard(transport)


def same_key(left, right):
    return left['type'] == right['type'] and left['key'] == right['key']


def classify_key(row, trusted, catalog):
    # Trust follows the computer name and key, never a DHCP address.
    previous = trusted.get(row['name']) or catalog.get(row['name'])
    if previous and not same_key(previous, row):
        return 'changed'
    return 'trusted' if previous else 'new'


def run(client, command, password=None, timeout=25, on_progress=None, control=None):
    if control:
        control.check()
    channel = client.get_transport().open_session(timeout=8)
    try:
        if control:
            control.check()
        channel.exec_command(command)
        # Do not request a PTY. Never put the password in command arguments.
        if password is not None:
            channel.sendall((password + '\n').encode('utf-8'))
        channel.shutdown_write()
        started = time.monotonic()
        deadline = started + timeout
        last_progress = started - 1
        output = bytearray()
        while time.monotonic() < deadline:
            if control:
                control.check()
            while channel.recv_ready():
                output.extend(channel.recv(8192))
                if len(output) > 64 * 1024:
                    raise RuntimeError('Слишком большой ответ; результат требует проверки')
            while channel.recv_stderr_ready():
                output.extend(channel.recv_stderr(8192))
                if len(output) > 64 * 1024:
                    raise RuntimeError('Слишком большой ответ; результат требует проверки')
            now = time.monotonic()
            if on_progress and now - last_progress >= .5:
                on_progress(dict(elapsed=int(now - started), output=output.decode('utf-8', errors='replace')))
                last_progress = now
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


def execute(host, pin, password, action, minutes, control=None):
    import paramiko
    if not password or '\n' in password or '\r' in password:
        raise ValueError('Некорректный пароль')
    command = power_command(action, minutes)
    ip = school_ip(pin.get('ip', host.ip))
    result = dict(name=host.name, ip=ip, action=action, ok=False)
    power_started = False
    client = paramiko.SSHClient()
    options = dict(control=control) if control else {}
    try:
        if control:
            control.add(client)
        # Pin the probed key before authenticating, in case the endpoint at this IP has changed.
        key = decode_key(pin)
        client.get_host_keys().add(ip, pin['type'], key)
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        client.connect(ip, username=host.username, password=password, look_for_keys=False,
                       allow_agent=False, timeout=4, banner_timeout=6, auth_timeout=8)
        code, actual = run(client, '/bin/hostname -s', **options)
        if code != 0 or actual.strip().lower() != host.name.split('.')[0]:
            raise RuntimeError('Имя ПК не совпало; команда питания не отправлена')
        code, version = run(client, '/usr/bin/cat /etc/astra/build_version', **options)
        if code != 0 or not version.strip().startswith('1.8.4.'):
            raise RuntimeError('Не подтверждена Astra Linux 1.8.4; команда не отправлена')
        power_started = True
        code, text = run(client, command, password=password, **options)
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
        result.update(stop=True, message='Неверный пароль SSH или вход выбранного пользователя запрещён; дальнейшие попытки остановлены')
    except paramiko.BadHostKeyException:
        result['message'] = 'SSH-ключ изменился; пароль не отправлен'
    except (paramiko.SSHException, EOFError, OSError) as error:
        result['message'] = ('Связь прервалась после отправки команды; результат не подтверждён. Проверьте ПК перед повтором' if power_started else str(error).replace(password, '[СКРЫТО]'))
    except Exception as error:
        result['message'] = str(error).replace(password, '[СКРЫТО]')
    finally:
        client.close()
        if control:
            control.discard(client)
    return result


def connect_verified(host, pin, password, control=None):
    """Pinned SSH and host/OS checks shared by upload and command operations."""
    import paramiko
    if not password or '\n' in password or '\r' in password:
        raise ValueError('Некорректный пароль')
    ip = school_ip(pin['ip'])
    client = paramiko.SSHClient()
    options = dict(control=control) if control else {}
    try:
        if control:
            control.add(client)
        key = decode_key(pin)
        client.get_host_keys().add(ip, pin['type'], key)
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        client.connect(ip, username=host.username, password=password, look_for_keys=False,
                       allow_agent=False, timeout=4, banner_timeout=6, auth_timeout=8)
        code, actual = run(client, '/bin/hostname -s', **options)
        if code != 0 or actual.strip().lower() != host.name.split('.')[0]:
            raise RuntimeError('Имя ПК не совпало; операция не выполнялась')
        code, version = run(client, '/usr/bin/cat /etc/astra/build_version', **options)
        if code != 0 or not version.strip().startswith('1.8.4.'):
            raise RuntimeError('Не подтверждена Astra Linux 1.8.4; операция не выполнялась')
        return client
    except BaseException:
        client.close()
        if control:
            control.discard(client)
        raise


def operation_error(result, error, password):
    import paramiko
    if isinstance(error, OperationCancelled):
        result.update(cancelled=True, message=str(error))
    elif isinstance(error, paramiko.AuthenticationException):
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
        raise ValueError('Путь должен начинаться с / или ~/ (домашняя папка выбранного пользователя)')
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


class CommandControl(OperationControl):
    def __init__(self, parent=None):
        super().__init__(parent=parent)
        self.stop_requested = threading.Event()

    def request_stop(self):
        self.stop_requested.set()

    def check_connection(self):
        super().check()

    def check(self):
        self.check_connection()
        if self.stop_requested.is_set():
            raise OperationCancelled('Команда отменена до запуска')


def supervised_script(script, token):
    """Run one Bash process group; stdin is a private stop channel, not user input."""
    program = r'''import json, os, selectors, signal, subprocess, sys, time
cfg = json.loads(CONFIG)
if not all(hasattr(os, name) for name in ('waitid', 'WNOWAIT', 'P_PID')):
    raise RuntimeError('Контроль процессов недоступен: команда не запущена')
child = subprocess.Popen(['/bin/bash', '-c', cfg['script']], stdin=subprocess.DEVNULL,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
selector = selectors.DefaultSelector()
selector.register(child.stdout, selectors.EVENT_READ, 'output')
selector.register(child.stderr, selectors.EVENT_READ, 'output')
selector.register(sys.stdin.buffer, selectors.EVENT_READ, 'control')
pipes = 2
pending = b''
stopping = False
killed = False
stop_time = None
confirmed = True
output_open = True
def emit(data):
    global output_open
    if output_open:
        try:
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()
        except BrokenPipeError:
            output_open = False

def signal_group(sig):
    global confirmed
    try:
        os.killpg(child.pid, sig)
    except ProcessLookupError:
        pass
    except PermissionError:
        confirmed = False

def exited():
    return os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None

try:
    # WNOWAIT reserves the child's PID until all group signalling is finished.
    while not exited() or pipes or (stopping and not killed):
        now = time.monotonic()
        if stopping and now - stop_time >= 3 and not killed:
            signal_group(signal.SIGKILL)
            killed = True
        if stopping and now - stop_time >= 8:
            confirmed = False
            break
        for key, mask in selector.select(.1):
            data = os.read(key.fileobj.fileno(), 8192)
            if not data:
                selector.unregister(key.fileobj)
                if key.data == 'output':
                    pipes -= 1
                continue
            if key.data == 'output':
                emit(data)
            else:
                pending += data
                if len(pending) > 4096:
                    raise RuntimeError('Invalid control message')
                while b'\n' in pending:
                    line, pending = pending.split(b'\n', 1)
                    if line == ('CM_STOP_' + cfg['token']).encode('ascii') and not stopping:
                        stopping, stop_time = True, time.monotonic()
                        signal_group(signal.SIGTERM)
    status = child.wait() if exited() else None
    if status is None:
        confirmed = False
    result = dict(exit=status, cancelled=stopping, stop_confirmed=bool(stopping and confirmed and status is not None))
    emit(('\nCM_RESULT_' + cfg['token'] + ':' + json.dumps(result) + '\n').encode('utf-8'))
finally:
    selector.close()
'''
    return program.replace('CONFIG', repr(json.dumps(dict(script=script, token=token))), 1)


def run_managed(client, command, token, password, timeout, control, on_progress=None):
    control.check()
    channel = client.get_transport().open_session(timeout=8)
    output = bytearray()
    sent_stop = False
    try:
        control.check()
        channel.exec_command(command)
        if password is not None:
            channel.sendall((password + '\n').encode('utf-8'))
        started = time.monotonic()
        deadline = started + timeout
        last_progress = started - 1
        while time.monotonic() < deadline:
            control.check_connection()
            now = time.monotonic()
            # Keep SSH open so the supervisor can signal the Bash group and report the outcome.
            if control.stop_requested.is_set() and not sent_stop:
                channel.sendall(('CM_STOP_' + token + '\n').encode('ascii'))
                sent_stop = True
                deadline = now + 10
            for ready, receive in ((channel.recv_ready, channel.recv), (channel.recv_stderr_ready, channel.recv_stderr)):
                while ready():
                    output.extend(receive(8192))
                    if len(output) > 64 * 1024 + 1024:
                        raise RuntimeError('Слишком большой ответ; результат требует проверки')
            text = output.decode('utf-8', errors='replace')
            marker = '\nCM_RESULT_' + token + ':'
            visible = text.split(marker, 1)[0]
            if len(visible.encode('utf-8')) > 64 * 1024:
                raise RuntimeError('Слишком большой ответ; результат требует проверки')
            if on_progress and now - last_progress >= .5:
                on_progress(dict(elapsed=int(now - started), output=visible))
                last_progress = now
            if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                code = channel.recv_exit_status()
                if marker in text:
                    raw = text.rsplit(marker, 1)[1].strip()
                    status = json.loads(raw)
                    if status['exit'] is not None:
                        code = status['exit'] if status['exit'] >= 0 else 128 - status['exit']
                    return code, visible, status
                return code, text, None
            time.sleep(.04)
        raise RuntimeError('Остановка команды не подтверждена; проверьте ПК перед повтором' if sent_stop else 'Время ожидания истекло; результат не подтверждён. Проверьте ПК перед повтором')
    finally:
        channel.close()


def execute_command(host, pin, password, script, sudo=False, timeout=300, cwd=None, expected_file=None, progress=None, control=None, access_gate=None):
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
    def notify(phase, elapsed=0, output=''):
        if progress:
            safe = output.replace(password, '[СКРЫТО]')
            # Withhold a password prefix split across successive SSH reads.
            for length in range(min(len(password) - 1, len(safe)), 0, -1):
                if safe.endswith(password[:length]):
                    safe = safe[:-length] + '[…]'
                    break
            result['output'] = safe
            progress(dict(phase=phase, elapsed=elapsed, output=safe))
    notify('Подключение и проверка имени/ОС')
    try:
        connection = dict(control=control) if control else {}
        client = access_gate.connect(host, pin, password, **connection) if access_gate else connect_verified(host, pin, password, **connection)
        if access_gate:
            access_gate.check()
        if expected_file is not None:
            notify('Проверка переданного файла SHA-256')
            check = '/usr/bin/sha256sum -- ' + shell_directory(expected_file['path'])
            code, digest = run(client, check, **connection)
            if code != 0 or digest.split()[:1] != [expected_file['sha256']]:
                raise RuntimeError('Переданный файл отсутствует или изменился; запуск отменён')
            result['expected_file'] = expected_file
        managed = isinstance(control, CommandControl)
        token = uuid.uuid4().hex if managed else None
        payload = ('/usr/bin/python3 -u -c ' + shlex.quote(supervised_script(script, token))) if managed else '/bin/bash -c ' + shlex.quote(script)
        command = ('LC_ALL=C sudo -k -S -p \'\' ' if sudo else '') + payload
        if cwd is not None:
            command = '/bin/bash -c ' + shlex.quote('cd -- ' + shell_directory(cwd) + ' && ' + command)
        if access_gate:
            access_gate.check()
        notify('Выполняется')
        options = dict(password=password if sudo else None, timeout=timeout, **connection)
        if progress:
            options['on_progress'] = lambda value: notify('Остановка команды' if managed and control.stop_requested.is_set() else 'Выполняется', value['elapsed'], value['output'])
        if managed:
            code, output, status = run_managed(client, command, token, **options)
        else:
            code, output = run(client, command, **options)
            status = None
        output = output.replace(password, '[СКРЫТО]')
        result.update(ok=code == 0, exit=code, output=output,
                      command=script.replace(password, '[СКРЫТО]'), sudo=sudo,
                      message='Команда завершена, код ' + str(code))
        if managed and control.stop_requested.is_set():
            result.update(stop_requested=True, stop_confirmed=False)
        if managed and status is None and code == 0:
            result.update(ok=False, message='Завершение команды не подтверждено; проверьте ПК перед повтором')
        if status and status.get('cancelled'):
            confirmed = bool(status.get('stop_confirmed'))
            result.update(ok=False, cancelled=True, stop_confirmed=confirmed,
                          message='Команда остановлена' if confirmed else 'Остановка команды не подтверждена; проверьте ПК перед повтором')
        if code == -1:
            result['message'] = 'Остановка команды не подтверждена; проверьте ПК перед повтором' if result.get('stop_requested') else 'Соединение закрыто; результат команды не подтверждён'
        if sudo and code != 0 and ('incorrect password' in output.lower() or 'authentication failure' in output.lower()):
            result.update(stop=True, message='Ошибка пароля sudo; дальнейшие попытки остановлены')
    except Exception as error:
        operation_error(result, error, password)
        if isinstance(control, CommandControl) and control.stop_requested.is_set():
            result.update(stop_requested=True, stop_confirmed=False)
    finally:
        if access_gate and result.get('stop'):
            access_gate.stopped.set()
        if client:
            client.close()
            if control:
                control.discard(client)
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


def transfer_files(host, pin, password, paths, batch, destination=None, progress=None, on_conflict=None, access_gate=None, prepared=None, control=None):
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
    passes = 2 if prepared is not None else 3
    total = sum(p.stat().st_size for p in sources) * passes
    done = 0
    def notify(phase, filename='', delta=0):
        nonlocal done
        if control:
            control.check()
        done += delta
        if progress:
            progress(dict(phase=phase, file=filename, done=done, total=total, destination=result['destination']))
    notify('Подключение и проверка имени/ОС')
    client = None
    sftp = None
    try:
        connection = dict(control=control) if control else {}
        client = access_gate.connect(host, pin, password, **connection) if access_gate else connect_verified(host, pin, password, **connection)
        sftp = client.open_sftp()
        sftp.get_channel().settimeout(60)
        home = sftp.normalize('.')
        if not home.startswith('/') or home == '/':
            raise RuntimeError('Не подтверждён домашний каталог выбранного пользователя')
        destination = home if requested == '~' else (posixpath.join(home, requested[2:]) if requested.startswith('~/') else requested)
        result['destination'] = destination
        ensure_remote_directory(sftp, destination)
        for source in sources:
            if access_gate:
                access_gate.check()
            before = source.stat()
            item = prepared[str(source.resolve())] if prepared is not None else None
            if item and (before.st_size, before.st_mtime_ns) != (item['size'], item['mtime_ns']):
                raise RuntimeError('Исходный файл изменился после подготовки: ' + source.name)
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
                    notify('Пропущен без перезаписи', source.name, before.st_size * passes)
                    continue
                overwrite = True
            if item:
                local_hash = item['sha256']
            else:
                notify('Подготовка SHA-256', source.name)
                with source.open('rb') as stream:
                    local_hash = _digest_stream(stream, lambda n: notify('Подготовка SHA-256', source.name, n))
            if access_gate:
                access_gate.check()
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
                # Publish the final name after verifying the temporary copy. Replacing an
                # existing file requires a fresh destination check and atomic rename.
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
    except TransferStopped as error:
        result.update(message=str(error), cancelled=True)
    except Exception as error:
        if control:
            try:
                control.check()
            except OperationCancelled as cancelled:
                error = cancelled
        operation_error(result, error, password)
        # Keep already verified files and list them in the report on partial failure.
    finally:
        if sftp:
            sftp.close()
        if client:
            client.close()
            if control:
                control.discard(client)
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
            if not any(network.subnet_of(ipaddress.ip_network(private)) for private in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')) or network.num_addresses > limit + 2:
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


def local_network_rows(payload, platform):
    """Normalize OS interface addresses; never infer a netmask from an IP."""
    candidates = []
    if platform == 'windows':
        for row in payload if isinstance(payload, list) else [payload]:
            if row:
                candidates.append((row.get('InterfaceAlias', ''), row.get('IPAddress', ''), row.get('PrefixLength')))
    else:
        for row in payload:
            if 'UP' not in row.get('flags', []) or 'LOOPBACK' in row.get('flags', []) or row.get('operstate') == 'DOWN':
                continue
            for address in row.get('addr_info', []):
                if address.get('family') == 'inet':
                    candidates.append((row.get('ifname', ''), address.get('local', ''), address.get('prefixlen')))
    result, seen = [], set()
    for interface, address, prefix in candidates:
        try:
            ip = school_ip(address)
            if type(prefix) is not int or not 0 <= prefix <= 32:
                continue
            network = ipaddress.IPv4Network(ip + '/' + str(prefix), strict=False)
            if not any(network.subnet_of(ipaddress.ip_network(private)) for private in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')):
                continue
            key = (interface, ip, str(network))
            if key not in seen:
                seen.add(key)
                result.append(dict(interface=str(interface), ip=ip, network=str(network)))
        except (ValueError, TypeError):
            continue
    return sorted(result, key=lambda row: (row['interface'], int(ipaddress.IPv4Address(row['ip']))))


def detect_local_networks():
    """Read connected IPv4 interfaces without admin privileges or network probes."""
    import shutil
    import subprocess
    import sys
    if os.name == 'nt':
        tool = shutil.which('powershell.exe')
        if not tool:
            raise RuntimeError('Windows PowerShell недоступен. Используйте ручной диапазон IP.')
        script = ("$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[System.Text.Encoding]::UTF8; "
                  "@(Get-NetIPInterface -AddressFamily IPv4 -ConnectionState Connected | "
                  "ForEach-Object { Get-NetIPAddress -InterfaceIndex $_.InterfaceIndex -AddressFamily IPv4 -AddressState Preferred -ErrorAction SilentlyContinue } | "
                  "Select-Object InterfaceAlias,IPAddress,PrefixLength) | ConvertTo-Json -Compress")
        command, platform = [tool, '-NoProfile', '-NonInteractive', '-Command', script], 'windows'
    elif sys.platform.startswith('linux'):
        tool = shutil.which('ip') or next((str(p) for p in (Path('/usr/sbin/ip'),Path('/sbin/ip')) if p.exists()), None)
        if not tool:
            raise RuntimeError('Не найдена команда ip (пакет iproute2). Используйте ручной диапазон IP.')
        command, platform = [tool, '-j', '-4', 'address', 'show', 'up'], 'linux'
    else:
        raise RuntimeError('Автоопределение сети поддерживается на Windows и Linux/Astra. Используйте ручной диапазон IP.')
    try:
        options = dict(creationflags=subprocess.CREATE_NO_WINDOW) if os.name == 'nt' else {}
        completed = subprocess.run(command, capture_output=True, timeout=15, **options)
        if completed.returncode or len(completed.stdout) > 1024 * 1024:
            raise ValueError('Не получены настройки интерфейсов')
        text = completed.stdout.decode('utf-8-sig')
        return local_network_rows(json.loads(text) if text.strip() else [], platform)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        raise RuntimeError('Не удалось прочитать локальные сети. Используйте ручной диапазон IP.') from None


def automatic_scan_plan(row, part=None, exclude=()):
    network = ipaddress.IPv4Network(row['network'])
    # A large real subnet is explicitly divided into /24 blocks, never silently scanned in full.
    parts = 2 ** (24 - network.prefixlen) if network.prefixlen < 23 else 1
    default = (int(ipaddress.IPv4Address(row['ip'])) - int(network.network_address)) // 256 + 1 if parts > 1 else 1
    part = default if part is None else part
    if type(part) is not int or not 1 <= part <= parts:
        raise ValueError('Выберите допустимый номер части сети')
    selected = ipaddress.IPv4Network((int(network.network_address) + (part - 1) * 256, 24)) if parts > 1 else network
    addresses = [ip for ip in parse_addresses(str(selected)) if ip not in set(exclude) | {row['ip']}]
    return dict(network=str(selected), addresses=addresses, parts=parts, part=part, partial=parts > 1)


def probe_address(ip, control=None):
    # No authentication or mutation during the first scan phase.
    import paramiko
    transport = None
    try:
        if control:
            control.check()
        ip = school_ip(ip)
        transport = paramiko.Transport(socket.create_connection((ip, 22), timeout=1.5))
        if control:
            control.add(transport)
        transport.start_client(timeout=4)
        key = transport.get_remote_server_key()
        return dict(ip=ip, ok=True, type=key.get_name(), key=key.get_base64(), fingerprint=fingerprint(key))
    except Exception:
        return dict(ip=ip, ok=False)
    finally:
        if transport:
            transport.close()
            if control:
                control.discard(transport)


def inspect_address(pin, password, control=None, username='user'):
    """Get the actual hostname through pinned SSH; never trust PTR as identity."""
    if not password or "\n" in password or "\r" in password:
        raise ValueError("Некорректный пароль")
    import paramiko
    client = paramiko.SSHClient()
    result = dict(pin, ok=False)
    options = dict(control=control) if control else {}
    try:
        if control:
            control.add(client)
        key = decode_key(pin)
        client.get_host_keys().add(pin['ip'], pin['type'], key)
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        client.connect(pin['ip'], username=login_name(username), password=password, look_for_keys=False,
                       allow_agent=False, timeout=4, banner_timeout=5, auth_timeout=8)
        code, actual = run(client, '/bin/hostname -s', **options)
        name = hostname(actual.strip())
        if code != 0 or name != actual.strip().lower():
            raise RuntimeError('Имя ПК не подходит; требуется проверка имени')
        code, version = run(client, '/usr/bin/cat /etc/astra/build_version', **options)
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
        if control:
            control.discard(client)
    return result


class TransferStopped(RuntimeError):
    pass


class TransferAccessGate:
    """Serialize password attempts only; file transfers run concurrently."""
    def __init__(self, control=None):
        self.control = control
        self.lock = threading.Lock()
        self.stopped = threading.Event()

    def check(self):
        if self.control:
            self.control.check()
        if self.stopped.is_set():
            raise TransferStopped('Пропущен после ошибки доступа; повторных попыток нет')

    def connect(self, host, pin, password, control=None):
        import paramiko
        effective = control or self.control
        # Serialize logins so authentication failures can stop queued attempts.
        # Workers can continue independently once connected.
        while not self.lock.acquire(timeout=.2):
            self.check()
            if effective:
                effective.check()
        try:
            self.check()
            try:
                if effective:
                    effective.check()
                options = dict(control=effective) if effective else {}
                return connect_verified(host, pin, password, **options)
            except paramiko.AuthenticationException:
                if effective:
                    effective.check()  # A stop request is not a password failure.
                self.stopped.set()
                raise
        finally:
            self.lock.release()


def prepare_transfer(path, progress=None):
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


def time_sync_script(token):
    """Remote half of the clock exchange. No NTP, timezone or RTC configuration writes."""
    program = r'''import datetime, json, math, sys, time
token = TOKEN
if not hasattr(time, 'clock_settime') or not hasattr(time, 'CLOCK_REALTIME'):
    raise RuntimeError('Установка системного времени не поддерживается')
def read():
    line = sys.stdin.buffer.readline(4097)
    if not line or len(line) > 4096:
        raise RuntimeError('Связь с учителем потеряна до установки времени')
    return json.loads(line)
print('CM_TIME_READY:' + token, flush=True)
probe = read()
if probe != dict(token=token, action='probe'):
    raise RuntimeError('Некорректный запрос проверки задержки')
print('CM_TIME_ACK:' + token, flush=True)
request = read()
if request.get('token') != token or request.get('action') != 'set':
    raise RuntimeError('Некорректный запрос синхронизации')
target = request.get('epoch')
if type(target) not in (int, float) or not math.isfinite(target) or not 0 < target < 253402300799:
    raise RuntimeError('Некорректное время учителя')
before = time.time()
time.clock_settime(time.CLOCK_REALTIME, target)
after = time.time()
if abs(after - target) > 1:
    raise RuntimeError('Новое время не подтверждено после установки')
def display(epoch):
    return datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).astimezone().isoformat(timespec='seconds')
result = dict(before=before, after=after, target=target, before_local=display(before),
              after_local=display(after), timezone=time.tzname, correction_seconds=target-before)
print('CM_TIME_RESULT:' + token + ':' + json.dumps(result), flush=True)
'''
    return program.replace('TOKEN', repr(token), 1)


def synchronize_time(host, pin, password, progress=None, control=None, access_gate=None, clock_source=None):
    """Send a fresh teacher timestamp only after verified SSH, sudo and an RTT probe."""
    import math
    result = dict(name=host.name, ip=pin['ip'], action='time_sync', ok=False, source='teacher', sent=False)
    client = channel = None
    started = time.monotonic()
    deadline = started + 60
    buffer = bytearray()
    diagnostics = bytearray()
    def notify(phase):
        if control:
            control.check()
        if progress:
            progress(dict(phase=phase, elapsed=int(time.monotonic()-started), output=''))
    def line(prefix):
        while time.monotonic() < deadline:
            if control:
                control.check()
            while channel.recv_ready():
                buffer.extend(channel.recv(8192))
                if len(buffer) > 16384:
                    raise RuntimeError('Слишком большой ответ синхронизации')
            while channel.recv_stderr_ready():
                diagnostics.extend(channel.recv_stderr(8192))
                if len(diagnostics) > 16384:
                    raise RuntimeError('Слишком большой ответ синхронизации')
            while b'\n' in buffer:
                value, remainder = buffer.split(b'\n', 1)
                buffer[:] = remainder
                value = value.decode('utf-8', errors='replace').rstrip('\r')
                if value.startswith(prefix):
                    return value[len(prefix):]
            if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                raise RuntimeError('Синхронизация не подтверждена: ' + diagnostics.decode('utf-8', errors='replace').strip())
            time.sleep(.02)
        raise RuntimeError('Время ожидания синхронизации истекло; результат не подтверждён')
    def send(data):
        if control:
            control.check()
        channel.sendall((json.dumps(data) + '\n').encode('utf-8'))
    try:
        notify('Подключение и проверка имени/ОС')
        options = dict(control=control) if control else {}
        client = access_gate.connect(host, pin, password, **options) if access_gate else connect_verified(host, pin, password, **options)
        if access_gate:
            access_gate.check()
        token = uuid.uuid4().hex
        notify('Проверка прав установки времени')
        channel = client.get_transport().open_session(timeout=8)
        channel.exec_command("LC_ALL=C sudo -k -S -p '' /usr/bin/python3 -u -c " + shlex.quote(time_sync_script(token)))
        channel.sendall((password + '\n').encode('utf-8'))
        line('CM_TIME_READY:' + token)
        if access_gate:
            access_gate.check()
        notify('Измерение задержки связи')
        probe_started = time.monotonic()
        send(dict(token=token, action='probe'))
        line('CM_TIME_ACK:' + token)
        rtt = time.monotonic()-probe_started
        if rtt > 5:
            raise RuntimeError('Слишком большая задержка связи; время не изменено. Повторите после проверки сети')
        if access_gate:
            access_gate.check()
        notify('Установка времени учителя')
        # Compute at the last possible moment, not during selection/confirmation/SSH login.
        teacher = (clock_source or time.time)()
        if type(teacher) not in (int, float) or not math.isfinite(teacher) or not 0 < teacher < 253402300799:
            raise ValueError('Проверьте дату и время компьютера учителя')
        target = teacher + rtt/2
        result.update(sent=True, teacher_epoch=teacher, target_epoch=target, round_trip_ms=round(rtt*1000, 2))
        send(dict(token=token, action='set', epoch=target))
        notify('Проверка установленного времени')
        detail = json.loads(line('CM_TIME_RESULT:' + token + ':'))
        if not all(type(detail.get(key)) in (int, float) and math.isfinite(detail[key]) for key in ('before', 'after', 'target')) or abs(detail['target']-target) > .001 or abs(detail['after']-target) > 1:
            raise RuntimeError('Ответ не подтверждает установленное время')
        result.update(ok=True, time=detail, message='Время синхронизировано с компьютером учителя',
                      output='Было: ' + detail['before_local'] + '\nСтало: ' + detail['after_local']
                             + '\nПоправка, секунд: ' + str(round(detail['target']-detail['before'], 3))
                             + '\nЗадержка обмена, мс: ' + str(result['round_trip_ms'])
                             + '\nЧасовой пояс и настройки NTP не изменялись.')
    except Exception as error:
        operation_error(result, error, password)
        text = str(error).lower()
        if 'incorrect password' in text or 'authentication failure' in text:
            result.update(stop=True, message='Ошибка пароля sudo; дальнейшие попытки остановлены')
        elif result['sent']:
            result['message'] = 'Запрос установки времени отправлен; результат не подтверждён. Проверьте ПК перед повтором. ' + result.get('message', '')
    finally:
        if result.get('stop') and access_gate:
            access_gate.stopped.set()
        if channel:
            channel.close()
        if client:
            client.close()
            if control:
                control.discard(client)
    return result

def mac_address(value):
    value = value.strip().replace(':', '').replace('-', '').lower()
    if not re.fullmatch(r'[0-9a-f]{12}', value) or int(value[:2], 16) & 1 or value == '0' * 12:
        raise ValueError('Нужен индивидуальный MAC Ethernet: AA:BB:CC:DD:EE:FF')
    return ':'.join(value[index:index + 2] for index in range(0, 12, 2))


def magic_packet(mac):
    return b'\xff' * 6 + bytes.fromhex(mac_address(mac).replace(':', '')) * 16


def wake_plan(host, networks):
    mac = mac_address(host.mac)
    if not host.wol_broadcast:
        raise ValueError(host.name + ': сначала получите MAC и адрес рассылки или задайте их в карточке ПК')
    broadcast = school_ip(host.wol_broadcast)
    matches = [row for row in networks if str(ipaddress.IPv4Network(row['network']).broadcast_address) == broadcast
               and ipaddress.IPv4Network(row['network']).prefixlen <= 30]
    # Bind to the teacher interface matching the broadcast. Reject ambiguous matches.
    sources = {row['ip'] for row in matches}
    if len(sources) != 1:
        raise ValueError(host.name + ': сеть WoL не подключена к учителю или подходит несколько интерфейсов; проверьте подключение и адрес рассылки')
    return dict(mac=mac, broadcast=broadcast, source=next(iter(sources)))


def mac_collection_script():
    """Read the address from sysfs: ip -j -4 may omit the link-level address."""
    return r'''import ipaddress,json,os,shutil,subprocess,sys
ip=sys.argv[1]
tool=shutil.which('ip') or next((p for p in ('/usr/sbin/ip','/sbin/ip') if os.path.exists(p)),None)
if not tool: raise SystemExit('Нужен пакет iproute2')
try:
    rows=json.loads(subprocess.check_output([tool,'-j','-4','address','show'],timeout=8))
    found=[]
    for row in rows:
        name=row.get('ifname','')
        if not name or '/' in name or name in ('.','..','lo'):
            continue
        base='/sys/class/net/'+name
        wifi=os.path.exists(base+'/wireless') or os.path.exists(base+'/phy80211')
        for addr in row.get('addr_info',[]):
            if addr.get('family')!='inet' or addr.get('local')!=ip:
                continue
            if not wifi and not os.path.exists(base+'/device'):
                raise SystemExit('IP подключения принадлежит виртуальному адаптеру; задайте нужный MAC вручную')
            prefix=addr['prefixlen']
            net=ipaddress.IPv4Network(ip+'/'+str(prefix),strict=False)
            with open(base+'/address',encoding='ascii') as stream:
                mac=stream.read().strip()
            found.append(dict(mac=mac,interface=name,mac_type='wifi' if wifi else 'ethernet',broadcast=str(net.broadcast_address),prefix=prefix))
    if len(found)!=1:
        raise SystemExit('Не найден единственный адаптер с IP подключения SSH; проверьте адрес компьютера')
    print(json.dumps(found[0]))
except (OSError,ValueError,KeyError,subprocess.SubprocessError) as error:
    raise SystemExit('Не удалось прочитать MAC адаптера: '+str(error))
'''


def collect_mac(host, pin, password, control=None, access_gate=None):
    result = dict(name=host.name, ip=pin['ip'], action='collect_mac', ok=False)
    client = None
    try:
        if access_gate:
            client = access_gate.connect(host, pin, password, control)
        else:
            client = connect_verified(host, pin, password, control)
        script = mac_collection_script()
        command = 'python3 -c ' + shlex.quote(script) + ' ' + shlex.quote(school_ip(pin['ip']))
        code, output = run(client, command, timeout=15, **(dict(control=control) if control else {}))
        if code:
            safe_output = output.replace(password, '[СКРЫТО]')
            result['diagnostic'] = safe_output[:4096]
            detail = next((line.strip() for line in reversed(safe_output.splitlines()) if line.strip()), 'нет ответа')
            raise RuntimeError('Не удалось получить MAC: ' + detail[:220])
        value = json.loads(output)
        mac = mac_address(value['mac'])
        prefix = value['prefix']
        if type(prefix) is not int or not 8 <= prefix <= 30:
            raise ValueError('Для WoL нужна обычная локальная подсеть с адресом рассылки')
        net = ipaddress.IPv4Network(pin['ip'] + '/' + str(prefix), strict=False)
        if not any(net.subnet_of(ipaddress.ip_network(private)) for private in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16')) or str(net.broadcast_address) != value['broadcast']:
            raise ValueError('Не подтверждён локальный адрес рассылки')
        kind = value.get('mac_type', 'ethernet')
        if kind not in ('ethernet', 'wifi'):
            raise ValueError('Неизвестный тип адаптера')
        result.update(ok=True, mac=mac, wol_broadcast=value['broadcast'], interface=value['interface'], mac_type=kind,
                      message='MAC ' + ('Wi-Fi' if kind == 'wifi' else 'Ethernet') + ' получен: ' + mac + ', рассылка ' + value['broadcast'] + ('; включение Wi-Fi не гарантируется' if kind == 'wifi' else ''))
    except Exception as error:
        operation_error(result, error, password)
        if result.get('stop') and access_gate:
            access_gate.stopped.set()
    finally:
        if client:
            client.close()
            if control: control.discard(client)
    return result


def wake_computer(host, plan, expected_key, control=None, progress=None, timeout=180):
    result = dict(name=host.name, ip='', action='wake', ok=False, sent=False)
    try:
        if not expected_key:
            raise ValueError('Нет доверенного SSH-ключа: сначала получите MAC на включённом ПК')
        if control: control.check()
        before = probe(host, control=control)
        if before.get('ok'):
            if not same_key(before, expected_key):
                raise RuntimeError('SSH-ключ изменился; включение не отправлялось')
            result.update(ok=True, ip=before['ip'], message='ПК уже доступен по SSH, ключ проверен; пакет WoL не отправлялся')
            return result
        if control: control.check()
        # One packet only: no automatic retransmission or router configuration.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            sender.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sender.bind((school_ip(plan['source']), 0))
            count = sender.sendto(magic_packet(plan['mac']), (school_ip(plan['broadcast']), 9))
            if count != 102: raise RuntimeError('Пакет WoL отправлен не полностью')
        result['sent'] = True
        # UDP send confirms local submission. The pinned SSH key identifies the expected PC.
        started = time.monotonic()
        while time.monotonic() - started < timeout:
            if control: control.check()
            if progress:
                progress('Запрос включения отправлен; ожидание SSH ' + str(int(time.monotonic() - started)) + '/' + str(timeout) + ' с')
            current = probe(host, control=control)
            if current.get('ok'):
                if not same_key(current, expected_key):
                    raise RuntimeError('После WoL обнаружен другой SSH-ключ; появление нужного ПК не подтверждено')
                result.update(ok=True, ip=current['ip'], message='После запроса WoL появился SSH с доверенным ключом')
                return result
            pause_until = min(started + timeout, time.monotonic() + 3)
            while time.monotonic() < pause_until:
                if control: control.check()
                time.sleep(.2)
        result['message'] = 'Запрос WoL отправлен; появление ПК за отведённое время не подтверждено. Автоповтора нет'
    except OperationCancelled:
        result.update(cancelled=True, message='Ожидание остановлено; уже отправленный WoL не отменяет включение' if result['sent'] else 'Включение отменено до отправки')
    except Exception as error:
        result['message'] = str(error)
    return result
