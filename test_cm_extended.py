import io
import json
import os
from pathlib import Path
import shutil
import tempfile
import types
import unittest
from unittest.mock import patch

import paramiko
import cm_core as core
import credential_store as store
import class_manager as gui


class RangeTests(unittest.TestCase):
    def test_formats_and_deduplication(self):
        self.assertEqual(core.parse_addresses('192.168.22.2-192.168.22.4, 192.168.22.2;192.168.22.8/31'),
                         ['192.168.22.2', '192.168.22.3', '192.168.22.4', '192.168.22.8', '192.168.22.9'])
        self.assertEqual(core.parse_addresses('192.168.201.39/32'), ['192.168.201.39'])

    def test_scope_and_size_limits_before_enumeration(self):
        for value in ['', '8.8.8.8', '192.168.0.0/16', '192.168.22.4-192.168.22.2',
                      '192.168.22.2-192.169.22.3', '192.168.0.1-192.168.3.1', '192.168.22.1;rm']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                core.parse_addresses(value)

    def test_legacy_and_current_key_decoding(self):
        root = Path(__file__).resolve().parent
        catalog = root / 'key-catalog.json'
        if not catalog.exists():
            catalog = root.parents[1] / 'outputs/CM-Astra/key-catalog.json'
        pin = next(iter(json.loads(catalog.read_text()).values()))
        current = core.decode_key(pin)
        with patch.object(paramiko, 'PKey', types.SimpleNamespace()):
            legacy = core.decode_key(pin)
        self.assertEqual(current.asbytes(), legacy.asbytes())
        self.assertEqual(core.fingerprint(current), pin['fingerprint'])


class CommandTests(unittest.TestCase):
    host = core.Host('a209-06', '', '209')
    pin = dict(ip='192.168.22.26')

    def test_sudo_script_is_quoted_password_only_stdin_output_redacted(self):
        client = types.SimpleNamespace(close=lambda: None)
        script = "printf '%s' 'one; two'\nprintf '%s' '$HOME'"
        with patch.object(core, 'connect_verified', return_value=client), patch.object(core, 'run', return_value=(0, 'output secret')) as run:
            result = core.execute_command(self.host, self.pin, 'secret', script, True, 120)
        self.assertTrue(result['ok'])
        self.assertNotIn('secret', json.dumps(result))
        self.assertEqual(run.call_args.kwargs['password'], 'secret')
        self.assertEqual(run.call_args.kwargs['timeout'], 120)
        self.assertNotIn('secret', run.call_args.args[1])
        import shlex
        self.assertEqual(shlex.split(run.call_args.args[1])[-1], script)

    def test_nonroot_command_and_failure_exit_are_reported(self):
        client = types.SimpleNamespace(close=lambda: None)
        with patch.object(core, 'connect_verified', return_value=client), patch.object(core, 'run', return_value=(7, 'problem')) as run:
            result = core.execute_command(self.host, self.pin, 'secret', 'exit 7', False)
        self.assertFalse(result['ok'])
        self.assertEqual(result['exit'], 7)
        self.assertNotIn('sudo', run.call_args.args[1])
        self.assertIsNone(run.call_args.kwargs['password'])

    def test_wrong_sudo_password_stops_batch(self):
        client = types.SimpleNamespace(close=lambda: None)
        with patch.object(core, 'connect_verified', return_value=client), patch.object(core, 'run', return_value=(1, '1 incorrect password attempt')):
            result = core.execute_command(self.host, self.pin, 'secret', 'id', True)
        self.assertTrue(result['stop'])

    def test_invalid_command_never_connects(self):
        for script, timeout in [('', 300), ('a\x00b', 300), ('x' * 33000, 300), ('id', 5)]:
            with patch.object(core, 'connect_verified') as connect, self.assertRaises(ValueError):
                core.execute_command(self.host, self.pin, 'secret', script, False, timeout)
            connect.assert_not_called()

    def test_working_directory_quoted_and_missing_directory_blocks_script(self):
        import subprocess
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder) / "folder ' ; $name"
            directory.mkdir()
            client = types.SimpleNamespace(close=lambda: None)
            def run(client, command, **kwargs):
                result = subprocess.run(['/bin/bash', '-c', command], capture_output=True, text=True,
                                        env=dict(os.environ, HOME=folder))
                return result.returncode, result.stdout + result.stderr
            with patch.object(core, 'connect_verified', return_value=client), patch.object(core, 'run', run):
                result = core.execute_command(self.host, self.pin, 'secret', 'pwd', cwd="~/folder ' ; $name")
                self.assertTrue(result['ok'])
                self.assertEqual(result['output'].strip(), str(directory))
                marker = Path(folder) / 'marker'
                result = core.execute_command(self.host, self.pin, 'secret', 'touch ' + str(marker), cwd='~/missing')
                self.assertFalse(result['ok'])
                self.assertFalse(marker.exists())

    def test_sudo_changes_directory_before_privilege_escalation(self):
        import shlex
        client = types.SimpleNamespace(close=lambda: None)
        with patch.object(core, 'connect_verified', return_value=client), patch.object(core, 'run', return_value=(0, 'ok')) as run:
            result = core.execute_command(self.host, self.pin, 'secret', "sh './setup.sh'", True, cwd='~/lesson files')
        self.assertTrue(result['ok'])
        outer = shlex.split(run.call_args.args[1])[-1]
        self.assertTrue(outer.startswith('cd -- "$HOME"/'))
        self.assertLess(outer.index(' && '), outer.index('sudo'))
        self.assertNotIn('secret', outer)

    def test_invalid_directory_never_connects(self):
        for value in ['', 'relative/path', '~root', '/tmp/../etc', '~/bad\npath', '/tmp/\x00']:
            with self.subTest(value=value), patch.object(core, 'connect_verified') as connect, self.assertRaises(ValueError):
                core.execute_command(self.host, self.pin, 'secret', 'id', cwd=value)
            connect.assert_not_called()

    def test_selected_file_command_quotes_filename_and_sets_sudo(self):
        import shlex
        spec = core.file_launch_spec("/home/user/Desktops/Desktop1/CM-Inbox/setup ' $;.sh", 'a' * 64)
        self.assertFalse(spec['sudo'])
        self.assertEqual(shlex.split(spec['script']), ['/bin/bash', "./setup ' $;.sh"])
        self.assertEqual(spec['cwd'], '/home/user/Desktops/Desktop1/CM-Inbox')
        self.assertTrue(core.file_launch_spec('/home/user/a.deb', 'a' * 64)['sudo'])

    def test_changed_transferred_file_blocks_execution(self):
        client = types.SimpleNamespace(close=lambda: None)
        spec = core.file_launch_spec('/home/user/setup.sh', 'a' * 64)
        with patch.object(core, 'connect_verified', return_value=client), patch.object(core, 'run', return_value=(0, 'b' * 64 + '  file')) as run:
            result = core.execute_command(self.host, self.pin, 'secret', spec['script'], cwd=spec['cwd'], expected_file=spec['expected_file'])
        self.assertFalse(result['ok'])
        run.assert_called_once()
        self.assertIn('запуск отменён', result['message'])

    def test_matching_transferred_file_allows_execution(self):
        client = types.SimpleNamespace(close=lambda: None)
        spec = core.file_launch_spec('/home/user/setup.sh', 'a' * 64)
        with patch.object(core, 'connect_verified', return_value=client), patch.object(core, 'run', side_effect=[(0, 'a' * 64 + '  file'), (0, 'done')]) as run:
            result = core.execute_command(self.host, self.pin, 'secret', spec['script'], cwd=spec['cwd'], expected_file=spec['expected_file'])
        self.assertTrue(result['ok'])
        self.assertEqual(run.call_count, 2)


class UploadTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.home = self.base / 'remote-home'
        self.home.mkdir()
        self.inbox = self.home / 'Desktops/Desktop1/CM-Inbox'
        self.inbox.parent.mkdir(parents=True)
        self.source = self.base / "app 'test';$.deb"
        self.source.write_bytes(b'package contents')
        outer = self
        class SFTP:
            def get_channel(self): return types.SimpleNamespace(settimeout=lambda n: None)
            def normalize(self, path): return str(outer.home)
            def lstat(self, path): return Path(path).lstat()
            def mkdir(self, path, mode): Path(path).mkdir(mode=mode)
            def put(self, source, path, confirm, callback):
                shutil.copyfile(source, path)
                callback(Path(source).stat().st_size, Path(source).stat().st_size)
                if getattr(outer, 'tamper', False):
                    Path(path).write_bytes(b'changed')
            def chmod(self, path, mode): Path(path).chmod(mode)
            def open(self, path, mode): return open(path, mode)
            def rename(self, source, target):
                if Path(target).exists(): raise FileExistsError(target)
                os.rename(source, target)
            def posix_rename(self, source, target): os.replace(source, target)
            def remove(self, path): Path(path).unlink()
            def close(self): pass
        self.client = types.SimpleNamespace(open_sftp=lambda: SFTP(), close=lambda: None)

    def upload(self, destination=None, progress=None, on_conflict=None):
        with patch.object(core, 'connect_verified', return_value=self.client):
            return core.transfer_files(core.Host('a209-06', '', '209'), dict(ip='192.168.22.26'), 'secret', [str(self.source)], 'batch-123', destination=destination, progress=progress, on_conflict=on_conflict)

    def test_files_hash_checked_and_not_executed(self):
        result = self.upload()
        self.assertTrue(result['ok'])
        target = Path(result['files'][0]['path'])
        self.assertEqual(target.read_bytes(), self.source.read_bytes())
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)
        self.assertFalse(list(self.home.rglob('*.part')))

    def test_corrupt_transfer_not_promoted_and_temp_removed(self):
        self.tamper = True
        result = self.upload()
        self.assertFalse(result['ok'])
        self.assertFalse(list(self.inbox.iterdir()))

    def test_existing_batch_not_overwritten(self):
        self.assertTrue(self.upload()['ok'])
        result = self.upload()
        self.assertFalse(result['ok'])
        self.assertEqual((self.inbox / self.source.name).read_bytes(), self.source.read_bytes())

    def test_symlink_parent_rejected(self):
        outside = self.base / 'outside'
        outside.mkdir()
        self.inbox.symlink_to(outside)
        self.assertFalse(self.upload()['ok'])
        self.assertFalse(list(outside.iterdir()))

    def test_custom_directory_progress_and_existing_file_protected(self):
        events = []
        destination = "~/Рабочие файлы/'$;test"
        result = self.upload(destination, events.append)
        self.assertTrue(result['ok'], result)
        self.assertEqual(Path(result['destination']), self.home / "Рабочие файлы/'$;test")
        self.assertEqual(events[-1]['done'], self.source.stat().st_size * 3)
        self.assertEqual(events[-1]['done'], events[-1]['total'])
        self.assertEqual({e['phase'] for e in events}, {'Подключение и проверка имени/ОС', 'Подготовка SHA-256', 'Передача', 'Проверка SHA-256 на ПК', 'Готово'})
        target = Path(result['files'][0]['path'])
        target.write_bytes(b'keep existing')
        self.assertFalse(self.upload(destination)['ok'])
        self.assertEqual(target.read_bytes(), b'keep existing')

    def test_empty_file_and_missing_directory(self):
        self.source.write_bytes(b'')
        events = []
        self.assertTrue(self.upload('~/new/nested', events.append)['ok'])
        self.assertEqual(events[-1]['phase'], 'Готово')
        self.assertEqual(events[-1]['total'], 0)

    def test_existing_temporary_file_preserved(self):
        directory = self.home / 'lesson'
        directory.mkdir()
        temporary = directory / (self.source.name + '.batch-123.part')
        temporary.write_bytes(b'preserve')
        result = self.upload('~/lesson')
        self.assertFalse(result['ok'])
        self.assertEqual(temporary.read_bytes(), b'preserve')

    def test_custom_symlink_directory_rejected(self):
        outside = self.base / 'outside'
        outside.mkdir()
        (self.home / 'link').symlink_to(outside)
        self.assertFalse(self.upload('~/link/nested')['ok'])
        self.assertFalse(list(outside.iterdir()))

    def test_overwrite_yes_and_no_preserve_or_replace_content(self):
        self.assertTrue(self.upload()['ok'])
        target = self.inbox / self.source.name
        self.source.write_bytes(b'new contents')
        prompts = []
        result = self.upload(on_conflict=lambda path: prompts.append(path) or False)
        self.assertTrue(result['ok'])
        self.assertEqual(result['skipped'], [str(target)])
        self.assertEqual(result['files'], [])
        self.assertEqual(target.read_bytes(), b'package contents')
        result = self.upload(on_conflict=lambda path: True)
        self.assertTrue(result['ok'], result)
        self.assertEqual(target.read_bytes(), b'new contents')
        self.assertEqual(prompts, [str(target)])

    def test_actual_downloader_through_forwarded_channel_and_overwrite(self):
        import socket
        import threading
        import subprocess
        class Transport:
            listener = None
            cancelled = False
            def request_port_forward(inner, address, port, handler):
                self.assertEqual((address, port), ('127.0.0.1', 0))
                inner.listener = socket.socket()
                inner.listener.bind((address, port))
                inner.listener.listen()
                inner.listener.settimeout(0.1)
                listener = inner.listener
                def accept():
                    while inner.listener:
                        try:
                            channel, origin = listener.accept()
                        except socket.timeout:
                            continue
                        except OSError:
                            break
                        handler(channel, origin, ('127.0.0.1', 0))
                threading.Thread(target=accept, daemon=True).start()
                return inner.listener.getsockname()[1]
            def cancel_port_forward(inner, address, port):
                inner.cancelled = True
                listener, inner.listener = inner.listener, None
                if listener:
                    listener.close()
        self.source.write_bytes(b'payload with spaces and quotes' * 30000)
        def run(client, command, **kwargs):
            result = subprocess.run(['/bin/sh', '-c', command], capture_output=True, text=True, timeout=20)
            return result.returncode, result.stdout + result.stderr
        def download(answer=None):
            transport = Transport()
            self.client.get_transport = lambda: transport
            events = []
            with patch.object(core, 'connect_verified', return_value=self.client), patch.object(core, 'run', run):
                result = core.download_from_teacher(core.Host('a209-06', '', '209'), dict(ip='192.168.22.26'),
                                                    'secret', str(self.source), progress=events.append,
                                                    on_conflict=(lambda path: answer) if answer is not None else None)
            return result, events, transport
        result, events, transport = download()
        self.assertTrue(result['ok'], result)
        self.assertTrue(transport.cancelled)
        self.assertEqual(events[-1]['done'], events[-1]['total'])
        target = Path(result['files'][0]['path'])
        self.assertEqual(target, self.inbox / self.source.name)
        self.assertEqual(target.read_bytes(), self.source.read_bytes())
        self.source.write_bytes(b'replacement')
        result, events, transport = download(False)
        self.assertTrue(result['ok'])
        self.assertTrue(result['skipped'])
        self.assertNotEqual(target.read_bytes(), b'replacement')
        result, events, transport = download(True)
        self.assertTrue(result['ok'], result)
        self.assertTrue(transport.cancelled)
        self.assertEqual(target.read_bytes(), b'replacement')
        self.assertFalse(list(self.inbox.glob('*.part')))

    def test_download_hash_failure_preserves_existing_file(self):
        import subprocess
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        import threading
        class Handler(BaseHTTPRequestHandler):
            def do_GET(inner):
                inner.send_response(200)
                inner.send_header('Content-Length', '5')
                inner.end_headers()
                inner.wfile.write(b'wrong')
            def log_message(self, *args): pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            self.inbox.mkdir()
            target = self.inbox / self.source.name
            target.write_bytes(b'preserve')
            script = core.download_script('http://127.0.0.1:' + str(server.server_port) + '/', str(self.inbox), self.source.name, '0' * 64, 5, True)
            import sys
            result = subprocess.run([sys.executable, '-c', script], capture_output=True, text=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(target.read_bytes(), b'preserve')
            self.assertFalse(list(self.inbox.glob('*.part')))
        finally:
            server.shutdown()
            server.server_close()

    def test_download_forwarding_rejected_no_file_written(self):
        transport = types.SimpleNamespace(request_port_forward=lambda *a, **kw: (_ for _ in ()).throw(RuntimeError('denied')))
        self.client.get_transport = lambda: transport
        with patch.object(core, 'connect_verified', return_value=self.client), patch.object(core, 'run') as run:
            result = core.download_from_teacher(core.Host('a209-06', '', '209'), dict(ip='192.168.22.26'), 'secret', str(self.source))
        self.assertFalse(result['ok'])
        self.assertIn('SSH-сервер', result['message'])
        run.assert_not_called()
        self.assertFalse(self.inbox.exists())


class ScanIdentityTests(unittest.TestCase):
    def inspect(self, replies, dns='192.168.22.26', auth_error=None):
        self.calls = []
        self.closed = False
        outer = self
        class Client:
            def get_host_keys(self): return types.SimpleNamespace(add=lambda *args: None)
            def set_missing_host_key_policy(self, policy): outer.policy = policy
            def connect(self, ip, **kwargs):
                outer.connected = ip
                if auth_error:
                    raise auth_error
            def close(self): outer.closed = True
        iterator = iter(replies)
        def run(client, command):
            self.calls.append(command)
            return next(iterator)
        with patch.object(paramiko, 'SSHClient', Client), patch.object(core, 'decode_key', return_value=object()), patch.object(core, 'run', run), patch.object(core, 'resolve', return_value=dns):
            return core.inspect_address(dict(ip='192.168.22.26', type='ssh-ed25519', key='key'), 'secret')

    def test_scan_uses_actual_hostname_and_dns_mode_without_mutations(self):
        result = self.inspect([(0, 'a209-06\n'), (0, '1.8.4.1')])
        self.assertTrue(result['ok'])
        self.assertEqual(result['name'], 'a209-06')
        self.assertEqual(result['mode'], 'dns')
        self.assertEqual(self.calls, ['/bin/hostname -s', '/usr/bin/cat /etc/astra/build_version'])
        self.assertIsInstance(self.policy, paramiko.RejectPolicy)
        self.assertTrue(self.closed)

    def test_unconfirmed_dns_uses_fixed_address_and_wrong_os_rejected(self):
        result = self.inspect([(0, 'a209-06'), (0, '1.8.4.1')], dns='192.168.22.27')
        self.assertEqual(result['mode'], 'fixed')
        result = self.inspect([(0, 'a209-06'), (1, 'not found')])
        self.assertFalse(result['ok'])

    def test_bad_scan_password_stops_without_hostname_commands(self):
        result = self.inspect([], auth_error=paramiko.AuthenticationException())
        self.assertTrue(result['stop'])
        self.assertEqual(self.calls, [])


class LinuxCredentialTests(unittest.TestCase):
    def test_stdin_secret_no_newline_no_argv_secret(self):
        with patch.object(store, 'os', types.SimpleNamespace(name='posix')), patch.object(store.shutil, 'which', return_value='/usr/bin/secret-tool'), patch.object(store.subprocess, 'run', return_value=types.SimpleNamespace(returncode=0, stdout='')) as run:
            store.save('Пароль with space ')
        self.assertEqual(run.call_args.kwargs['input'], 'Пароль with space ')
        self.assertNotIn('Пароль', ' '.join(run.call_args.args[0]))

    def test_read_and_delete_secret_service(self):
        with patch.object(store, 'os', types.SimpleNamespace(name='posix')), patch.object(store.shutil, 'which', return_value='/usr/bin/secret-tool'), patch.object(store.subprocess, 'run', return_value=types.SimpleNamespace(returncode=0, stdout='secret ')) as run:
            self.assertEqual(store.load(), 'secret ')
            store.delete()
            self.assertIn('clear', run.call_args.args[0])

    def test_missing_backend_has_no_plaintext_fallback(self):
        with patch.object(store, 'os', types.SimpleNamespace(name='posix')), patch.object(store.shutil, 'which', return_value=None):
            self.assertIsNone(store.load())
            with self.assertRaises(RuntimeError):
                store.save('secret')


class DispatchTests(unittest.TestCase):
    def test_batch_dispatches_upload_and_commands_without_power_calls(self):
        with tempfile.TemporaryDirectory() as directory:
            for action, function, job in [('upload', 'transfer_files', dict(files=['x'], batch='test')),
                                          ('command', 'execute_command', dict(script='id', sudo=False, timeout=60)),
                                          ('download', 'download_from_teacher', dict(files=['x'], destination=core.DEFAULT_INBOX))]:
                app = gui.Manager.__new__(gui.Manager)
                app.data = Path(directory)
                import queue
                app.events = queue.Queue()
                row = dict(name='a209-06', ip='192.168.22.26')
                result = dict(row, ok=True, message='ok')
                with patch.object(gui, function, return_value=result) as target, patch.object(gui, 'execute') as power:
                    app.send({'a209-06': core.Host('a209-06', '', '209')}, [row], 'secret', action, 0, [], job)
                target.assert_called_once()
                power.assert_not_called()

    def test_transferred_files_loaded_after_restart_with_per_host_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            app = gui.Manager.__new__(gui.Manager)
            app.data = Path(directory)
            app.last_results = []
            report = app.data / 'reports/20261125-1.json'
            rows = [dict(name=name, action=action, files=[dict(path=path, sha256='a' * 64)])
                    for name, action, path in [('a209-01', 'upload', '/home/user/Desktops/Desktop1/CM-Inbox/run.sh'),
                                               ('a209-02', 'download', '/home/user/lesson/run.sh')]]
            core.atomic_json(report, rows)
            groups = app.transferred_files()
            targets = groups[('run.sh', 'a' * 64)]
            self.assertEqual(targets['a209-01']['cwd'], '/home/user/Desktops/Desktop1/CM-Inbox')
            self.assertEqual(targets['a209-02']['cwd'], '/home/user/lesson')
            self.assertEqual(targets['a209-01']['script'], targets['a209-02']['script'])

    def test_password_failure_stops_remaining_downloads(self):
        import queue
        with tempfile.TemporaryDirectory() as directory:
            app = gui.Manager.__new__(gui.Manager)
            app.data, app.events = Path(directory), queue.Queue()
            rows = [dict(name='a209-01', ip='192.168.22.1'), dict(name='a209-02', ip='192.168.22.2')]
            failed = dict(rows[0], ok=False, message='Ошибка доступа', stop=True, action='download')
            with patch.object(gui, 'download_from_teacher', return_value=failed) as download:
                app.send({r['name']: core.Host(r['name'], '', '209') for r in rows}, rows, 'secret', 'download', 0, [], dict(files=['x'], destination=core.DEFAULT_INBOX))
            download.assert_called_once()
            events = []
            while not app.events.empty():
                events.append(app.events.get())
            results = [value for kind, value in events if kind == 'result']
            self.assertEqual(len(results), 2)
            self.assertIn('Пропущен', results[1]['message'])

    def test_forwarded_http_channel_serves_only_selected_token(self):
        class Channel:
            def __init__(self, request):
                self.request, self.output, self.closed = request, b'', False
            def settimeout(self, timeout): pass
            def recv(self, count):
                result, self.request = self.request[:count], self.request[count:]
                return result
            def sendall(self, value): self.output += value
            def close(self): self.closed = True
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'chosen.bin'
            path.write_bytes(b'only this file')
            wrong = Channel(b'GET /../another HTTP/1.1\r\n\r\n')
            core._serve_file_channel(wrong, path, 'token', path.stat().st_size, lambda count: None)
            self.assertIn(b'404', wrong.output)
            self.assertNotIn(b'only this file', wrong.output)
            correct = Channel(b'GET /token HTTP/1.1\r\n\r\n')
            counts = []
            core._serve_file_channel(correct, path, 'token', path.stat().st_size, counts.append)
            self.assertEqual(correct.output.split(b'\r\n\r\n')[1], path.read_bytes())
            self.assertEqual(sum(counts), path.stat().st_size)
            self.assertTrue(correct.closed)


if __name__ == '__main__':
    unittest.main()
