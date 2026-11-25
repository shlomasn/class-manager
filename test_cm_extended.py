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

    def test_live_output_silent_heartbeat_and_split_password_redaction(self):
        clock = [0.0]
        class Channel:
            first = second = False
            closed = False
            def exec_command(self, command): pass
            def shutdown_write(self): pass
            def recv_ready(inner): return not inner.first or (clock[0] >= .5 and not inner.second)
            def recv(inner, size):
                if not inner.first:
                    inner.first = True
                    return b'Preparing secr'
                inner.second = True
                return b'et\nInstalling package\n'
            def recv_stderr_ready(self): return False
            def exit_status_ready(self): return clock[0] >= 2
            def recv_exit_status(self): return 0
            def close(inner): inner.closed = True
        channel = Channel()
        client = types.SimpleNamespace(get_transport=lambda: types.SimpleNamespace(open_session=lambda **kwargs: channel), close=lambda: None)
        events = []
        def sleep(seconds): clock[0] += .25
        with patch.object(core, 'connect_verified', return_value=client), patch.object(core.time, 'monotonic', side_effect=lambda: clock[0]), patch.object(core.time, 'sleep', side_effect=sleep):
            result = core.execute_command(self.host, self.pin, 'secret', 'test installer', progress=events.append)
        self.assertTrue(result['ok'])
        running = [event for event in events if event['phase'] == 'Выполняется']
        self.assertGreaterEqual(max(event['elapsed'] for event in running), 1)
        self.assertTrue(any('Installing package' in event['output'] for event in running))
        self.assertFalse(any('secret' in event['output'] or 'secr' in event['output'] for event in running))
        self.assertIn('[СКРЫТО]', result['output'])
        self.assertTrue(channel.closed)



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

    def test_prepared_sftp_multiple_files_progress_and_partial_failure(self):
        second = self.base / 'setup.sh'
        second.write_bytes(b'echo hello')
        paths = [str(self.source), str(second)]
        prepared = {str(Path(path).resolve()): core.prepare_transfer(path) for path in paths}
        events = []
        with patch.object(core, 'connect_verified', return_value=self.client), patch.object(core, '_digest_stream', wraps=core._digest_stream) as hashes:
            result = core.transfer_files(core.Host('a209-06', '', '209'), dict(ip='192.168.22.26'), 'secret', paths, 'batch',
                                         prepared=prepared, access_gate=core.TransferAccessGate(), progress=events.append)
        self.assertTrue(result['ok'], result)
        self.assertEqual(len(result['files']), 2)
        self.assertEqual(hashes.call_count, 2)  # Only remote verification; local hashes reused.
        self.assertEqual(events[-1]['done'], events[-1]['total'])
        self.assertEqual(events[-1]['total'], sum(Path(path).stat().st_size for path in paths) * 2)
        # Replacing one file and skipping another preserves each independent choice.
        self.source.write_bytes(b'replacement')
        prepared = {str(Path(path).resolve()): core.prepare_transfer(path) for path in paths}
        with patch.object(core, 'connect_verified', return_value=self.client):
            result = core.transfer_files(core.Host('a209-06', '', '209'), dict(ip='192.168.22.26'), 'secret', paths, 'batch-next',
                                         prepared=prepared, access_gate=core.TransferAccessGate(), on_conflict=lambda path: path.endswith('.deb'))
        self.assertTrue(result['ok'], result)
        self.assertEqual(len(result['files']), 1)
        self.assertEqual(len(result['skipped']), 1)
        self.assertEqual((self.inbox / self.source.name).read_bytes(), b'replacement')
        self.assertEqual((self.inbox / second.name).read_bytes(), b'echo hello')
        second.write_bytes(b'changed after preparation')
        with patch.object(core, 'connect_verified', return_value=self.client):
            result = core.transfer_files(core.Host('a209-06', '', '209'), dict(ip='192.168.22.26'), 'secret', paths, 'partial',
                                         destination='~/partial', prepared=prepared, access_gate=core.TransferAccessGate())
        self.assertFalse(result['ok'])
        self.assertEqual(len(result['files']), 1)
        self.assertEqual((self.home / 'partial' / self.source.name).read_bytes(), b'replacement')
        self.assertFalse((self.home / 'partial' / second.name).exists())

    def test_changed_prepared_source_is_not_sent(self):
        prepared = {str(self.source.resolve()): core.prepare_transfer(self.source)}
        self.source.write_bytes(b'changed after preparation')
        with patch.object(core, 'connect_verified', return_value=self.client):
            result = core.transfer_files(core.Host('a209-06', '', '209'), dict(ip='192.168.22.26'), 'secret', [str(self.source)], 'batch',
                                         prepared=prepared, access_gate=core.TransferAccessGate())
        self.assertFalse(result['ok'])
        self.assertEqual(result['files'], [])
        self.assertIn('после подготовки', result['message'])


    def test_cancel_during_second_file_keeps_first_verified_file(self):
        second = self.base / 'setup.sh'
        second.write_bytes(b'echo hello')
        parent = core.OperationControl()
        control = core.OperationControl(parent=parent, reason='Раздача отменена пользователем')
        sftp = self.client.open_sftp()
        original_put = sftp.put
        def put(source, target, callback, confirm):
            if source == str(second):
                control.cancel()
            return original_put(source, target, confirm, callback)
        sftp.put = put
        self.client.open_sftp = lambda: sftp
        with patch.object(core, 'connect_verified', return_value=self.client):
            result = core.transfer_files(core.Host('a209-01', '', '209'), dict(ip='192.168.22.1'), 'secret',
                                         [str(self.source), str(second)], 'batch', control=control)
        self.assertTrue(result['cancelled'])
        self.assertFalse(result['ok'])
        self.assertEqual(len(result['files']), 1)
        self.assertEqual((self.inbox / self.source.name).read_bytes(), self.source.read_bytes())
        self.assertFalse((self.inbox / second.name).exists())
        self.assertFalse(parent.cancelled.is_set())


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
            for action, function, job in [('command', 'execute_command', dict(script='id', sudo=False, timeout=60)),
                                          ('distribute', 'transfer_files', dict(files=['x'], destination=core.DEFAULT_INBOX))]:
                if action == 'distribute':
                    path = Path(directory) / 'teacher.bin'
                    path.write_bytes(b'file')
                    job['files'] = [str(path)]
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
        import threading
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'teacher.bin'
            path.write_bytes(b'data')
            app = gui.Manager.__new__(gui.Manager)
            app.data, app.events = Path(directory), queue.Queue()
            rows = [dict(name='a209-' + str(n), ip='192.168.22.' + str(n)) for n in range(1, 9)]
            attempted = []
            denied = threading.Event()
            def connect(host, pin, password):
                attempted.append(host.name)
                if len(attempted) == 2:
                    denied.set()
                    raise paramiko.AuthenticationException('bad password')
                return object()
            def download(host, pin, password, paths, batch, access_gate, **kwargs):
                result = dict(name=host.name, ip=pin['ip'], action='download', ok=False)
                try:
                    access_gate.connect(host, pin, password)
                    self.assertTrue(denied.wait(3), 'Other hosts were held until first download finished')
                    result.update(ok=True, message='Already started download completed')
                except core.TransferStopped as error:
                    result.update(cancelled=True, message=str(error))
                except Exception as error:
                    core.operation_error(result, error, password)
                return result
            with patch.object(core, 'connect_verified', connect), patch.object(gui, 'transfer_files', download):
                app.send({r['name']: core.Host(r['name'], '', '209') for r in rows}, rows, 'secret', 'distribute', 0, [], dict(files=[str(path)], destination=core.DEFAULT_INBOX))
            self.assertEqual(len(attempted), 2)
            events = []
            while not app.events.empty():
                events.append(app.events.get())
            results = [value for kind, value in events if kind == 'result']
            self.assertEqual(len(results), 8)
            self.assertEqual(sum(r.get('stop', False) for r in results), 1)
            self.assertEqual(sum(r.get('cancelled', False) for r in results), 6)
            self.assertEqual(sum(r['ok'] for r in results), 1)
            self.assertEqual(len([v for k, v in events if k == 'finished']), 1)

    def test_all_eight_downloads_start_before_any_one_finishes(self):
        import queue
        import threading
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'teacher.bin'
            path.write_bytes(b'file contents')
            app = gui.Manager.__new__(gui.Manager)
            app.data, app.events = Path(directory), queue.Queue()
            rows = [dict(name='a209-' + str(n), ip='192.168.22.' + str(n)) for n in range(1, 9)]
            second = Path(directory) / 'second.sh'
            second.write_bytes(b'echo hello')
            barrier = threading.Barrier(len(rows), timeout=3)
            prepared_ids = []
            def download(host, pin, password, paths, batch, progress, access_gate, prepared, **kwargs):
                access_gate.connect(host, pin, password)
                self.assertEqual(paths, [str(path), str(second)])
                self.assertEqual(set(prepared), {str(path.resolve()), str(second.resolve())})
                prepared_ids.append(id(prepared))
                progress(dict(phase='Скачивание с учительского ПК', file='teacher.bin', done=4, total=13, destination='/home/user/Desktops/Desktop1/CM-Inbox'))
                barrier.wait()  # Sequential or six-worker dispatch cannot pass this barrier.
                return dict(name=host.name, ip=pin['ip'], action='download', ok=True, message='done')
            with patch.object(core, 'connect_verified', return_value=object()), patch.object(gui, 'transfer_files', download), patch.object(gui, 'prepare_transfer', wraps=core.prepare_transfer) as prepare:
                app.send({r['name']: core.Host(r['name'], '', '209') for r in rows}, rows, 'secret', 'distribute', 0, [], dict(files=[str(path), str(second)], destination=core.DEFAULT_INBOX))
            self.assertEqual(prepare.call_count, 2)
            self.assertEqual(len(prepared_ids), 8)
            self.assertEqual(len(set(prepared_ids)), 1)
            events = []
            while not app.events.empty():
                events.append(app.events.get())
            results = [v for k, v in events if k == 'result']
            self.assertEqual(len(results), 8)
            self.assertTrue(all(r['ok'] for r in results), results)
            progress = [v for k, v in events if k == 'distribution_progress']
            self.assertEqual({v['name'] for v in progress}, {r['name'] for r in rows})
            finished = [v for k, v in events if k == 'finished']
            self.assertEqual(len(finished), 1)
            self.assertEqual([r['name'] for r in finished[0][0]], [r['name'] for r in rows])
            self.assertEqual(json.loads(Path(finished[0][1]).read_text()), finished[0][0])

    def test_progress_is_separate_for_each_pc_and_final_status_is_preserved(self):
        import queue
        app = gui.Manager.__new__(gui.Manager)
        app.events = queue.Queue()
        app.statuses = {}
        app.distribution_state = {name: dict(percent=0, complete=False) for name in ['a209-01', 'a209-02']}
        displayed = {}
        app.table = types.SimpleNamespace(exists=lambda name: True, set=lambda name, column, value: displayed.update({name: value}))
        app.progress = types.SimpleNamespace(stop=lambda: None, configure=lambda **kwargs: None)
        app.summary = types.SimpleNamespace(set=lambda value: None)
        app.window = types.SimpleNamespace(after=lambda *args: None)
        app.refresh = lambda: displayed.update({name: status[0] for name, status in app.statuses.items()})
        for name, done in [('a209-01', 50), ('a209-02', 25)]:
            app.events.put(('distribution_progress', dict(name=name, done=done, total=100, phase='Скачивание')))
        app.events.put(('result', dict(name='a209-01', action='download', ok=True, message='Файл скачан и проверен')))
        app.events.put(('distribution_progress', dict(name='a209-01', done=80, total=100, phase='Скачивание')))
        app.poll()
        self.assertEqual(displayed['a209-01'], 'Файл скачан и проверен')
        self.assertIn('25%', displayed['a209-02'])
        self.assertTrue(app.distribution_state['a209-01']['complete'])
        self.assertFalse(app.distribution_state['a209-02']['complete'])

    def test_command_status_shows_live_line_and_elapsed_time_until_result(self):
        import queue
        app = gui.Manager.__new__(gui.Manager)
        app.events, app.statuses = queue.Queue(), {}
        displayed = {}
        app.table = types.SimpleNamespace(exists=lambda name: True, set=lambda name, column, value: displayed.update({name: value}))
        app.summary = types.SimpleNamespace(set=lambda value: None)
        app.window = types.SimpleNamespace(after=lambda *args: None)
        app.refresh = lambda: displayed.update({name: status[0] for name, status in app.statuses.items()})
        app.events.put(('command_waiting', ['a209-01', 'a209-02']))
        app.events.put(('command_progress', dict(name='a209-01', phase='Выполняется', elapsed=12, output='Preparing\n\x1b[32mInstalling package\x1b[0m\n')))
        app.poll()
        self.assertIn('12 с', displayed['a209-01'])
        self.assertIn('Installing package', displayed['a209-01'])
        self.assertNotIn('\x1b', displayed['a209-01'])
        self.assertEqual(displayed['a209-02'], 'Ожидает выполнения команды')
        app.events.put(('result', dict(name='a209-01', action='command', ok=True, message='Команда завершена, код 0')))
        app.poll()
        self.assertEqual(displayed['a209-01'], 'Команда завершена, код 0')




class ConcurrentOperationsTests(unittest.TestCase):
    def app(self, directory):
        from unittest.mock import Mock
        app = gui.Manager.__new__(gui.Manager)
        app.data = Path(directory)
        app.operations, app.shutdown = gui.OperationBook(), core.OperationControl()
        app.busy, app.closing, app.preparing_operation = False, False, None
        app.events = __import__('queue').Queue()
        app.job, app.last_results = {}, []
        app.statuses, app.trusted, app.catalog, app.last_ips = {}, {}, {}, {}
        app.selected = set()
        app.last_upload_directory = None
        app.hosts = [core.Host('a209-01', '', '209'), core.Host('a209-02', '', '209'), core.Host('a208-01', '', '208')]
        app.visible = lambda: app.hosts
        app.window = types.SimpleNamespace(after=Mock(), destroy=Mock())
        app.summary = types.SimpleNamespace(set=Mock())
        app.delay = types.SimpleNamespace(get=lambda: '1')
        class Widget:
            def __init__(self): self.options = dict(mode='indeterminate')
            def configure(self, **kwargs): self.options.update(kwargs)
            def __getitem__(self, key): return self.options[key]
            def start(self, *args): pass
            def stop(self): pass
        app.progress, app.room_box, app.delay_box = Widget(), Widget(), Widget()
        app.action_button, app.edit_button = Widget(), Widget()
        app.controls = [app.action_button, app.edit_button]
        app.inventory_controls = [app.edit_button]
        app.table = types.SimpleNamespace(exists=lambda name: True, set=Mock())
        app.refresh = Mock()
        app.get_password = lambda: 'test-password'
        return app

    def process_until(self, app, condition):
        import time
        deadline = time.monotonic() + 4
        while not condition():
            if time.monotonic() > deadline:
                self.fail('Operation event did not arrive')
            kind, value = app.events.get(timeout=2)
            identifier = None
            if kind == 'operation_event':
                identifier, kind, value = value
            app.handle_event(kind, value, identifier)

    def test_slow_distribution_allows_command_on_finished_host_and_keeps_reports_separate(self):
        import threading
        with tempfile.TemporaryDirectory() as directory:
            app = self.app(directory)
            path = Path(directory) / 'setup.sh'
            path.write_text('lesson')
            slow_started, release_slow = threading.Event(), threading.Event()
            def probe(host, **kwargs):
                return dict(name=host.name, ip='192.168.22.1', ok=True, type='ssh-ed25519', key='key')
            def transfer(host, pin, password, paths, batch, progress, **kwargs):
                progress(dict(phase='Передача', file='lesson.txt', done=1, total=10))
                if host.name == 'a209-02':
                    slow_started.set()
                    if not release_slow.wait(4):
                        raise RuntimeError('test timeout')
                return dict(name=host.name, ip=pin['ip'], action='upload', ok=True, files=[dict(path='/home/user/Desktops/Desktop1/CM-Inbox/setup.sh', sha256='a' * 64, bytes=6)], message='Передано')
            def command(host, pin, password, script, sudo, timeout, progress, **kwargs):
                self.assertEqual(script, 'hostname')
                progress(dict(phase='Выполняется', elapsed=1, output='hostname output'))
                return dict(name=host.name, ip=pin['ip'], action='command', ok=True, message='Команда завершена')
            with patch.object(gui, 'probe', probe), patch.object(gui, 'classify_key', return_value='trusted'), patch.object(gui.messagebox, 'askokcancel', return_value=True), patch.object(gui, 'transfer_files', transfer), patch.object(gui, 'execute_command', command):
                try:
                    app.selected = {'a209-01', 'a209-02'}
                    app.begin('distribute', dict(files=[str(path)], destination=core.DEFAULT_INBOX))
                    first = next(iter(app.operations.active))
                    self.process_until(app, lambda: 'a209-01' not in app.operations.owners)
                    self.assertTrue(slow_started.wait(2))
                    self.assertIn('a209-01', app.transferred_files()[('setup.sh', 'a' * 64)])
                    self.assertFalse(app.busy)
                    self.assertEqual(app.action_button.options['state'], 'normal')
                    self.assertEqual(app.edit_button.options['state'], 'disabled')
                    app.select_visible()
                    self.assertNotIn('a209-02', app.selected)
                    app.selected = {'a209-02'}
                    with patch.object(gui.threading, 'Thread') as thread, patch.object(gui.messagebox, 'showinfo'):
                        app.begin('command', dict(script='hostname', sudo=False, timeout=30, cwd='~'))
                    thread.assert_not_called()
                    app.selected = {'a209-01'}
                    app.begin('command', dict(script='hostname', sudo=False, timeout=30, cwd='~'))
                    second = next(identifier for identifier in app.operations.active if identifier != first)
                    self.process_until(app, lambda: second not in app.operations.active)
                    self.assertIn(first, app.operations.active)
                    self.assertEqual(app.statuses['a209-01'][0], 'Команда завершена')
                    # A late packet from the older batch cannot overwrite this new result.
                    app.handle_event('distribution_progress', dict(name='a209-01', phase='OLD', done=9, total=10), first)
                    self.assertEqual(app.statuses['a209-01'][0], 'Команда завершена')
                finally:
                    release_slow.set()
                self.process_until(app, lambda: not app.operations.active)
            self.assertEqual(app.operations.owners, {})
            self.assertEqual(app.edit_button.options['state'], 'normal')
            reports = [json.loads(p.read_text()) for p in (app.data / 'reports').glob('*.json')]
            self.assertEqual(sorted(len(rows) for rows in reports), [1, 2])
            self.assertTrue(any(rows[0]['action'] == 'command' for rows in reports))
            self.assertNotIn('test-password', json.dumps(reports))

    def test_finishing_old_operation_preserves_new_preparation_and_job(self):
        with tempfile.TemporaryDirectory() as directory:
            app = self.app(directory)
            old = app.operations.start('distribute', app.hosts[:1], dict(files=['first']))
            old['state'] = 'running'
            new = app.operations.start('command', app.hosts[1:2], dict(script='new-script'))
            app.preparing_operation, app.busy = new['id'], True
            app.handle_event('finished', ([dict(name='a209-01', ok=True)], 'report.json'), old['id'])
            self.assertTrue(app.busy)
            self.assertEqual(app.preparing_operation, new['id'])
            self.assertEqual(new['job']['script'], 'new-script')
            self.assertEqual(app.operations.owners, {'a209-02': new['id']})
            self.assertEqual(app.action_button.options['state'], 'disabled')
            with patch.object(gui.messagebox, 'showerror'):
                app.handle_event('error', 'old event', old['id'])
            self.assertIn(new['id'], app.operations.active)

    def test_exit_refusal_keeps_work_and_exit_confirmation_cancels_and_reports(self):
        from unittest.mock import Mock
        with tempfile.TemporaryDirectory() as directory:
            app = self.app(directory)
            operation = app.operations.start('distribute', app.hosts[:2], dict(files=['lesson']))
            operation['state'] = 'running'
            operation['results'].append(dict(name='a209-01', ok=True, message='Передано'))
            app.operations.release(operation['id'], 'a209-01')
            client = types.SimpleNamespace(close=Mock())
            app.shutdown.add(client)
            with patch.object(gui.messagebox, 'askyesno', return_value=False) as ask:
                app.close()
            self.assertEqual(ask.call_args.kwargs['default'], 'no')
            self.assertIn('a209-02', ask.call_args.args[1])
            self.assertFalse(app.shutdown.cancelled.is_set())
            self.assertFalse(app.closing)
            client.close.assert_not_called()
            app.window.destroy.assert_not_called()
            with patch.object(gui.messagebox, 'askyesno', return_value=True) as ask:
                app.close()
            self.assertIn('могут продолжить', ask.call_args.args[1])
            client.close.assert_called_once()
            app.window.destroy.assert_called_once()
            self.assertTrue(app.shutdown.cancelled.is_set())
            reports = list((app.data / 'reports').glob('*-interrupted-*.json'))
            self.assertEqual(len(reports), 1)
            rows = json.loads(reports[0].read_text())
            self.assertEqual(len(rows), 2)
            self.assertTrue(rows[0]['ok'])
            self.assertFalse(rows[1]['ok'])
            self.assertIn('не подтверждён', rows[1]['message'])
            with patch.object(gui.messagebox, 'askyesno') as ask:
                app.close()
            ask.assert_not_called()

    def test_idle_exit_has_no_prompt_but_busy_scanner_requires_confirmation(self):
        with tempfile.TemporaryDirectory() as directory:
            app = self.app(directory)
            with patch.object(gui.messagebox, 'askyesno') as ask:
                app.close()
            ask.assert_not_called()
            app.window.destroy.assert_called_once()
            app = self.app(directory)
            app.busy = True
            with patch.object(gui.messagebox, 'askyesno', return_value=False) as ask:
                app.close()
            ask.assert_called_once()
            app.window.destroy.assert_not_called()

    def test_exit_cancels_worker_waiting_for_overwrite_answer(self):
        import threading
        with tempfile.TemporaryDirectory() as directory:
            app = self.app(directory)
            path = Path(directory) / 'lesson.txt'
            path.write_text('lesson')
            def transfer(host, pin, password, paths, batch, on_conflict, **kwargs):
                on_conflict('/home/user/lesson.txt')
                raise AssertionError('Cancellation should interrupt the wait')
            pin = dict(name='a209-01', ip='192.168.22.1')
            with patch.object(gui, 'transfer_files', transfer):
                thread = threading.Thread(target=app.send, args=({'a209-01': app.hosts[0]}, [pin], 'test-password', 'distribute', 0, [], dict(files=[str(path)], destination=core.DEFAULT_INBOX), app.events, app.shutdown))
                thread.start()
                while True:
                    kind, value = app.events.get(timeout=2)
                    if kind == 'overwrite':
                        break
                app.shutdown.cancel()
                thread.join(2)
                self.assertFalse(thread.is_alive())
            reports = list((app.data / 'reports').glob('*.json'))
            self.assertEqual(len(reports), 1)
            self.assertFalse(json.loads(reports[0].read_text())[0]['ok'])

    def test_cancel_closes_live_command_and_prevents_a_new_command(self):
        import threading
        from unittest.mock import Mock
        control = core.OperationControl()
        started, closed = threading.Event(), threading.Event()
        channel = types.SimpleNamespace(exec_command=lambda command: started.set(), shutdown_write=lambda: None,
                                        recv_ready=lambda: False, recv_stderr_ready=lambda: False,
                                        exit_status_ready=lambda: False, close=closed.set)
        open_session = Mock(return_value=channel)
        client = types.SimpleNamespace(get_transport=lambda: types.SimpleNamespace(open_session=open_session), close=Mock())
        control.add(client)
        errors = []
        def execute():
            try:
                core.run(client, 'sleep 100', timeout=300, control=control)
            except RuntimeError as error:
                errors.append(str(error))
        thread = threading.Thread(target=execute)
        thread.start()
        self.assertTrue(started.wait(2))
        control.cancel()
        thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertTrue(closed.is_set())
        client.close.assert_called_once()
        self.assertTrue(errors)
        with self.assertRaises(RuntimeError):
            core.run(client, 'another', control=control)
        open_session.assert_called_once()


    def test_cancel_selected_distribution_keeps_siblings_and_other_operations(self):
        from unittest.mock import Mock
        with tempfile.TemporaryDirectory() as directory:
            app = self.app(directory)
            batch = app.operations.start('distribute', app.hosts[:2], {})
            other = app.operations.start('command', app.hosts[2:], {})
            batch['state'] = other['state'] = 'running'
            batch['controls'] = {host.name: core.OperationControl(parent=app.shutdown, reason='Раздача отменена пользователем') for host in app.hosts[:2]}
            clients = [types.SimpleNamespace(close=Mock()) for _ in app.hosts]
            batch['controls']['a209-01'].add(clients[0])
            batch['controls']['a209-02'].add(clients[1])
            app.shutdown.add(clients[2])
            app.table.focus = lambda name: None
            app.toggle('a209-01')
            app.selected.add('a208-01')  # The cancel button must ignore a command target.
            app.cancel_distribution()
            clients[0].close.assert_called_once()
            clients[1].close.assert_not_called()
            clients[2].close.assert_not_called()
            self.assertFalse(app.shutdown.cancelled.is_set())
            self.assertEqual(app.operations.owners['a209-01'], batch['id'])
            self.assertIn('Отмена', app.statuses['a209-01'][0])
            app.handle_event('distribution_progress', dict(name='a209-01', phase='late', done=9, total=10), batch['id'])
            self.assertIn('Отмена', app.statuses['a209-01'][0])
            app.handle_event('result', dict(name='a209-01', action='upload', ok=False, cancelled=True, message='Раздача отменена пользователем'), batch['id'])
            self.assertNotIn('a209-01', app.operations.owners)
            self.assertEqual(app.operations.owners['a209-02'], batch['id'])
            self.assertEqual(app.operations.owners['a208-01'], other['id'])
            app.shutdown.cancel()
            clients[1].close.assert_called_once()
            clients[2].close.assert_called_once()

    def test_cancel_overwrite_wait_on_one_pc_does_not_finish_other_pc(self):
        import threading
        with tempfile.TemporaryDirectory() as directory:
            app = self.app(directory)
            path = Path(directory) / 'lesson.txt'
            path.write_text('lesson')
            operation = app.operations.start('distribute', app.hosts[:2], {})
            operation['state'] = 'running'
            operation['controls'] = {host.name: core.OperationControl(parent=app.shutdown, reason='Раздача отменена пользователем') for host in app.hosts[:2]}
            sibling_started, release_sibling = threading.Event(), threading.Event()
            def transfer(host, pin, password, paths, batch, on_conflict, control, **kwargs):
                if host.name == 'a209-01':
                    on_conflict('/home/user/lesson.txt')
                    raise AssertionError('The cancelled overwrite wait should not resume')
                sibling_started.set()
                self.assertTrue(release_sibling.wait(4))
                control.check()
                return dict(name=host.name, ip=pin['ip'], action='upload', ok=True, files=[], message='Передано')
            pins = [dict(name=h.name, ip='192.168.22.1') for h in app.hosts[:2]]
            with patch.object(gui, 'transfer_files', transfer):
                thread = threading.Thread(target=app.send, args=({h.name: h for h in app.hosts[:2]}, pins, 'secret', 'distribute', 0, [], dict(files=[str(path)], destination=core.DEFAULT_INBOX), gui.OperationEvents(app.events, operation['id']), app.shutdown, operation['controls']))
                thread.start()
                try:
                    while True:
                        kind, payload = app.events.get(timeout=2)
                        identifier, kind, value = payload
                        if kind == 'overwrite':
                            break  # Leave the question unanswered, then cancel this host.
                        app.handle_event(kind, value, identifier)
                    self.assertTrue(sibling_started.wait(2))
                    app.selected = {'a209-01'}
                    app.cancel_distribution()
                    self.process_until(app, lambda: 'a209-01' not in app.operations.owners)
                    self.assertIn('a209-02', app.operations.owners)
                    self.assertFalse(app.shutdown.cancelled.is_set())
                finally:
                    release_sibling.set()
                    thread.join(3)
                self.assertFalse(thread.is_alive())
                self.process_until(app, lambda: not app.operations.active)
            report = json.loads(next((app.data / 'reports').glob('*.json')).read_text())
            self.assertTrue(report[0]['cancelled'])
            self.assertTrue(report[1]['ok'])

    def test_eight_commands_start_before_any_command_finishes(self):
        import threading
        with tempfile.TemporaryDirectory() as directory:
            app = self.app(directory)
            hosts = [core.Host('a209-' + str(n), '', '209') for n in range(1, 9)]
            rows = [dict(name=h.name, ip='192.168.22.1') for h in hosts]
            barrier = threading.Barrier(len(hosts), timeout=3)
            def connect(host, pin, password, **kwargs):
                return types.SimpleNamespace(name=host.name, close=lambda: None)
            def run(client, command, **kwargs):
                kwargs['on_progress'](dict(elapsed=1, output='running ' + client.name))
                barrier.wait()
                return 0, 'done ' + client.name
            with patch.object(core, 'connect_verified', connect), patch.object(core, 'run', run):
                app.send({h.name: h for h in hosts}, rows, 'secret', 'command', 0, [], dict(script='hostname', sudo=False, timeout=30, cwd='~'))
            report = json.loads(next((app.data / 'reports').glob('*.json')).read_text())
            self.assertEqual([r['name'] for r in report], [h.name for h in hosts])
            self.assertTrue(all(r['ok'] for r in report), report)
            progress = []
            while not app.events.empty():
                kind, value = app.events.get()
                if kind == 'command_progress': progress.append(value)
            self.assertEqual({r['name'] for r in progress}, {h.name for h in hosts})

    def test_parallel_commands_stop_new_password_attempts_after_first_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            app = self.app(directory)
            hosts = [core.Host('a209-' + str(n), '', '209') for n in range(1, 9)]
            rows = [dict(name=h.name, ip='192.168.22.1') for h in hosts]
            with patch.object(core, 'connect_verified', side_effect=paramiko.AuthenticationException('wrong')) as connect, patch.object(core, 'run') as run:
                app.send({h.name: h for h in hosts}, rows, 'secret', 'command', 0, [], dict(script='id', sudo=False, timeout=30))
            connect.assert_called_once()
            run.assert_not_called()
            report = json.loads(next((app.data / 'reports').glob('*.json')).read_text())
            self.assertEqual(len(report), 8)
            self.assertEqual(sum(r.get('stop', False) for r in report), 1)
            self.assertEqual(sum('Пропущен' in r['message'] for r in report), 7)

    def test_sudo_password_failure_blocks_next_command_without_reconnecting(self):
        gate = core.TransferAccessGate()
        client = types.SimpleNamespace(close=lambda: None)
        host, pin = core.Host('a209-01', '', '209'), dict(ip='192.168.22.1')
        with patch.object(core, 'connect_verified', return_value=client) as connect, patch.object(core, 'run', return_value=(1, 'incorrect password')) as run:
            first = core.execute_command(host, pin, 'secret', 'id', sudo=True, access_gate=gate)
            second = core.execute_command(host, pin, 'secret', 'id', sudo=True, access_gate=gate)
        self.assertTrue(first['stop'])
        self.assertFalse(second['ok'])
        self.assertIn('Пропущен', second['message'])
        connect.assert_called_once()
        run.assert_called_once()

    def test_all_targets_cancelled_during_preparation_never_start_transfer(self):
        with tempfile.TemporaryDirectory() as directory:
            app = self.app(directory)
            path = Path(directory) / 'lesson.txt'
            path.write_text('lesson')
            controls = {host.name: core.OperationControl(parent=app.shutdown, reason='Раздача отменена пользователем') for host in app.hosts[:2]}
            for control in controls.values(): control.cancel()
            rows = [dict(name=h.name, ip='192.168.22.1') for h in app.hosts[:2]]
            with patch.object(gui, 'transfer_files') as transfer:
                app.send({h.name: h for h in app.hosts[:2]}, rows, 'secret', 'distribute', 0, [], dict(files=[str(path)], destination=core.DEFAULT_INBOX), control=app.shutdown, host_controls=controls)
            transfer.assert_not_called()
            report = json.loads(next((app.data / 'reports').glob('*.json')).read_text())
            self.assertEqual(len(report), 2)
            self.assertTrue(all(r['cancelled'] for r in report))
            self.assertFalse(app.shutdown.cancelled.is_set())


    def test_cancelling_authentication_does_not_stop_sibling_transfers(self):
        parent = core.OperationControl()
        cancelled = core.OperationControl(parent=parent, reason='Раздача отменена пользователем')
        sibling = core.OperationControl(parent=parent)
        gate = core.TransferAccessGate(parent)
        def connect(host, pin, password, control):
            if host.name == 'a209-01':
                control.cancel()
                raise paramiko.AuthenticationException('transport closed')
            return 'connected sibling'
        with patch.object(core, 'connect_verified', connect):
            with self.assertRaises(core.OperationCancelled):
                gate.connect(core.Host('a209-01', '', '209'), {}, 'secret', control=cancelled)
            self.assertFalse(gate.stopped.is_set())
            self.assertEqual(gate.connect(core.Host('a209-02', '', '209'), {}, 'secret', control=sibling), 'connected sibling')
        self.assertFalse(parent.cancelled.is_set())


    def test_stop_selected_commands_requires_confirmation_and_preserves_other_tasks(self):
        with tempfile.TemporaryDirectory() as directory:
            app = self.app(directory)
            operation = app.operations.start('command', app.hosts[:2], {})
            operation['state'] = 'running'
            operation['controls'] = {h.name: core.CommandControl(parent=app.shutdown) for h in app.hosts[:2]}
            other = app.operations.start('distribute', app.hosts[2:], {})
            app.table.focus = lambda name: None
            app.toggle('a209-01')
            with patch.object(gui.messagebox, 'askokcancel', return_value=False):
                app.stop_commands()
            self.assertFalse(operation['controls']['a209-01'].stop_requested.is_set())
            with patch.object(gui.messagebox, 'askokcancel', return_value=True):
                app.stop_commands()
            self.assertTrue(operation['controls']['a209-01'].stop_requested.is_set())
            self.assertFalse(operation['controls']['a209-02'].stop_requested.is_set())
            self.assertFalse(app.shutdown.cancelled.is_set())
            self.assertEqual(app.operations.owners['a209-01'], operation['id'])
            app.handle_event('command_progress', dict(name='a209-01', phase='Выполняется', elapsed=1, output='late'), operation['id'])
            self.assertIn('Остановка', app.statuses['a209-01'][0])
            app.handle_event('result', dict(name='a209-01', action='command', ok=False, cancelled=True, stop_confirmed=True, message='Команда остановлена'), operation['id'])
            self.assertNotIn('a209-01', app.operations.owners)
            self.assertEqual(app.operations.owners['a209-02'], operation['id'])
            self.assertEqual(app.operations.owners['a208-01'], other['id'])

    def test_finishing_during_stop_confirmation_keeps_final_status(self):
        with tempfile.TemporaryDirectory() as directory:
            app = self.app(directory)
            operation = app.operations.start('command', app.hosts[:1], {})
            control = core.CommandControl(parent=app.shutdown)
            operation['controls'] = {'a209-01': control}
            app.selected = {'a209-01'}
            def confirm(*args, **kwargs):
                app.handle_event('result', dict(name='a209-01', action='command', ok=True, message='Команда завершена'), operation['id'])
                return True
            with patch.object(gui.messagebox, 'askokcancel', side_effect=confirm):
                app.stop_commands()
            self.assertEqual(app.statuses['a209-01'][0], 'Команда завершена')
            self.assertFalse(control.stop_requested.is_set())


class ManagedCommandTests(unittest.TestCase):
    def local_client(self):
        import subprocess
        import select
        from unittest.mock import Mock
        class Channel:
            process = None
            stdout_eof = stderr_eof = False
            commands = []
            sent = []
            def exec_command(inner, command):
                inner.commands.append(command)
                import sys, shlex
                local_command = command.replace('/usr/bin/python3', shlex.quote(sys.executable), 1)
                inner.process = subprocess.Popen(['/bin/sh', '-c', local_command], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            def sendall(inner, data):
                inner.sent.append(data)
                inner.process.stdin.write(data)
                inner.process.stdin.flush()
            def recv_ready(inner):
                return not inner.stdout_eof and bool(select.select([inner.process.stdout], [], [], 0)[0])
            def recv_stderr_ready(inner):
                return not inner.stderr_eof and bool(select.select([inner.process.stderr], [], [], 0)[0])
            def recv(inner, size):
                value = os.read(inner.process.stdout.fileno(), size)
                if not value: inner.stdout_eof = True
                return value
            def recv_stderr(inner, size):
                value = os.read(inner.process.stderr.fileno(), size)
                if not value: inner.stderr_eof = True
                return value
            def exit_status_ready(inner): return inner.process.poll() is not None
            def recv_exit_status(inner): return inner.process.wait()
            def close(inner):
                if inner.process:
                    for stream in [inner.process.stdin, inner.process.stdout, inner.process.stderr]:
                        if stream:
                            try: stream.close()
                            except OSError: pass
                    if inner.process.poll() is None:
                        inner.process.terminate()
                        inner.process.wait(timeout=3)
        channel = Channel()
        client = types.SimpleNamespace(get_transport=lambda: types.SimpleNamespace(open_session=lambda **kw: channel), close=Mock())
        return client, channel

    def test_managed_command_normal_exit_preserves_output_and_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            client, channel = self.local_client()
            control = core.CommandControl()
            with patch.object(core, 'connect_verified', return_value=client):
                result = core.execute_command(core.Host('a209-01', '', '209'), dict(ip='192.168.22.1'), 'secret', 'pwd; printf done; exit 7', cwd=directory, control=control)
            self.assertFalse(result['ok'])
            self.assertEqual(result['exit'], 7)
            self.assertIn(directory, result['output'])
            self.assertIn('done', result['output'])
            self.assertNotIn('CM_RESULT_', result['output'])
            self.assertFalse(result.get('cancelled', False))
            self.assertNotIn('secret', channel.commands[0])

    def test_stop_terminates_process_group_and_preserves_other_command(self):
        import threading
        import shlex
        import time
        with tempfile.TemporaryDirectory() as directory:
            pidfile = Path(directory) / 'group.pid'
            client, channel = self.local_client()
            control = core.CommandControl()
            events, results = [], []
            script = 'echo $$ > ' + shlex.quote(str(pidfile)) + "; trap '' TERM; sleep 60 & wait"
            def execute():
                with patch.object(core, 'connect_verified', return_value=client):
                    results.append(core.execute_command(core.Host('a209-01', '', '209'), dict(ip='192.168.22.1'), 'secret', script, control=control, progress=events.append))
            thread = threading.Thread(target=execute)
            thread.start()
            try:
                deadline = time.monotonic() + 3
                while not pidfile.exists() and time.monotonic() < deadline:
                    time.sleep(.02)
                self.assertTrue(pidfile.exists())
                control.request_stop()
                thread.join(12)
                self.assertFalse(thread.is_alive())
                self.assertTrue(results[0].get('cancelled'), results)
                self.assertTrue(results[0]['stop_confirmed'], results)
                self.assertEqual(results[0]['message'], 'Команда остановлена')
                self.assertTrue(any(event['phase'] == 'Остановка команды' for event in events))
                group = int(pidfile.read_text())
                with self.assertRaises(ProcessLookupError):
                    os.killpg(group, 0)
                self.assertTrue(any(data.startswith(b'CM_STOP_') for data in channel.sent))
                # A separate supervisor/client is unaffected by this stop request.
                sibling_client, sibling_channel = self.local_client()
                with patch.object(core, 'connect_verified', return_value=sibling_client):
                    sibling = core.execute_command(core.Host('a209-02', '', '209'), dict(ip='192.168.22.2'), 'secret', 'printf sibling', control=core.CommandControl())
                self.assertTrue(sibling['ok'], sibling)
                self.assertEqual(sibling['output'], 'sibling')
            finally:
                if thread.is_alive():
                    control.cancel()
                    thread.join(2)
                if pidfile.exists():
                    try: os.killpg(int(pidfile.read_text()), 9)
                    except ProcessLookupError: pass

    def test_stopping_one_of_two_live_supervisors_does_not_stop_sibling(self):
        import threading, time, shlex
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            ready, release = base / 'ready', base / 'release'
            clients = [self.local_client()[0], self.local_client()[0]]
            parent = core.OperationControl()
            controls = [core.CommandControl(parent=parent), core.CommandControl(parent=parent)]
            results = {}
            scripts = ["printf target; trap '' TERM; sleep 60 & wait", 'touch ' + shlex.quote(str(ready)) + '; while [ ! -f ' + shlex.quote(str(release)) + ' ]; do sleep .05; done; printf sibling']
            def connect(host, pin, password, **kwargs): return clients[int(host.name[-1]) - 1]
            def execute(index):
                results[index] = core.execute_command(core.Host('a209-0' + str(index + 1), '', '209'), dict(ip='192.168.22.1'), 'secret', scripts[index], control=controls[index])
            threads = [threading.Thread(target=execute, args=(n,)) for n in range(2)]
            with patch.object(core, 'connect_verified', connect):
                for thread in threads: thread.start()
                try:
                    deadline = time.monotonic() + 3
                    while not ready.exists() and time.monotonic() < deadline: time.sleep(.02)
                    self.assertTrue(ready.exists())
                    controls[0].request_stop()
                    threads[0].join(12)
                    self.assertFalse(threads[0].is_alive())
                    self.assertTrue(results[0].get('stop_confirmed'), results)
                    self.assertTrue(threads[1].is_alive())
                    self.assertFalse(controls[1].stop_requested.is_set())
                    self.assertFalse(parent.cancelled.is_set())
                    release.touch()
                    threads[1].join(3)
                    self.assertTrue(results[1]['ok'], results)
                    self.assertEqual(results[1]['output'], 'sibling')
                finally:
                    release.touch()
                    for control in controls: control.request_stop()
                    for thread in threads: thread.join(12)

    def test_stop_confirmation_has_its_own_ten_second_deadline(self):
        from unittest.mock import Mock
        control = core.CommandControl()
        clock = [0.0]
        channel = types.SimpleNamespace(exec_command=lambda command: control.request_stop(), sendall=Mock(),
                                        recv_ready=lambda: False, recv_stderr_ready=lambda: False,
                                        recv=lambda size: b'', recv_stderr=lambda size: b'',
                                        exit_status_ready=lambda: False, close=Mock())
        client = types.SimpleNamespace(get_transport=lambda: types.SimpleNamespace(open_session=lambda **kw: channel))
        def sleep(seconds): clock[0] += 1
        with patch.object(core.time, 'monotonic', side_effect=lambda: clock[0]), patch.object(core.time, 'sleep', side_effect=sleep):
            with self.assertRaisesRegex(RuntimeError, 'Остановка команды не подтверждена'):
                core.run_managed(client, 'supervisor', 'token', None, 300, control)
        self.assertLessEqual(clock[0], 10)
        channel.sendall.assert_called_once_with(b'CM_STOP_token\n')
        channel.close.assert_called_once()

    def test_pending_authentication_can_be_stopped_without_waiting_for_other_host(self):
        import threading
        gate, control = core.TransferAccessGate(), core.CommandControl()
        errors = []
        def connect():
            try:
                gate.connect(core.Host('a209-01', '', '209'), {}, 'secret', control=control)
            except core.OperationCancelled:
                errors.append('cancelled')
        gate.lock.acquire()
        thread = threading.Thread(target=connect)
        try:
            with patch.object(core, 'connect_verified') as remote:
                thread.start()
                control.request_stop()
                thread.join(1)
                self.assertFalse(thread.is_alive())
                remote.assert_not_called()
            self.assertEqual(errors, ['cancelled'])
        finally:
            gate.lock.release()
            thread.join(1)

    def test_stop_before_start_never_connects_and_does_not_trip_password_gate(self):
        control = core.CommandControl()
        control.request_stop()
        gate = core.TransferAccessGate()
        with patch.object(core, 'connect_verified') as connect:
            result = core.execute_command(core.Host('a209-01', '', '209'), dict(ip='192.168.22.1'), 'secret', 'id', control=control, access_gate=gate)
        self.assertTrue(result['cancelled'])
        self.assertFalse(result.get('stop', False))
        self.assertFalse(gate.stopped.is_set())
        connect.assert_not_called()

    def test_disconnect_during_stop_is_not_reported_as_confirmed(self):
        client = types.SimpleNamespace(close=lambda: None)
        control = core.CommandControl()
        with patch.object(core, 'connect_verified', return_value=client), patch.object(core, 'run_managed', side_effect=RuntimeError('Связь потеряна; остановка не подтверждена')):
            result = core.execute_command(core.Host('a209-01', '', '209'), dict(ip='192.168.22.1'), 'secret', 'sleep 10', control=control)
        self.assertFalse(result['ok'])
        self.assertFalse(result.get('stop_confirmed', False))
        self.assertIn('не подтверждена', result['message'])

    def test_sudo_supervisor_uses_stdin_password_and_user_directory(self):
        client = types.SimpleNamespace(close=lambda: None)
        control = core.CommandControl()
        with patch.object(core, 'connect_verified', return_value=client), patch.object(core, 'run_managed', return_value=(0, 'done', dict(exit=0, cancelled=False, stop_confirmed=False))) as run:
            result = core.execute_command(core.Host('a209-01', '', '209'), dict(ip='192.168.22.1'), 'secret', 'id', sudo=True, cwd='~/lesson files', control=control)
        self.assertTrue(result['ok'])
        self.assertEqual(run.call_args.kwargs['password'], 'secret')
        self.assertNotIn('secret', run.call_args.args[1])
        import shlex
        outer = shlex.split(run.call_args.args[1])[-1]
        self.assertLess(outer.index('cd -- '), outer.index('sudo'))
        self.assertIn('/usr/bin/python3 -u -c ', outer)


if __name__ == '__main__':
    unittest.main()
