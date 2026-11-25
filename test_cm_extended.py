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


class UploadTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.home = self.base / 'remote-home'
        self.home.mkdir()
        self.source = self.base / "app 'test';$.deb"
        self.source.write_bytes(b'package contents')
        outer = self
        class SFTP:
            def get_channel(self): return types.SimpleNamespace(settimeout=lambda n: None)
            def normalize(self, path): return str(outer.home)
            def lstat(self, path): return Path(path).lstat()
            def mkdir(self, path, mode): Path(path).mkdir(mode=mode)
            def put(self, source, path, confirm):
                shutil.copyfile(source, path)
                if getattr(outer, 'tamper', False):
                    Path(path).write_bytes(b'changed')
            def chmod(self, path, mode): Path(path).chmod(mode)
            def open(self, path, mode): return open(path, mode)
            def rename(self, source, target): os.rename(source, target)
            def remove(self, path): Path(path).unlink()
            def close(self): pass
        self.client = types.SimpleNamespace(open_sftp=lambda: SFTP(), close=lambda: None)

    def upload(self):
        with patch.object(core, 'connect_verified', return_value=self.client):
            return core.transfer_files(core.Host('a209-06', '', '209'), dict(ip='192.168.22.26'), 'secret', [str(self.source)], 'batch-123')

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
        self.assertFalse(list((self.home / 'CM-Inbox/batch-123').iterdir()))

    def test_existing_batch_not_overwritten(self):
        self.assertTrue(self.upload()['ok'])
        result = self.upload()
        self.assertFalse(result['ok'])
        self.assertEqual((self.home / 'CM-Inbox/batch-123' / self.source.name).read_bytes(), self.source.read_bytes())

    def test_symlink_parent_rejected(self):
        outside = self.base / 'outside'
        outside.mkdir()
        (self.home / 'CM-Inbox').symlink_to(outside)
        self.assertFalse(self.upload()['ok'])
        self.assertFalse(list(outside.iterdir()))


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
                                          ('command', 'execute_command', dict(script='id', sudo=False, timeout=60))]:
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


if __name__ == '__main__':
    unittest.main()
