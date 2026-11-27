import ctypes
import json
from pathlib import Path
import queue
import tempfile
import types
import unittest
from unittest.mock import patch

import paramiko
import cm_core as core
import class_manager as gui
import credential_store as store


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'list.lst'

    def test_legacy_lists_import(self):
        self.path.write_text('# Заголовок\n701-01;10.42.1.2;\npc-02;10.42.1.3\n', encoding='cp1251')
        self.assertEqual(core.load_hosts(self.path), [
            core.Host('a701-01', '10.42.1.2', '701'),
            core.Host('pc-02', '10.42.1.3', 'Без класса'),
        ])

    def test_fqdn_and_utf8_bom(self):
        self.path.write_bytes('\ufeffpc-01.school.example;10.42.1.2;\r\n'.encode())
        self.assertEqual(core.load_hosts(self.path)[0].name, 'pc-01.school.example')

    def test_invalid_lists_rejected(self):
        for content in ['a702-06;8.8.8.8;', 'a702-06;127.0.0.1;', 'a702-06;10.42.22.26;\na702-06;10.42.22.27;',
                        'a702-06;10.42.22.26;extra;bad',
                        'a702-06;10.42.22.26$(touch x);', 'a702-06;shutdown;10.42.22.26;', '']:
            with self.subTest(content=content):
                self.path.write_text(content)
                with self.assertRaises((ValueError, KeyError)):
                    core.load_hosts(self.path)

    def test_atomic_json_replaces_and_keeps_unicode(self):
        path = Path(self.temp.name) / 'reports/report.json'
        core.atomic_json(path, {'message': 'Отменено'})
        self.assertEqual(json.loads(path.read_text())['message'], 'Отменено')
        self.assertEqual(len(list(path.parent.iterdir())), 1)


class PowerTests(unittest.TestCase):
    def test_only_fixed_operations_and_valid_delays(self):
        self.assertIn('/usr/sbin/shutdown -P +1', core.power_command('off', 1))
        self.assertIn('/usr/sbin/shutdown -r +5', core.power_command('reboot', 5))
        self.assertTrue(core.power_command('cancel', 1).endswith('shutdown -c'))
        for action, delay in [('off; rm', 1), ('off', '1;whoami'), ('off', -1), ('off', 31), ('off', True)]:
            with self.assertRaises(ValueError):
                core.power_command(action, delay)

    def test_known_keys_follow_name_across_dhcp_and_unknown_still_asks(self):
        row = dict(name='a702-06', ip='10.42.22.26', type='ssh-ed25519', key='key')
        self.assertEqual(core.classify_key(row, {}, {row['name']: row}), 'trusted')
        moved = dict(row, ip='10.42.22.99')
        self.assertEqual(core.classify_key(moved, {row['name']: row}, {}), 'trusted')
        self.assertEqual(core.classify_key(dict(moved, key='other'), {row['name']: row}, {}), 'changed')
        self.assertEqual(core.classify_key(dict(row, name='a702-07'), {}, {row['name']: row}), 'new')

    def test_password_only_in_stdin_without_pty(self):
        class Channel:
            def exec_command(self, cmd): self.cmd = cmd
            def sendall(self, data): self.data = data
            def shutdown_write(self): pass
            def recv_ready(self): return False
            def recv_stderr_ready(self): return False
            def exit_status_ready(self): return True
            def recv_exit_status(self): return 0
            def close(self): self.closed = True
        channel = Channel()
        client = types.SimpleNamespace(get_transport=lambda: types.SimpleNamespace(open_session=lambda **kw: channel))
        code, _ = core.run(client, 'sudo -S fixed', password='hidden-test-password')
        self.assertEqual(code, 0)
        self.assertEqual(channel.data, b'hidden-test-password\n')
        self.assertNotIn('hidden-test-password', channel.cmd)
        self.assertTrue(channel.closed)

    def perform(self, replies=None, connection_error=None, action='off'):
        self.commands = []
        self.closed = False
        self.policy = None
        test = self
        class Client:
            def get_host_keys(self): return types.SimpleNamespace(add=lambda *a: None)
            def set_missing_host_key_policy(self, policy): test.policy = policy
            def connect(self, *a, **kw):
                test.connect_options = kw
                if connection_error: raise connection_error
            def close(self): test.closed = True
        replies = iter(replies or [(0, 'a702-06\n'), (0, '1.8.4.1\n'), (0, 'scheduled')])
        def run(client, command, **kw):
            test.commands.append((command, kw))
            return next(replies)
        with patch.object(paramiko, 'SSHClient', Client), patch.object(paramiko.PKey, 'from_type_string', return_value=object()), patch.object(core, 'run', run):
            return core.execute(core.Host('a702-06', '10.42.22.26', '702'), {'type': 'ssh-ed25519', 'key': 'a2V5'}, 'hidden-test-password', action, 1)

    def test_off_reboot_cancel_use_sudo_after_hostname_and_astra_checks(self):
        for action, ending in [('off', ' -P +1'), ('reboot', ' -r +1'), ('cancel', ' -c')]:
            result = self.perform(action=action)
            self.assertTrue(result['ok'])
            self.assertEqual(self.commands[0][0], '/bin/hostname -s')
            self.assertEqual(self.commands[1][0], '/usr/bin/cat /etc/astra/build_version')
            self.assertIn(ending, self.commands[2][0])
            self.assertEqual(self.commands[2][1]['password'], 'hidden-test-password')
            self.assertIsInstance(self.policy, paramiko.RejectPolicy)
            self.assertFalse(self.connect_options['allow_agent'])
            self.assertFalse(self.connect_options['look_for_keys'])
            self.assertTrue(self.closed)

    def test_wrong_hostname_prevents_power_command(self):
        result = self.perform([(0, 'a702-01')])
        self.assertFalse(result['ok'])
        self.assertEqual(len(self.commands), 1)

    def test_wrong_os_prevents_sudo(self):
        result = self.perform([(0, 'a702-06'), (1, 'file missing')])
        self.assertFalse(result['ok'])
        self.assertEqual(len(self.commands), 2)

    def test_immediate_disconnect_is_not_reported_as_confirmed_success(self):
        result = self.perform([(0, 'a702-06'), (0, '1.8.4.1'), (-1, '')])
        self.assertFalse(result['ok'])
        self.assertIn('без подтверждения', result['message'])
        self.assertEqual(len(self.commands), 3)

    def test_ssh_password_failure_stops_batch(self):
        result = self.perform(connection_error=paramiko.AuthenticationException())
        self.assertTrue(result['stop'])
        self.assertEqual(self.commands, [])

    def test_changed_key_never_sends_command(self):
        result = self.perform(connection_error=paramiko.BadHostKeyException('host', object(), object()))
        self.assertFalse(result['ok'])
        self.assertEqual(self.commands, [])

    def test_sudo_wrong_password_stops_and_redacts(self):
        result = self.perform([(0, 'a702-06'), (0, '1.8.4.1'), (1, 'sudo: 1 incorrect password attempt hidden-test-password')])
        self.assertTrue(result['stop'])
        self.assertNotIn('hidden-test-password', json.dumps(result))

    def test_remote_error_does_not_persist_secret(self):
        result = self.perform([(0, 'a702-06'), (0, '1.8.4.1'), (1, 'failure hidden-test-password')])
        self.assertNotIn('hidden-test-password', json.dumps(result))


class InterfaceTests(unittest.TestCase):
    def app(self):
        app = gui.Manager.__new__(gui.Manager)
        app.window = object()
        app.domain = ''
        app.selected = {'a702-06'}
        app.statuses, app.trusted, app.catalog, app.last_ips = {}, {}, {}, {}
        app.credential_status = types.SimpleNamespace(set=lambda text: None)
        app.events = queue.Queue()
        app.refresh = lambda: None
        app.set_busy = lambda value: None
        app.summary = types.SimpleNamespace(set=lambda text: None)
        return app

    def test_room_change_clears_hidden_selection(self):
        app = self.app()
        app.change_room()
        self.assertEqual(app.selected, set())

    def test_cancel_confirmation_never_requests_password(self):
        app = self.app()
        row = dict(name='a702-06', ip='10.42.22.26', ok=True, type='ssh-ed25519', key='key')
        app.trusted[row['name']] = row
        with patch.object(gui.messagebox, 'askokcancel', return_value=False), patch.object(gui.simpledialog, 'askstring') as password:
            app.discovered([core.Host('a702-06', row['ip'], '702')], 'off', 1, [row])
        password.assert_not_called()

    def test_refused_host_trust_never_requests_password(self):
        app = self.app()
        app.trust_dialog = lambda text: False
        row = dict(name='a702-06', ip='10.42.22.26', ok=True, type='ssh-ed25519', key='key', fingerprint='SHA256:key')
        with patch.object(gui.simpledialog, 'askstring') as password:
            app.discovered([core.Host('a702-06', row['ip'], '702')], 'off', 1, [row])
        password.assert_not_called()
        self.assertFalse(app.trusted)

    def test_scan_never_asks_password_or_trust(self):
        app = self.app()
        row = dict(name='a702-06', ip='10.42.22.26', ok=True, type='ssh-ed25519', key='key')
        with patch.object(gui.simpledialog, 'askstring') as password:
            app.discovered([core.Host('a702-06', row['ip'], '702')], 'scan', 1, [row])
        password.assert_not_called()
        self.assertFalse(app.trusted)

    def test_stopped_batch_reports_all_remaining_hosts_as_skipped(self):
        app = self.app()
        with tempfile.TemporaryDirectory() as directory:
            app.data = Path(directory)
            rows = [dict(name='a702-%02d' % n, ip='10.42.22.%d' % (20 + n)) for n in range(1, 4)]
            hosts = {r['name']: core.Host(r['name'], r['ip'], '702') for r in rows}
            failure = dict(rows[0], ok=False, stop=True, message='Неверный пароль')
            with patch.object(gui, 'execute', return_value=failure) as execute:
                app.send(hosts, rows, 'hidden-test-password', 'off', 1, [])
            self.assertEqual(execute.call_count, 1)
            reports = list((app.data / 'reports').glob('*.json'))
            self.assertEqual(len(reports), 1)
            text = reports[0].read_text()
            self.assertNotIn('hidden-test-password', text)
            report = json.loads(text)
            self.assertEqual(len(report), 3)
            self.assertTrue(all(not r['ok'] for r in report))


class NewFeaturesTests(unittest.TestCase):
    def test_dns_ignores_old_address_and_resolves_fqdn_every_time(self):
        host = core.Host('a701-02', '10.42.22.2', '701', domain='school.example')
        with patch.object(core.socket, 'getaddrinfo', return_value=[(None, None, None, None, ('10.42.22.88', 22))]) as resolver:
            self.assertEqual(core.resolve(host), '10.42.22.88')
            core.resolve(host)
            self.assertEqual(resolver.call_count, 2)
            self.assertEqual(resolver.call_args.args[0], 'a701-02.school.example')

    def test_dns_failure_never_falls_back_to_stale_ip(self):
        with patch.object(core.socket, 'getaddrinfo', side_effect=core.socket.gaierror()), patch.object(core.socket, 'create_connection') as connect:
            result = core.probe(core.Host('a701-02', '10.42.22.2', '701'))
        self.assertFalse(result['ok'])
        connect.assert_not_called()

    def test_ambiguous_or_public_dns_rejected(self):
        for ips in [('10.42.22.2', '10.42.22.3'), ('8.8.8.8',)]:
            answers = [(None, None, None, None, (ip, 22)) for ip in ips]
            with patch.object(core.socket, 'getaddrinfo', return_value=answers):
                with self.assertRaises(ValueError):
                    core.resolve(core.Host('pc-01', '', '701'))

    def test_static_mode_does_not_resolve_dns(self):
        with patch.object(core.socket, 'getaddrinfo') as resolver:
            self.assertEqual(core.resolve(core.Host('pc-01', '10.42.22.3', '701', 'fixed')), '10.42.22.3')
        resolver.assert_not_called()

    def test_class_and_computer_edits_persist_including_empty_classes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'inventory.json'
            hosts = core.validate_hosts([dict(name='pc-01', room='Новый класс', mode='dns')])
            core.save_inventory(path, ['Новый класс', 'Пустой'], hosts)
            rooms, saved = core.load_inventory(path)
            self.assertEqual(rooms, ['Новый класс', 'Пустой'])
            self.assertEqual(saved, hosts)
            core.save_inventory(path, ['Пустой'], [])
            self.assertEqual(core.load_inventory(path), (['Пустой'], []))
            core.save_inventory(path, [], [])
            self.assertEqual(core.load_inventory(path), ([], []))

    def test_bad_inventory_does_not_replace_saved_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'inventory.json'
            core.save_inventory(path, ['701'], [])
            before = path.read_bytes()
            for rooms, hosts in [(['701', '701'], []), ([], [core.Host('pc-01', '', '701')])]:
                with self.assertRaises(ValueError):
                    core.save_inventory(path, rooms, hosts)
                self.assertEqual(path.read_bytes(), before)

    def test_duplicate_fixed_address_rejected_but_dns_hints_not_used(self):
        rows = [dict(name='pc-01', ip='10.42.22.2', mode='fixed'), dict(name='pc-02', ip='10.42.22.2', mode='fixed')]
        with self.assertRaises(ValueError):
            core.validate_hosts(rows)
        for row in rows:
            row['mode'] = 'dns'
        self.assertEqual(len(core.validate_hosts(rows)), 2)

    def test_immediate_actions_use_now_and_cancel_is_separate(self):
        self.assertIn('shutdown -P now ', core.power_command('off', 0))
        self.assertIn('shutdown -r now ', core.power_command('reboot', 0))
        self.assertTrue(core.power_command('cancel', 0).endswith('shutdown -c'))

    def test_removing_room_keeps_computers_unassigned(self):
        app = InterfaceTests().app()
        with tempfile.TemporaryDirectory() as directory:
            app.inventory_file = Path(directory) / 'inventory.json'
            app.rooms = ['701', '702']
            app.hosts = [core.Host('a701-02', '', '701'), core.Host('a702-06', '', '702')]
            app.room = types.SimpleNamespace(get=lambda: '701', set=lambda value: None)
            with patch.object(gui.messagebox, 'askyesno', return_value=True), patch.object(gui, 'execute') as execute:
                app.remove_room()
            self.assertEqual(app.rooms, ['702'])
            self.assertEqual([(host.name, host.room) for host in app.hosts], [('a701-02', ''), ('a702-06', '702')])
            self.assertEqual(core.load_inventory(app.inventory_file), (app.rooms, app.hosts))
            execute.assert_not_called()

    def test_saved_password_avoids_prompt(self):
        app = InterfaceTests().app()
        with patch.object(store, 'load', return_value='hidden-test-password'), patch.object(gui.simpledialog, 'askstring') as prompt:
            self.assertEqual(app.get_password(), 'hidden-test-password')
        prompt.assert_not_called()

    def test_unsaved_password_is_prompted_without_automatic_storage(self):
        app = InterfaceTests().app()
        with patch.object(store, 'load', return_value=None), patch.object(gui.simpledialog, 'askstring', return_value='test') as prompt, patch.object(store, 'save') as save:
            self.assertEqual(app.get_password(), 'test')
        prompt.assert_called_once()
        save.assert_not_called()


class CredentialTests(unittest.TestCase):
    def setUp(self):
        self.saved = None
        self.freed = False
        self.last_error = store.NOT_FOUND
        self.backend = types.SimpleNamespace(write=self.write, read=self.read, delete=self.delete, free=self.free, last_error=lambda: self.last_error)
        self.addCleanup(patch.stopall)
        patch.object(store, 'api', return_value=self.backend).start()
        patch.object(store, 'os', types.SimpleNamespace(name='nt')).start()

    def write(self, pointer, flags):
        record = ctypes.cast(pointer, ctypes.POINTER(store.Credential)).contents
        self.assertEqual(record.TargetName, store.TARGET)
        self.assertEqual(record.UserName, 'user')
        self.assertEqual(record.Type, 1)
        self.assertEqual(record.Persist, 2)
        self.saved = ctypes.string_at(record.CredentialBlob, record.CredentialBlobSize)
        return True

    def read(self, target, kind, flags, output):
        if self.saved is None:
            return False
        self.buffer = (store.wintypes.BYTE * len(self.saved)).from_buffer_copy(self.saved)
        self.record = store.Credential()
        self.record.UserName = 'user'
        self.record.CredentialBlobSize = len(self.saved)
        self.record.CredentialBlob = ctypes.cast(self.buffer, ctypes.POINTER(store.wintypes.BYTE))
        ctypes.cast(output, ctypes.POINTER(ctypes.POINTER(store.Credential)))[0] = ctypes.pointer(self.record)
        return True

    def free(self, pointer):
        self.freed = True

    def delete(self, *args):
        self.saved = None
        return True

    def test_unicode_save_read_and_delete_through_windows_api(self):
        store.save('Пароль-test-123')
        self.assertEqual(store.load(), 'Пароль-test-123')
        self.assertTrue(self.freed)
        store.delete()
        self.assertIsNone(store.load())

    def test_invalid_password_rejected_before_api(self):
        for password in ['', 'one\ntwo', 'x' * 1281]:
            with self.assertRaises(ValueError):
                store.save(password)
        self.assertIsNone(self.saved)

    def test_corrupt_blob_is_freed_and_not_disclosed_in_error(self):
        self.saved = b'secret!'
        with self.assertRaisesRegex(RuntimeError, 'повреждён') as error:
            store.load()
        self.assertNotIn('secret', str(error.exception))
        self.assertTrue(self.freed)

    def test_api_failure_does_not_fall_back_to_password_file(self):
        self.backend.write = lambda *args: False
        self.last_error = 5
        with self.assertRaisesRegex(RuntimeError, 'код 5'):
            store.save('secret')
        self.assertIsNone(self.saved)


if __name__ == '__main__':
    unittest.main()
