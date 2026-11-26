"""Real Tk checks. Run separately with a desktop session, never from headless build."""
import json
from pathlib import Path
import tempfile
import tkinter as tk
from tkinter import ttk
import types
import unittest
from unittest.mock import Mock, patch

import class_manager as gui
import cm_core as core
import cm_ui


class WorkbenchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = tk.Tk()
        root = Path(__file__).resolve().parent
        assets = root if (root / 'computers.json').exists() else root.parents[1] / 'outputs/CM-Astra'
        self.assets = patch.object(gui, 'ROOT', assets)
        self.assets.start()
        fixtures = core.load_hosts(assets / 'legacy-lists' / 'comp2.lst')
        core.save_inventory(Path(self.temp.name) / 'inventory.json', sorted({h.room for h in fixtures}), fixtures)
        self.app = gui.Manager(self.root, data=self.temp.name)
        self.root.update_idletasks()

    def tearDown(self):
        self.app.closing = True
        self.app.shutdown.cancel()
        self.root.destroy()
        self.assets.stop()
        self.temp.cleanup()

    def test_both_themes_fit_small_and_large_windows(self):
        app = self.app
        for theme in ('light', 'dark'):
            app.theme.set(theme)
            app.apply_theme()
            for width, height in [(850, 600), (1024, 768), (1220, 800)]:
                with self.subTest(theme=theme, width=width, height=height):
                    self.root.geometry(str(width) + 'x' + str(height))
                    self.root.update_idletasks()
                    for widget in app.controls + [app.room_list, app.table, app.task_table, app.summary_label, app.delay_box]:
                        x, y = widget.winfo_rootx() - self.root.winfo_rootx(), widget.winfo_rooty() - self.root.winfo_rooty()
                        self.assertTrue(widget.winfo_ismapped(), str(widget))
                        self.assertGreaterEqual(x, 0)
                        self.assertGreaterEqual(y, 0)
                        self.assertLessEqual(x + widget.winfo_width(), width + 2)
                        self.assertLessEqual(y + widget.winfo_height(), height + 2)
                        if widget in app.controls:
                            self.assertGreaterEqual(widget.winfo_width(), widget.winfo_reqwidth() - 2, widget.cget('text'))

    def test_long_room_name_keeps_action_buttons_visible(self):
        app = self.app
        name = 'Ш' * 40
        app.rooms.append(name)
        app.room.set(name)
        app.refresh()
        self.root.geometry('850x600')
        self.root.update_idletasks()
        self.assertEqual(app.room_title.get(), 'Кабинет ' + name)
        for widget in app.controls:
            self.assertTrue(widget.winfo_ismapped(), widget.cget('text'))
            self.assertGreaterEqual(widget.winfo_width(), widget.winfo_reqwidth() - 2, widget.cget('text'))

    def test_room_navigation_clears_selection_but_preserves_operations(self):
        app = self.app
        operation = app.operations.start('distribute', app.hosts[:1], {})
        operation['state'] = 'running'
        app.selected = {app.hosts[0].name}
        target = next(name for name in app.rooms if name != app.hosts[0].room)
        app.refresh_rooms()
        identifier = next(key for key, value in app.room_ids.items() if value == target)
        app.room_list.selection_set(identifier)
        app.room_selected()
        self.assertEqual(app.room.get(), target)
        self.assertFalse(app.selected)
        self.assertIn(operation['id'], app.operations.active)
        self.assertEqual(len(app.table.get_children()), sum(host.room == target for host in app.hosts))

    def test_theme_is_saved_and_updates_open_dialog_without_affecting_jobs(self):
        app = self.app
        operation = app.operations.start('command', app.hosts[:1], dict(script='sleep 1'))
        app.selected = {app.hosts[1].name}
        dialog = tk.Toplevel(self.root)
        text = tk.Text(dialog)
        text.pack()
        app.theme.set('dark')
        app.apply_theme()
        self.assertEqual(cm_ui.load_theme(Path(self.temp.name) / 'ui.json'), 'dark')
        self.assertEqual(text.cget('background'), cm_ui.PALETTES['dark']['surface'])
        self.assertEqual(app.selected, {app.hosts[1].name})
        self.assertIn(operation['id'], app.operations.active)
        self.assertFalse(app.shutdown.cancelled.is_set())
        app.theme.set('light')
        app.apply_theme()
        self.assertEqual(text.cget('foreground'), cm_ui.PALETTES['light']['foreground'])
        self.assertEqual(json.loads(app.ui_file.read_text()), dict(version=1, theme='light'))
        dialog.destroy()

    def test_theme_radio_control_runs_in_event_loop_and_keeps_operations(self):
        app = self.app
        operation = app.operations.start('command', app.hosts[:1], dict(script='sleep 1'))
        def descendants(widget):
            for child in widget.children.values():
                yield child
                yield from descendants(child)
        dark = next(widget for widget in descendants(self.root) if isinstance(widget, ttk.Radiobutton) and str(widget.cget('value')) == 'dark')
        self.root.after(20, dark.invoke)
        self.root.after(150, self.root.quit)
        self.root.mainloop()
        self.assertEqual(app.theme.get(), 'dark')
        self.assertEqual(cm_ui.load_theme(app.ui_file), 'dark')
        self.assertIn(operation['id'], app.operations.active)
        self.assertFalse(app.shutdown.cancelled.is_set())

    def test_results_keep_json_and_readable_output_in_both_themes(self):
        app = self.app
        app.last_results = [dict(name='a209-01', ok=True, message='Команда завершена, код 0', output='hello', cwd='~/lesson')]
        app.show_results()
        dialog = next(child for child in self.root.winfo_children() if isinstance(child, tk.Toplevel))
        def descendants(widget):
            for child in widget.children.values():
                yield child
                yield from descendants(child)
        notebook = next(child for child in descendants(dialog) if isinstance(child, ttk.Notebook))
        texts = [child for child in descendants(dialog) if isinstance(child, tk.Text)]
        self.assertEqual(len(notebook.tabs()), 2)
        self.assertIn('a209-01 — Успешно', texts[0].get('1.0', 'end'))
        self.assertIn('hello', texts[0].get('1.0', 'end'))
        self.assertEqual(json.loads(texts[1].get('1.0', 'end')), app.last_results)
        app.theme.set('dark')
        app.apply_theme()
        self.assertTrue(all(text.cget('background') == cm_ui.PALETTES['dark']['surface'] for text in texts))
        dialog.destroy()

    def test_time_sync_button_and_confirmation_require_selected_hosts(self):
        app = self.app
        with patch.object(app, 'begin') as begin:
            app.time_sync_button.invoke()
        begin.assert_called_once_with('time_sync')
        host = app.hosts[0]
        operation = app.operations.start('time_sync', [host], {})
        pin = dict(name=host.name, ip='192.168.22.1', ok=True, type='ssh-ed25519', key='key')
        with patch.object(gui, 'classify_key', return_value='trusted'), patch.object(gui.messagebox, 'askokcancel', return_value=False) as confirm, patch.object(app, 'get_password') as password, patch.object(gui.threading, 'Thread') as thread:
            app.discovered([host], 'time_sync', 0, [pin], operation_id=operation['id'])
        self.assertIn('компьютер учителя', confirm.call_args.args[1])
        self.assertIn('Часовой пояс', confirm.call_args.args[1])
        password.assert_not_called()
        thread.assert_not_called()
        self.assertNotIn(operation['id'], app.operations.active)

    def test_all_inventory_password_and_power_actions_stay_available_in_menus(self):
        labels = {menu.entrycget(index, 'label'): (menu, index, inventory) for menu, index, inventory in self.app.menu_controls}
        expected = ['Добавить ПК…', 'Изменить выбранную строку…', 'Удалить отмеченные ПК…',
                    'Перенести отмеченные в кабинет…', 'Импорт списка .csv / .lst / .json…', 'Найти ПК по IP…',
                    'Добавить кабинет…', 'Удалить текущий кабинет…', 'Сохранить / изменить пароль…',
                    'Забыть сохранённый пароль', 'Выключить…', 'Перезагрузить…',
                    'Отменить запланированное выключение / перезагрузку…',
                    'Отменить раздачу выбранным', 'Остановить команды выбранным…']
        self.assertTrue(set(expected).issubset(labels))
        self.app.operations.start('command', self.app.hosts[:1], {})
        self.app.set_busy(False)
        for label, (menu, index, inventory) in labels.items():
            self.assertEqual(str(menu.entrycget(index, 'state')), 'disabled' if inventory else 'normal', label)
        self.app.set_busy(True)
        self.assertTrue(all(str(menu.entrycget(index, 'state')) == 'disabled' for menu, index, inventory in labels.values()))

    def test_row_stop_only_targets_its_computer_and_preserves_other_selection(self):
        app = self.app
        operation = app.operations.start('command', app.hosts[:2], {})
        operation['state'] = 'running'
        operation['controls'] = {host.name: core.CommandControl(parent=app.shutdown) for host in app.hosts[:2]}
        app.selected = {app.hosts[1].name}
        with patch.object(gui.messagebox, 'askokcancel', return_value=True):
            app.stop_for_host(app.hosts[0].name)
        self.assertTrue(operation['controls'][app.hosts[0].name].stop_requested.is_set())
        self.assertFalse(operation['controls'][app.hosts[1].name].stop_requested.is_set())
        self.assertEqual(app.selected, {app.hosts[1].name})

    def test_refresh_preserves_focused_pc_and_scroll_and_task_details(self):
        app = self.app
        app.table.focus(app.hosts[8].name)
        app.table.selection_set(app.hosts[8].name)
        app.table.yview_moveto(.4)
        before = app.table.yview()[0]
        operation = app.operations.start('distribute', app.hosts[:2], dict(files=['lesson.txt']))
        operation['state'] = 'running'
        operation['progress'] = {h.name: dict(percent=30, complete=False) for h in app.hosts[:2]}
        app.refresh()
        self.assertEqual(app.table.focus(), app.hosts[8].name)
        self.assertEqual(app.table.selection(), (app.hosts[8].name,))
        self.assertAlmostEqual(app.table.yview()[0], before, places=2)
        self.assertTrue(app.task_table.exists(operation['id']))
        self.assertIn('30%', app.task_table.item(operation['id'], 'values')[2])
        app.task_table.selection_set(operation['id'])
        app.show_operation()
        dialogs = [child for child in self.root.winfo_children() if isinstance(child, tk.Toplevel)]
        self.assertEqual(len(dialogs), 1)
        app.theme.set('dark')
        app.apply_theme()
        self.assertEqual(dialogs[0].cget('background'), cm_ui.PALETTES['dark']['background'])
        dialogs[0].destroy()


    def test_csv_merge_preview_cancel_and_preserve_fixed_address(self):
        app = self.app
        old = app.hosts[0]
        from dataclasses import replace
        app.hosts[0] = replace(old, mode='fixed', ip='192.168.22.100')
        path = Path(self.temp.name) / 'computers.csv'
        path.write_text('кабинет;компьютер;логин\nНовый;' + old.name + ';admin\n')
        before = list(app.hosts)
        with patch.object(gui.messagebox,'askokcancel',return_value=False):
            app.import_csv(path)
        self.assertEqual(app.hosts, before)
        with patch.object(gui.messagebox,'askokcancel',return_value=True):
            app.import_csv(path)
        changed = next(h for h in app.hosts if h.name == old.name)
        self.assertEqual((changed.room,changed.username,changed.credential_mode,changed.ip),('Новый','admin','host','192.168.22.100'))
        self.assertEqual(len(app.hosts),len(before))

    def test_editor_saves_scoped_password_and_preserves_other_host(self):
        app = self.app
        old = app.hosts[0]
        def fill_and_save():
            dialog = next(w for w in self.root.winfo_children() if isinstance(w,tk.Toplevel))
            frame = dialog.winfo_children()[0]
            frame.grid_slaves(row=4,column=1)[0].delete(0,'end')
            frame.grid_slaves(row=4,column=1)[0].insert(0,'admin')
            field = frame.grid_slaves(row=5,column=1)[0]
            self.assertEqual(field.cget('show'), '*')
            field.insert(0,'private-test-value')
            bar = frame.grid_slaves(row=10,column=0)[0]
            next(w for w in bar.winfo_children() if w.cget('text')=='Сохранить').invoke()
        before = app.hosts[1]
        self.root.after(50,fill_and_save)
        # A timeout keeps a broken editor from blocking the test process.
        def close_dialog():
            for w in self.root.winfo_children():
                if isinstance(w,tk.Toplevel): w.destroy()
        timer=self.root.after(2000,close_dialog)
        with patch.object(gui.credential_store,'save') as save, patch.object(gui.messagebox,'showerror') as error:
            app.host_editor(old)
            error.assert_not_called()
        self.root.after_cancel(timer)
        save.assert_called_once_with('private-test-value','admin',old.name)
        self.assertIn(before,app.hosts)
        updated=next(h for h in app.hosts if h.name==old.name)
        self.assertEqual((updated.username,updated.credential_mode),('admin','host'))
        self.assertNotIn('private-test-value',app.inventory_file.read_text())


    def test_optional_network_domain_persists_without_changing_trust_or_accounts(self):
        app=self.app
        app.trusted={'pc-01':dict(key='test-key')}
        before=[(h.name,h.username,h.credential_mode) for h in app.hosts]
        for value in ('school.example',''):
            with patch.object(gui.simpledialog,'askstring',return_value=value):
                app.network_settings()
            self.assertTrue(all(h.domain==value for h in app.hosts))
            self.assertEqual(json.loads(app.network_file.read_text())['domain'],value)
            self.assertEqual([(h.name,h.username,h.credential_mode) for h in app.hosts],before)
            self.assertEqual(app.trusted['pc-01']['key'],'test-key')
        self.assertTrue(all(h.domain=='' for h in core.load_inventory(app.inventory_file)[1]))

    def test_fresh_installation_can_start_without_school_computers(self):
        assets=Path(self.temp.name)/'empty-assets'
        assets.mkdir()
        (assets/'computers.json').write_text('[]')
        (assets/'key-catalog.json').write_text('{}')
        window=tk.Toplevel(self.root)
        with patch.object(gui,'ROOT',assets):
            fresh=gui.Manager(window,data=Path(self.temp.name)/'fresh')
        self.assertEqual(fresh.hosts,[])
        self.assertEqual(fresh.rooms,[])
        self.assertEqual(fresh.domain,'')
        fresh.closing=True
        fresh.shutdown.cancel()
        window.destroy()


    def test_auto_network_dialog_cancel_does_not_scan(self):
        app=self.app
        rows=[dict(interface='LAN',ip='192.168.2.10',network='192.168.2.0/24')]
        def cancel():
            dialog=next(w for w in self.root.winfo_children() if isinstance(w,tk.Toplevel))
            def widgets(parent):
                for w in parent.winfo_children():
                    yield w
                    yield from widgets(w)
            next(w for w in widgets(dialog) if isinstance(w,ttk.Button) and w.cget('text')=='Отмена').invoke()
        self.root.after(50,cancel)
        with patch.object(app,'start_scan') as start:
            app.choose_local_network(rows)
        start.assert_not_called()

    def test_auto_network_dialog_selects_detected_scope_without_manual_input(self):
        app=self.app
        rows=[dict(interface='Wi-Fi',ip='10.20.30.10',network='10.20.0.0/16')]
        def start():
            dialog=next(w for w in self.root.winfo_children() if isinstance(w,tk.Toplevel))
            def widgets(parent):
                for w in parent.winfo_children():
                    yield w
                    yield from widgets(w)
            next(w for w in widgets(dialog) if isinstance(w,ttk.Button) and w.cget('text')=='Найти компьютеры').invoke()
        self.root.after(50,start)
        with patch.object(app,'start_scan') as scan:
            app.choose_local_network(rows)
        ips=scan.call_args.args[0]
        self.assertEqual(len(ips),253)
        self.assertEqual(ips[0],'10.20.30.1')
        self.assertNotIn('10.20.30.10',ips)


if __name__ == '__main__':
    unittest.main()
