"""Class Manager for a Windows teacher computer controlling Astra over SSH."""
from concurrent.futures import ThreadPoolExecutor, as_completed
import datetime
import json
import os
from pathlib import Path
import queue
import re
import posixpath
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
import uuid

from cm_core import Host, atomic_json, classify_key, execute, load_hosts, probe, hostname, room_name, validate_hosts, load_inventory, save_inventory, transfer_files, execute_command, parse_addresses, probe_address, inspect_address, same_key, remote_path, DEFAULT_INBOX, file_launch_spec, prepare_transfer, TransferAccessGate, OperationControl, OperationCancelled, CommandControl
import credential_store

ROOT = Path(__file__).resolve().parent


def data_directory():
    base = Path(os.environ.get('APPDATA', str(Path.home() / '.local/share')))
    return base / 'CM-Astra'


class OperationBook:
    """Main-thread operation state; ownership is released per finished computer."""
    def __init__(self):
        self.active = {}
        self.owners = {}

    def start(self, action, hosts, job):
        names = {host.name for host in hosts}
        conflicts = names.intersection(self.owners)
        if conflicts:
            raise ValueError('Эти ПК уже заняты: ' + ', '.join(sorted(conflicts)) + '. Выберите свободные ПК.')
        identifier = uuid.uuid4().hex
        operation = dict(id=identifier, action=action, job=dict(job or {}), pending=names,
                         state='preparing', progress={}, results=[])
        self.active[identifier] = operation
        for name in names:
            self.owners[name] = identifier
        return operation

    def release(self, identifier, name):
        operation = self.active.get(identifier)
        if operation:
            operation['pending'].discard(name)
        if self.owners.get(name) == identifier:
            del self.owners[name]

    def finish(self, identifier):
        operation = self.active.get(identifier)
        if operation:
            for name in list(operation['pending']):
                self.release(identifier, name)
            del self.active[identifier]


class OperationEvents:
    def __init__(self, queue, identifier):
        self.queue, self.identifier = queue, identifier

    def put(self, event):
        kind, value = event
        self.queue.put(('operation_event', (self.identifier, kind, value)))


class Manager:
    def __init__(self, window, data=None):
        self.window = window
        self.data = Path(data) if data else data_directory()
        self.data.mkdir(parents=True, exist_ok=True)
        self.host_file = self.data / 'computers.json'
        self.trust_file = self.data / 'trusted-keys.json'
        self.inventory_file = self.data / 'inventory.json'
        if self.inventory_file.exists():
            self.rooms, self.hosts = load_inventory(self.inventory_file)
        else:
            self.hosts = load_hosts(self.host_file if self.host_file.exists() else ROOT / 'computers.json')
            self.rooms = sorted({host.room for host in self.hosts})
        self.catalog = json.loads((ROOT / 'key-catalog.json').read_text(encoding='utf-8'))
        self.trusted = json.loads(self.trust_file.read_text(encoding='utf-8')) if self.trust_file.exists() else {}
        self.trusted = {value.get('name', key): value for key, value in self.trusted.items()}
        self.last_upload_directory = None
        self.operations = OperationBook()
        self.shutdown = OperationControl()
        self.closing = False
        self.preparing_operation = None
        self.inventory_controls = []
        self.last_results = []
        self.last_ips = {}
        self.selected = set()
        self.statuses = {}
        self.busy = False
        self.events = queue.Queue()
        self.controls = []
        window.title('CM Astra 1.9 — управление школьными компьютерами')
        window.geometry(str(min(1100, window.winfo_screenwidth() - 60)) + 'x' + str(min(800, window.winfo_screenheight() - 90)))
        window.minsize(850, 600)
        window.protocol('WM_DELETE_WINDOW', self.close)
        self.build()
        self.refresh()
        self.window.after(100, self.poll)

    def button(self, frame, text, command):
        widget = ttk.Button(frame, text=text, command=command)
        widget.pack(side='left', padx=(0, 7))
        self.controls.append(widget)
        return widget

    def build(self):
        outer = ttk.Frame(self.window, padding=18)
        outer.pack(fill='both', expand=True)
        ttk.Label(outer, text='Управление компьютерами Astra Linux', font=('Segoe UI', 17, 'bold')).pack(anchor='w')
        ttk.Label(outer, text='Отметьте свободные ПК. Завершившие работу ПК доступны сразу; остальные операции продолжаются в фоне.').pack(anchor='w', pady=(5, 15))
        toolbar = ttk.Frame(outer)
        toolbar.pack(fill='x', pady=(0, 10))
        ttk.Label(toolbar, text='Кабинет:').pack(side='left', padx=(0, 6))
        self.room = tk.StringVar(value='Все кабинеты')
        self.room_box = ttk.Combobox(toolbar, textvariable=self.room, state='readonly', width=17)
        self.room_box.pack(side='left', padx=(0, 15))
        self.room_box.bind('<<ComboboxSelected>>', lambda event: self.change_room())
        self.button(toolbar, 'Выбрать все в списке', self.select_visible)
        self.button(toolbar, 'Снять выбор', self.clear_selection)
        self.inventory_controls.append(self.button(toolbar, 'Открыть .lst / .json', self.import_list))
        editing = ttk.Frame(outer)
        editing.pack(fill='x', pady=(0, 10))
        self.inventory_controls.append(self.button(editing, 'Добавить ПК', self.add_host))
        self.inventory_controls.append(self.button(editing, 'Изменить ПК', self.edit_host))
        self.inventory_controls.append(self.button(editing, 'Удалить отмеченные', self.remove_hosts))
        groups = ttk.Frame(outer)
        groups.pack(fill='x', pady=(0, 10))
        self.inventory_controls.append(self.button(groups, 'Добавить класс', self.add_room))
        self.inventory_controls.append(self.button(groups, 'Удалить класс', self.remove_room))
        self.inventory_controls.append(self.button(groups, 'Перенести отмеченные в класс…', self.move_hosts))
        self.inventory_controls.append(self.button(groups, 'Поиск по диапазону IP…', self.scan_range))
        table_frame = ttk.Frame(outer)
        table_frame.pack(fill='both', expand=True)
        columns = ('check', 'name', 'ip', 'status')
        self.table = ttk.Treeview(table_frame, columns=columns, show='headings', selectmode='browse', height=5)
        for name, title, width in [('check', 'Выбор', 60), ('name', 'Компьютер', 160), ('ip', 'IP-адрес', 155), ('status', 'Состояние / результат', 540)]:
            self.table.heading(name, text=title)
            self.table.column(name, width=width, minwidth=width if name != 'status' else 260, stretch=name == 'status')
        self.table.tag_configure('chosen', background='#e8f1fa')
        self.table.tag_configure('error', foreground='#a32121')
        self.table.pack(side='left', fill='both', expand=True)
        scrollbar = ttk.Scrollbar(table_frame, orient='vertical', command=self.table.yview)
        scrollbar.pack(side='right', fill='y')
        self.table.configure(yscrollcommand=scrollbar.set)
        self.table.bind('<Button-1>', self.clicked)
        self.table.bind('<space>', self.key_toggle)
        self.counter = tk.StringVar()
        ttk.Label(outer, textvariable=self.counter).pack(anchor='w', pady=(8, 12))
        actions = ttk.Frame(outer)
        actions.pack(fill='x')
        self.button(actions, 'Проверить связь', lambda: self.begin('scan'))
        self.button(actions, 'Выключить…', lambda: self.begin('off'))
        self.button(actions, 'Перезагрузить…', lambda: self.begin('reboot'))
        self.button(actions, 'Отменить выключение', lambda: self.begin('cancel'))
        remote = ttk.Frame(outer)
        remote.pack(fill='x', pady=(10, 0))
        self.button(remote, 'Раздать файлы', self.distribute_dialog)
        self.button(remote, 'Отменить раздачу выбранным', self.cancel_distribution)
        remote = ttk.Frame(outer)
        remote.pack(fill='x', pady=(7, 0))
        self.button(remote, 'Запустить переданный файл…', self.launch_dialog)
        self.button(remote, 'Выполнить команду…', self.command_dialog)
        self.button(remote, 'Остановить команды выбранным', self.stop_commands)
        self.button(remote, 'Результаты', self.show_results)
        delay_row = ttk.Frame(outer)
        delay_row.pack(fill='x', pady=(12, 12))
        ttk.Label(delay_row, text='Выключение и перезагрузка через:').pack(side='left')
        self.delay = tk.StringVar(value='1')
        self.delay_box = ttk.Combobox(delay_row, textvariable=self.delay, state='readonly', values=('0', '1', '2', '5', '10', '15', '30'), width=4)
        self.delay_box.pack(side='left', padx=6)
        ttk.Label(delay_row, text='мин.  •  0 = немедленно. Для DHCP адрес определяется по имени.').pack(side='left')
        credentials = ttk.Frame(outer)
        credentials.pack(fill='x', pady=(0, 10))
        self.button(credentials, 'Сохранить / изменить пароль…', self.save_password)
        self.button(credentials, 'Забыть пароль', self.forget_password)
        self.credential_status = tk.StringVar(value='Хранилище: Windows Credentials / Linux Secret Service')
        ttk.Label(credentials, textvariable=self.credential_status).pack(side='left')
        self.progress = ttk.Progressbar(outer, mode='indeterminate')
        self.progress.pack(fill='x', pady=(0, 7))
        self.summary = tk.StringVar(value='Готово. Сначала отметьте компьютеры в столбце «Выбор».')
        ttk.Label(outer, textvariable=self.summary, wraplength=940).pack(anchor='w')

    def visible(self):
        room = self.room.get()
        return [h for h in self.hosts if room == 'Все кабинеты' or h.room == room]

    def refresh(self):
        self.room_box['values'] = ['Все кабинеты'] + sorted(self.rooms)
        self.table.delete(*self.table.get_children())
        for host in self.visible():
            chosen = host.name in self.selected
            status, failed = self.statuses.get(host.name, ('Не проверен', False))
            tags = (['chosen'] if chosen else []) + (['error'] if failed else [])
            self.table.insert('', 'end', iid=host.name, values=('☑' if chosen else '☐', host.name, self.last_ips.get(host.name, 'Авто (DNS)' if host.mode == 'dns' else host.ip), status), tags=tags)
        self.counter.set('Выбрано: ' + str(len(self.selected)) + '   •   В списке: ' + str(len(self.visible())))

    def change_room(self):
        # A hidden selection must never shut down computers from another classroom.
        self.selected.clear()
        self.refresh()

    def clicked(self, event):
        if self.busy or self.table.identify_column(event.x) != '#1':
            return
        name = self.table.identify_row(event.y)
        if name:
            self.toggle(name)
            return 'break'

    def key_toggle(self, event):
        if not self.busy and self.table.focus():
            self.toggle(self.table.focus())
        return 'break'

    def toggle(self, name):
        owners = getattr(getattr(self, 'operations', None), 'owners', {})
        operation = getattr(getattr(self, 'operations', None), 'active', {}).get(owners.get(name), {})
        if name in owners and name not in self.selected and operation.get('action') not in ('distribute', 'command'):
            messagebox.showinfo('Компьютер занят', name + ': дождитесь окончания его операции или выберите другой ПК.', parent=self.window)
            return
        if name in self.selected:
            self.selected.remove(name)
        else:
            self.selected.add(name)
        self.refresh()
        self.table.focus(name)

    def select_visible(self):
        occupied = getattr(getattr(self, 'operations', None), 'owners', {})
        self.selected = {h.name for h in self.visible() if h.name not in occupied}
        self.refresh()

    def clear_selection(self):
        self.selected.clear()
        self.refresh()

    def import_list(self):
        path = filedialog.askopenfilename(parent=self.window, title='Список компьютеров CM', filetypes=[('Списки CM', '*.lst *.json'), ('Все файлы', '*.*')])
        if not path:
            return
        try:
            raw = json.loads(Path(path).read_text(encoding='utf-8')) if Path(path).suffix.lower() == '.json' else None
            if isinstance(raw, dict) and raw.get('version') == 2:
                rooms, rows = load_inventory(path)
            else:
                rows = load_hosts(path)
                rooms = sorted({host.room for host in rows})
            save_inventory(self.inventory_file, rooms, rows)
            self.hosts = rows
            self.rooms = rooms
            self.last_ips.clear()
            self.selected.clear()
            self.statuses.clear()
            self.room.set('Все кабинеты')
            self.refresh()
            self.summary.set('Загружен список: ' + Path(path).name)
        except Exception as error:
            messagebox.showerror('Список не загружен', str(error), parent=self.window)

    def persist(self):
        save_inventory(self.inventory_file, self.rooms, self.hosts)

    def add_room(self):
        value = simpledialog.askstring('Добавить класс', 'Название класса, например 208:', parent=self.window)
        if value is None:
            return
        try:
            name = room_name(value)
            if name in self.rooms:
                raise ValueError('Такой класс уже есть')
            save_inventory(self.inventory_file, self.rooms + [name], self.hosts)
            self.rooms.append(name)
            self.room.set(name)
            self.change_room()
        except Exception as error:
            messagebox.showerror('Класс не добавлен', str(error), parent=self.window)

    def remove_room(self):
        room = self.room.get()
        if room == 'Все кабинеты':
            messagebox.showinfo('Выберите класс', 'Выберите удаляемый класс в списке кабинетов.', parent=self.window)
            return
        count = sum(host.room == room for host in self.hosts)
        if not messagebox.askyesno('Удалить класс', 'Удалить класс «' + room + '» и его записи ПК (' + str(count) + ')?\nСами компьютеры и домен не изменятся.', default='no', parent=self.window):
            return
        try:
            rooms = [value for value in self.rooms if value != room]
            hosts = [host for host in self.hosts if host.room != room]
            save_inventory(self.inventory_file, rooms, hosts)
            self.rooms, self.hosts = rooms, hosts
            self.room.set('Все кабинеты')
            self.change_room()
        except Exception as error:
            messagebox.showerror('Класс не удалён', str(error), parent=self.window)

    def add_host(self):
        self.host_editor()

    def edit_host(self):
        focus = self.table.focus()
        host = next((host for host in self.hosts if host.name == focus), None)
        if not host:
            messagebox.showinfo('Выберите ПК', 'Нажмите на строку компьютера для изменения.', parent=self.window)
            return
        self.host_editor(host)

    def host_editor(self, original=None):
        if not self.rooms:
            messagebox.showinfo('Добавьте класс', 'Сначала нажмите «Добавить класс».', parent=self.window)
            return
        dialog = tk.Toplevel(self.window)
        dialog.title('Изменить компьютер' if original else 'Добавить компьютер')
        dialog.transient(self.window)
        frame = ttk.Frame(dialog, padding=18)
        frame.pack(fill='both', expand=True)
        name = tk.StringVar(value=original.name if original else '')
        selected_room = self.room.get() if self.room.get() in self.rooms else sorted(self.rooms)[0]
        room = tk.StringVar(value=original.room if original else selected_room)
        mode = tk.StringVar(value='По имени (DHCP / DNS)' if not original or original.mode == 'dns' else 'Постоянный IP')
        ip = tk.StringVar(value=original.ip if original and original.mode == 'fixed' else '')
        for row, (label, widget) in enumerate([
            ('Имя ПК:', ttk.Entry(frame, textvariable=name, width=42)),
            ('Класс:', ttk.Combobox(frame, textvariable=room, values=sorted(self.rooms), state='readonly', width=39)),
            ('Адресация:', ttk.Combobox(frame, textvariable=mode, values=('По имени (DHCP / DNS)', 'Постоянный IP'), state='readonly', width=39)),
            ('Постоянный IP:', ttk.Entry(frame, textvariable=ip, width=42))]):
            ttk.Label(frame, text=label).grid(row=row, column=0, sticky='w', padx=(0, 12), pady=6)
            widget.grid(row=row, column=1, sticky='ew', pady=6)
            if row == 0:
                first = widget
            if row == 3:
                ip_entry = widget
        def mode_changed(event=None):
            ip_entry.configure(state='disabled' if mode.get().startswith('По имени') else 'normal')
        frame.grid_slaves(row=2, column=1)[0].bind('<<ComboboxSelected>>', mode_changed)
        mode_changed()
        ttk.Label(frame, text='Пример: a208-02. Для DHCP программа каждый раз ищет\nимя в домене 534school.spb.ru через школьный DNS.').grid(row=4, columnspan=2, sticky='w', pady=12)
        def save():
            try:
                dns = mode.get().startswith('По имени')
                candidate = dict(name=hostname(name.get()), room=room.get(), ip='' if dns else ip.get(), mode='dns' if dns else 'fixed')
                rows = [dict(name=h.name, room=h.room, ip=h.ip, mode=h.mode) for h in self.hosts if original is None or h.name != original.name]
                rows.append(candidate)
                hosts = validate_hosts(rows)
                save_inventory(self.inventory_file, self.rooms, hosts)
                self.hosts = hosts
                self.selected.clear()
                self.last_ips.clear()
                self.statuses.clear()
                self.refresh()
                dialog.destroy()
            except Exception as error:
                messagebox.showerror('Компьютер не сохранён', str(error), parent=dialog)
        bar = ttk.Frame(frame)
        bar.grid(row=5, columnspan=2, sticky='ew')
        ttk.Button(bar, text='Сохранить', command=save).pack(side='left')
        ttk.Button(bar, text='Отмена', command=dialog.destroy).pack(side='right')
        dialog.grab_set()
        first.focus_set()
        self.window.wait_window(dialog)

    def remove_hosts(self):
        targets = {host.name for host in self.visible() if host.name in self.selected}
        if not targets:
            messagebox.showinfo('Выберите ПК', 'Отметьте компьютеры для удаления из списка.', parent=self.window)
            return
        if not messagebox.askyesno('Удалить записи компьютеров', 'Удалить из списка: ' + ', '.join(sorted(targets)) + '?\nСами компьютеры и домен не изменятся.', default='no', parent=self.window):
            return
        try:
            hosts = [host for host in self.hosts if host.name not in targets]
            save_inventory(self.inventory_file, self.rooms, hosts)
            self.hosts = hosts
            self.selected.clear()
            self.refresh()
        except Exception as error:
            messagebox.showerror('Компьютеры не удалены', str(error), parent=self.window)

    def save_password(self):
        password = simpledialog.askstring('Сохранить пароль', 'Пароль локального user на школьных ПК:\nБудет сохранён в системном хранилище текущего пользователя.', show='*', parent=self.window)
        if not password:
            return
        try:
            credential_store.save(password)
            self.credential_status.set('Пароль сохранён в системном хранилище')
        except Exception as error:
            messagebox.showerror('Пароль не сохранён', str(error), parent=self.window)
        finally:
            password = None

    def forget_password(self):
        try:
            credential_store.delete()
            self.credential_status.set('Сохранённый пароль удалён')
        except Exception as error:
            messagebox.showerror('Пароль не удалён', str(error), parent=self.window)

    def get_password(self):
        password = credential_store.load()
        if password:
            self.credential_status.set('Используется пароль из системного хранилища')
            return password
        return simpledialog.askstring('Пароль администратора', 'Общий пароль локального user на выбранных ПК:\nДля сохранения используйте кнопку «Сохранить / изменить пароль».', show='*', parent=self.window)

    def move_hosts(self):
        targets = {host.name for host in self.visible() if host.name in self.selected}
        if not targets:
            messagebox.showinfo('Выберите ПК', 'Отметьте компьютеры для переноса в класс.', parent=self.window)
            return
        dialog = tk.Toplevel(self.window)
        dialog.title('Перенести компьютеры в класс')
        dialog.transient(self.window)
        frame = ttk.Frame(dialog, padding=18)
        frame.pack()
        ttk.Label(frame, text='Новый класс для отмеченных ПК:').pack(anchor='w')
        destination = tk.StringVar(value=sorted(self.rooms)[0])
        ttk.Combobox(frame, textvariable=destination, values=sorted(self.rooms), state='readonly', width=35).pack(pady=10)
        def save():
            try:
                hosts = [Host(h.name, h.ip, destination.get() if h.name in targets else h.room, h.mode) for h in self.hosts]
                save_inventory(self.inventory_file, self.rooms, hosts)
                self.hosts = hosts
                self.selected.clear()
                self.refresh()
                dialog.destroy()
            except Exception as error:
                messagebox.showerror('Перенос не выполнен', str(error), parent=dialog)
        ttk.Button(frame, text='Перенести', command=save).pack(side='left')
        ttk.Button(frame, text='Отмена', command=dialog.destroy).pack(side='right')
        dialog.grab_set()
        self.window.wait_window(dialog)

    def distribute_dialog(self):
        files = filedialog.askopenfilenames(parent=self.window, title='Файлы для одновременной раздачи выбранным ПК (до 20)')
        if not files:
            return
        if len(files) > 20:
            messagebox.showerror('Передача файлов', 'За одну отправку допускается до 20 файлов.', parent=self.window)
            return
        batch = datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8]
        destination = simpledialog.askstring(
            'Куда передать файлы на ученических ПК?',
            'Папка НА УЧЕНИЧЕСКИХ ПК (одинаковый путь для всех выбранных):\n'
            '~/ — домашняя папка user; можно указать /полный/путь.\n'
            'Недостающие папки будут созданы. При совпадении имени будет вопрос о перезаписи.\n'
            'Передача не запускает файлы. Права записи — у user.',
            initialvalue=DEFAULT_INBOX, parent=self.window)
        if destination is None:
            return
        try:
            destination = remote_path(destination)
        except ValueError as error:
            messagebox.showerror('Папка назначения', str(error), parent=self.window)
            return
        self.begin('distribute', dict(files=list(files), batch=batch, destination=destination))

    def cancel_distribution(self):
        targets = []
        for host in self.visible():
            if host.name not in self.selected:
                continue
            operation = self.operations.active.get(self.operations.owners.get(host.name), {})
            if operation.get('action') == 'distribute':
                control = operation.get('controls', {}).get(host.name)
                if control and not control.cancelled.is_set():
                    targets.append((host.name, control))
        if not targets:
            messagebox.showinfo('Отмена раздачи', 'Отметьте ПК, которые ещё получают файлы, затем нажмите «Отменить раздачу выбранным».', parent=self.window)
            return
        for name, control in targets:
            control.cancel()
            self.statuses[name] = ('Отмена раздачи…', False)
            self.selected.discard(name)
        self.refresh()
        self.summary.set('Отмена раздачи запрошена для ' + str(len(targets)) + ' ПК. Остальные операции продолжаются.')

    def stop_commands(self):
        targets = []
        for host in self.visible():
            if host.name not in self.selected:
                continue
            operation = self.operations.active.get(self.operations.owners.get(host.name), {})
            control = operation.get('controls', {}).get(host.name)
            if operation.get('action') == 'command' and isinstance(control, CommandControl) and not control.stop_requested.is_set():
                targets.append((host.name, control))
        if not targets:
            messagebox.showinfo('Остановка команды', 'Отметьте ПК с выполняющейся командой, затем нажмите «Остановить команды выбранным».', parent=self.window)
            return
        text = ('Остановить команды на выбранных ПК?\n\n' + ', '.join(name for name, control in targets)
                + '\n\nУстановка пакетов может остаться незавершённой. Остановка не откатывает изменения. '
                  'Команды на остальных ПК продолжатся.')
        if not messagebox.askokcancel('Остановка выбранных команд', text, icon='warning', default='cancel', parent=self.window):
            return
        requested = 0
        for name, control in targets:
            current = self.operations.active.get(self.operations.owners.get(name), {})
            if current.get('controls', {}).get(name) is not control:
                continue  # The command may have finished while confirmation was open.
            requested += 1
            control.request_stop()
            self.statuses[name] = ('Остановка команды…', False)
            self.selected.discard(name)
        self.refresh()
        self.summary.set('Остановка запрошена для ' + str(requested) + ' ПК. Ожидается подтверждение удалённых процессов.' if requested else 'Выбранные команды уже завершены.')

    def transferred_files(self):
        records = []
        for report in sorted((self.data / 'reports').glob('*.json'))[-100:]:
            try:
                rows = json.loads(report.read_text(encoding='utf-8'))
                if isinstance(rows, list):
                    records.extend(rows)
            except (OSError, ValueError):
                continue
        records.extend(self.last_results)
        for operation in getattr(getattr(self, 'operations', None), 'active', {}).values():
            records.extend(operation['results'])
        groups = {}
        for row in records:
            if not isinstance(row, dict) or row.get('action') not in ('upload', 'download'):
                continue
            for item in row.get('files', []):
                try:
                    spec = file_launch_spec(item['path'], item['sha256'])
                    name = posixpath.basename(item['path'])
                    groups.setdefault((name, item['sha256']), {})[row['name']] = spec
                except (KeyError, TypeError, ValueError):
                    continue
        return groups

    def launch_dialog(self):
        selected = {h.name for h in self.visible() if h.name in self.selected}
        if not selected:
            messagebox.showinfo('Выберите компьютеры', 'Отметьте ПК, на которых нужно запустить переданный файл.', parent=self.window)
            return
        groups = [(key, targets) for key, targets in self.transferred_files().items() if selected.intersection(targets)]
        if not groups:
            messagebox.showinfo('Нет переданных файлов', 'Передайте .sh или .deb на выбранные ПК. Список берётся из последних 100 отчётов передачи.', parent=self.window)
            return
        dialog = tk.Toplevel(self.window)
        dialog.title('Выбор переданного .sh или .deb')
        dialog.transient(self.window)
        frame = ttk.Frame(dialog, padding=16)
        frame.pack(fill='both', expand=True)
        ttk.Label(frame, text='Выберите файл. Команда и папка будут подставлены; затем проверьте и подтвердите запуск.').pack(anchor='w')
        labels = [key[0] + ' • SHA-256 ' + key[1][:12] + ' • ПК: ' + str(len(selected.intersection(targets))) + '/' + str(len(selected)) for key, targets in groups]
        choice = ttk.Combobox(frame, values=labels, state='readonly', width=95)
        choice.current(0)
        choice.pack(fill='x', pady=10)
        details = tk.StringVar()
        def show_paths(event=None):
            targets = groups[choice.current()][1]
            details.set('\n'.join(name + ': ' + (targets[name]['expected_file']['path'] if name in targets else 'нет подтверждённой передачи') for name in sorted(selected)))
        choice.bind('<<ComboboxSelected>>', show_paths)
        ttk.Label(frame, textvariable=details, wraplength=850).pack(anchor='w')
        show_paths()
        def prepare():
            targets = groups[choice.current()][1]
            missing = sorted(selected.difference(targets))
            if missing:
                messagebox.showerror('Файл не передан на все выбранные ПК', 'Сначала передайте этот файл или снимите выбор: ' + ', '.join(missing), parent=dialog)
                return
            spec = targets[next(iter(selected))]
            preset = dict(spec, targets={name: targets[name] for name in selected})
            dialog.destroy()
            self.command_dialog(preset)
        ttk.Button(frame, text='Подготовить команду…', command=prepare).pack(side='right', pady=12)
        ttk.Button(frame, text='Отмена', command=dialog.destroy).pack(side='left', pady=12)
        dialog.grab_set()
        self.window.wait_window(dialog)

    def command_dialog(self, preset=None):
        dialog = tk.Toplevel(self.window)
        dialog.title('Команда на выбранных ПК Astra')
        dialog.transient(self.window)
        frame = ttk.Frame(dialog, padding=16)
        frame.pack(fill='both', expand=True)
        ttk.Label(frame, text='Введите команду Bash. Выполнение начнётся после выбора и подтверждения списка ПК.').pack(anchor='w')
        text = tk.Text(frame, width=85, height=10, wrap='word')
        text.insert('1.0', preset['script'] if preset else 'hostname; uptime')
        text.pack(fill='both', expand=True, pady=10)
        ttk.Label(frame, text='Рабочая папка НА УЧЕНИЧЕСКИХ ПК (~ — домашняя папка user):').pack(anchor='w')
        cwd = tk.StringVar(value=preset['cwd'] if preset else '~')
        ttk.Entry(frame, textvariable=cwd, width=85, state='readonly' if preset else 'normal').pack(fill='x', pady=4)
        if preset:
            ttk.Label(frame, text='Папка берётся из отчёта отдельно для каждого ПК. Перед запуском файл проверяется SHA-256.').pack(anchor='w')
        if self.last_upload_directory and not preset:
            ttk.Button(frame, text='Подставить папку последней передачи',
                       command=lambda: cwd.set(self.last_upload_directory)).pack(anchor='w')
        ttk.Label(frame, text="Пример для переданного скрипта: sh './setup.sh'\n"
                  "Для .deb с sudo: apt-get install -y './package.deb'\n"
                  'Если папки нет, команда не запускается. ~ означает папку user и при sudo.').pack(anchor='w', pady=6)
        sudo = tk.BooleanVar(value=preset['sudo'] if preset else False)
        ttk.Checkbutton(frame, text='Выполнить от root через sudo', variable=sudo).pack(anchor='w')
        ttk.Label(frame, text='Не вводите пароли в текст команды: команды и вывод сохраняются в отчёте.').pack(anchor='w', pady=8)
        bar = ttk.Frame(frame)
        bar.pack(fill='x')
        ttk.Label(bar, text='Ожидание, секунд (10–1800):').pack(side='left')
        timeout = tk.StringVar(value='300')
        ttk.Entry(bar, textvariable=timeout, width=6).pack(side='left', padx=6)
        def submit():
            try:
                job = dict(script=text.get('1.0', 'end-1c'), sudo=sudo.get(), timeout=int(timeout.get()), cwd=remote_path(cwd.get()))
                if not job['script'].strip() or len(job['script'].encode()) > 32768 or not 10 <= job['timeout'] <= 1800:
                    raise ValueError('Проверьте команду (до 32 КБ) и время ожидания')
                if preset:
                    job['targets'] = preset['targets']
                dialog.destroy()
                self.begin('command', job)
            except Exception as error:
                messagebox.showerror('Команда', str(error), parent=dialog)
        ttk.Button(bar, text='Продолжить…', command=submit).pack(side='right')
        ttk.Button(bar, text='Отмена', command=dialog.destroy).pack(side='right', padx=8)
        dialog.grab_set()
        self.window.wait_window(dialog)

    def show_results(self):
        dialog = tk.Toplevel(self.window)
        dialog.title('Последние результаты CM')
        dialog.geometry('850x550')
        frame = ttk.Frame(dialog, padding=12)
        frame.pack(fill='both', expand=True)
        text = tk.Text(frame, wrap='word')
        scrollbar = ttk.Scrollbar(frame, command=text.yview)
        text.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side='right', fill='y')
        text.pack(fill='both', expand=True)
        text.insert('1.0', json.dumps(self.last_results, ensure_ascii=False, indent=2) if self.last_results else 'Пока нет результатов действий.')
        text.configure(state='disabled')

    def scan_range(self):
        value = simpledialog.askstring('Найти компьютеры', 'IP, диапазон, подсеть или список через запятую. До 512 адресов.\nПример: 192.168.22.1-192.168.22.32, 192.168.201.39', parent=self.window)
        if value is None:
            return
        try:
            addresses = parse_addresses(value)
        except Exception as error:
            messagebox.showerror('Диапазон IP', str(error), parent=self.window)
            return
        self.set_busy(True)
        self.summary.set('Поиск SSH-серверов: ' + str(len(addresses)) + ' адресов; без команд и паролей…')
        threading.Thread(target=self.scan_worker, args=(addresses,), daemon=True).start()

    def scan_worker(self, addresses):
        try:
            with ThreadPoolExecutor(max_workers=16) as pool:
                control = getattr(self, 'shutdown', None)
                options = dict(control=control) if control else {}
                rows = list(pool.map(lambda ip: probe_address(ip, **options), addresses))
            self.events.put(('range_found', [row for row in rows if row['ok']]))
        except Exception as error:
            self.events.put(('error', str(error)))

    def range_found(self, rows):
        if not rows:
            self.set_busy(False)
            self.summary.set('В диапазоне доступных SSH-серверов не найдено.')
            return
        known = list(self.catalog.values()) + list(self.trusted.values())
        unknown = [row for row in rows if not any(same_key(row, value) for value in known)]
        if unknown:
            details = '\n'.join(row['ip'] + '\n' + row['fingerprint'] for row in unknown)
            if not self.trust_dialog(details):
                self.set_busy(False)
                self.summary.set('Поиск отменён до отправки пароля.')
                return
        password = self.get_password()
        if not password:
            self.set_busy(False)
            return
        self.summary.set('Проверка имён и версии Astra через SSH; команды питания не отправляются…')
        threading.Thread(target=self.inspect_worker, args=(rows, password), daemon=True).start()
        password = None

    def inspect_worker(self, rows, password):
        results = []
        try:
            for row in rows:
                control = getattr(self, 'shutdown', None)
                options = dict(control=control) if control else {}
                if control:
                    control.check()
                result = inspect_address(row, password, **options)
                results.append(result)
                self.events.put(('scan_progress', 'Проверено SSH-узлов: ' + str(len(results)) + ' из ' + str(len(rows))))
                if result.get('stop'):
                    break
            self.events.put(('range_inspected', results))
        except Exception as error:
            self.events.put(('error', str(error).replace(password, '[СКРЫТО]')))
        finally:
            password = None

    def range_results(self, rows):
        self.set_busy(False)
        self.last_results = rows
        counts = {}
        for row in rows:
            if row['ok']:
                counts[row['name']] = counts.get(row['name'], 0) + 1
        candidates = []
        for row in rows:
            if not row['ok']:
                continue
            if counts[row['name']] > 1 or classify_key(row, self.trusted, self.catalog) == 'changed':
                row.update(ok=False, message='Повторное имя или изменённый ключ; добавление заблокировано')
            else:
                candidates.append(row)
        if not candidates:
            self.summary.set('Новых подходящих ПК не найдено. Подробности: «Результаты».')
            return
        dialog = tk.Toplevel(self.window)
        dialog.title('Найденные компьютеры — выбрать и добавить')
        dialog.geometry('820x520')
        dialog.transient(self.window)
        frame = ttk.Frame(dialog, padding=14)
        frame.pack(fill='both', expand=True)
        selected = set()
        tree = ttk.Treeview(frame, columns=('pick', 'name', 'ip', 'mode'), show='headings')
        for key, label, width in [('pick', 'Выбор', 55), ('name', 'Реальное имя', 180), ('ip', 'IP', 170), ('mode', 'Адресация', 300)]:
            tree.heading(key, text=label)
            tree.column(key, width=width)
        for row in candidates:
            tree.insert('', 'end', iid=row['name'], values=('☐', row['name'], row['ip'], 'DNS / DHCP' if row['mode'] == 'dns' else 'Постоянный IP (DNS не подтверждён)'))
        tree.pack(fill='both', expand=True)
        def toggle(event):
            name = tree.identify_row(event.y)
            if name:
                if name in selected:
                    selected.remove(name)
                else:
                    selected.add(name)
                values = list(tree.item(name, 'values'))
                values[0] = '☑' if name in selected else '☐'
                tree.item(name, values=values)
        tree.bind('<Button-1>', toggle)
        ttk.Label(frame, text='Выбранные записи добавятся в класс; существующие записи с тем же именем обновятся.').pack(anchor='w', pady=8)
        rooms = sorted(self.rooms) or ['Найденные']
        destination = tk.StringVar(value=self.room.get() if self.room.get() in rooms else rooms[0])
        ttk.Combobox(frame, textvariable=destination, values=rooms, state='readonly', width=40).pack(anchor='w', pady=5)
        def add():
            if not selected:
                return
            try:
                hosts = [host for host in self.hosts if host.name not in selected]
                new_trust = dict(self.trusted)
                for row in candidates:
                    if row['name'] in selected:
                        hosts.append(Host(row['name'], row['ip'], destination.get(), row['mode']))
                        new_trust[row['name']] = {key: row[key] for key in ('type', 'key', 'fingerprint', 'name')}
                new_rooms = list(self.rooms)
                if destination.get() not in new_rooms:
                    new_rooms.append(destination.get())
                save_inventory(self.inventory_file, new_rooms, hosts)
                atomic_json(self.trust_file, new_trust)
                self.hosts, self.rooms, self.trusted = hosts, new_rooms, new_trust
                self.selected.clear()
                self.refresh()
                self.summary.set('Добавлено/обновлено записей: ' + str(len(selected)))
                dialog.destroy()
            except Exception as error:
                messagebox.showerror('Добавление', str(error), parent=dialog)
        bar = ttk.Frame(frame)
        bar.pack(fill='x', pady=8)
        def all_rows():
            selected.update(row['name'] for row in candidates)
            for name in selected:
                values = list(tree.item(name, 'values'))
                values[0] = '☑'
                tree.item(name, values=values)
        ttk.Button(bar, text='Выбрать все', command=all_rows).pack(side='left')
        ttk.Button(bar, text='Добавить выбранные', command=add).pack(side='left', padx=8)
        ttk.Button(bar, text='Отмена', command=dialog.destroy).pack(side='right')
        dialog.grab_set()
        self.window.wait_window(dialog)

    def set_busy(self, value):
        self.busy = value
        active = bool(getattr(getattr(self, 'operations', None), 'active', {}))
        for control in self.controls:
            blocked = value or (active and control in self.inventory_controls)
            control.configure(state='disabled' if blocked else 'normal')
        self.room_box.configure(state='disabled' if value else 'readonly')
        self.delay_box.configure(state='disabled' if value else 'readonly')
        if value:
            self.progress.configure(mode='indeterminate', value=0, maximum=100)
            self.progress.start(12)
        elif not active:
            self.progress.stop()

    def begin(self, action, job=None):
        hosts = [h for h in self.visible() if h.name in self.selected]
        if not hosts:
            messagebox.showinfo('Выберите компьютеры', 'Поставьте отметки в столбце «Выбор».', parent=self.window)
            return
        if job and job.get('targets') and any(h.name not in job['targets'] for h in hosts):
            messagebox.showerror('Выбор ПК изменился', 'Подготовьте запуск файла заново для текущего выбора ПК.', parent=self.window)
            return
        minutes = int(self.delay.get())
        try:
            operation = self.operations.start(action, hosts, job)
        except ValueError as error:
            messagebox.showinfo('Компьютеры заняты', str(error), parent=self.window)
            return
        if action == 'distribute':
            operation['controls'] = {host.name: OperationControl(parent=self.shutdown, reason='Раздача отменена пользователем') for host in hosts}
        elif action == 'command':
            operation['controls'] = {host.name: CommandControl(parent=self.shutdown) for host in hosts}
        self.preparing_operation = operation['id']
        self.set_busy(True)
        self.summary.set('Проверка SSH без пароля…')
        events = OperationEvents(self.events, operation['id'])
        threading.Thread(target=self.discover, args=(hosts, action, minutes, events, self.shutdown), daemon=True).start()

    def finish_operation(self, identifier):
        self.operations.finish(identifier)
        if self.preparing_operation == identifier:
            self.preparing_operation = None
            self.busy = False
        self.set_busy(self.busy)
        if self.operations.active:
            self.update_activity()

    def update_activity(self):
        active = self.operations.active
        if not active:
            return
        count = len(self.operations.owners)
        self.summary.set('Активных операций: ' + str(len(active)) + ' • Занято ПК: ' + str(count)
                         + '. Можно работать с другими ПК; «Выбрать все» выбирает свободные.')
        states = [state for op in active.values() for state in op['progress'].values()]
        if states and all(op['action'] == 'distribute' and op['state'] == 'running' for op in active.values()):
            self.progress.stop()
            self.progress.configure(mode='determinate', maximum=100, value=sum(x['percent'] for x in states) / len(states))
        elif str(self.progress['mode']) != 'indeterminate':
            self.progress.stop()
            self.progress.configure(mode='indeterminate', maximum=100, value=0)
            self.progress.start(12)

    def discover(self, hosts, action, minutes, events=None, control=None):
        events = events or self.events
        try:
            options = dict(control=control) if control else {}
            with ThreadPoolExecutor(max_workers=6) as pool:
                rows = list(pool.map(lambda host: probe(host, **options), hosts))
            events.put(('discovered', (hosts, action, minutes, rows)))
        except Exception as error:
            events.put(('error', str(error)))

    def discovered(self, hosts, action, minutes, rows, operation_id=None):
        operation = self.operations.active.get(operation_id) if operation_id else None
        job = operation['job'] if operation else getattr(self, 'job', {})
        def finish():
            if operation_id:
                self.finish_operation(operation_id)
            else:
                self.set_busy(False)
        permitted = []
        fresh = []
        initial_results = []
        host_map = {h.name: h for h in hosts}
        for row in rows:
            if not row['ok']:
                self.statuses[row['name']] = (row['message'], True)
                initial_results.append(dict(name=row['name'], ip=row['ip'], ok=False, message=row['message']))
                continue
            state = classify_key(row, self.trusted, self.catalog)
            if state == 'changed':
                message = 'SSH-ключ изменился; подключение заблокировано'
                self.statuses[row['name']] = (message, True)
                initial_results.append(dict(name=row['name'], ip=row['ip'], ok=False, message=message))
                continue
            self.last_ips[row['name']] = row['ip']
            self.statuses[row['name']] = ('SSH доступен', False)
            permitted.append(row)
            if state == 'new':
                fresh.append(row)
        if operation_id:
            operation['results'].extend(initial_results)
            for result in initial_results:
                self.operations.release(operation_id, result['name'])
        self.refresh()
        if action == 'scan':
            finish()
            self.summary.set('Проверка завершена. SSH доступен: ' + str(len(permitted)) + ' из ' + str(len(rows)) + '. Команды питания не отправлялись.')
            return
        if not permitted:
            finish()
            self.summary.set('Нет доступных компьютеров с подходящими SSH-ключами. Команды не отправлялись.')
            return
        if fresh:
            details = '\n'.join(r['name'] + '  ' + r['ip'] + '\n' + r['fingerprint'] for r in fresh)
            answer = self.trust_dialog(details)
            if not answer:
                finish()
                self.summary.set('Отменено. Пароль и команды питания не отправлялись.')
                return
            for row in fresh:
                self.trusted[row['name']] = {k: row[k] for k in ('type', 'key', 'fingerprint', 'name')}
            atomic_json(self.trust_file, self.trusted)
        names = ', '.join(row['name'] for row in permitted)
        verb = {'off': 'Выключить', 'reboot': 'Перезагрузить', 'cancel': 'Отменить запланированное выключение / перезагрузку на', 'distribute': 'Раздать файлы на', 'command': 'Выполнить команду на'}[action]
        text = verb + ' ' + str(len(permitted)) + (' компьютерах?' if action == 'cancel' else ' компьютеров?') + '\n\n' + names
        if action in ('off', 'reboot'):
            text += ('\n\nНЕМЕДЛЕННО, без возможности отмены после выполнения.' if minutes == 0 else '\n\nЧерез ' + str(minutes) + ' мин. после отправки каждому ПК.')
            text += ' Несохранённые данные будут потеряны.'
        if action == 'distribute':
            text += '\n\nФайлы: ' + ', '.join(Path(value).name for value in job['files']) + '\nПапка на ученических ПК: ' + job['destination'] + '\n~ — домашняя папка user. При совпадении имени будет вопрос о перезаписи. Автоматического запуска нет.'
        if action == 'command':
            text += '\n\n' + ('ПРАВА ROOT (sudo)' if job['sudo'] else 'Права локального user') + '\nРабочая папка: ' + job['cwd'] + '\n' + job['script'][:2000]
        if action == 'distribute':
            text += '\nФайлы раздаются всем выбранным ПК параллельно. После передачи проверяется SHA-256.'
        if action == 'command' and job.get('targets'):
            text += '\n\nПроверка SHA-256 и запуск файлов:\n' + '\n'.join(row['name'] + ': ' + job['targets'][row['name']]['expected_file']['path'] for row in permitted)
        if initial_results:
            text += '\n\nНедоступные или заблокированные ПК пропущены: ' + str(len(initial_results)) + '.'
        if not messagebox.askokcancel('Подтверждение команды учителя', text, icon='warning', default='cancel', parent=self.window):
            finish()
            self.summary.set('Отменено. Команды питания не отправлялись.')
            return
        password = self.get_password()
        if not password:
            finish()
            self.summary.set('Отменено. Команды питания не отправлялись.')
            return
        if '\n' in password or '\r' in password:
            finish()
            messagebox.showerror('Пароль', 'Пароль не должен содержать перевод строки.', parent=self.window)
            return
        self.summary.set('Передача файлов: подключение…' if action == 'distribute' else 'Выполнение: подключение…')
        events = OperationEvents(self.events, operation_id) if operation_id else self.events
        control = getattr(self, 'shutdown', None)
        if operation:
            operation['state'] = 'running'
            self.preparing_operation = None
            self.selected.difference_update(h.name for h in hosts)
            self.set_busy(False)
            self.refresh()
            self.update_activity()
        threading.Thread(target=self.send, args=(host_map, permitted, password, action, minutes, initial_results, job, events, control, operation.get('controls') if operation else None), daemon=True).start()
        password = None

    def trust_dialog(self, details):
        dialog = tk.Toplevel(self.window)
        dialog.title('Первое подключение: SSH-ключи')
        dialog.geometry('790x520')
        dialog.transient(self.window)
        result = [False]
        frame = ttk.Frame(dialog, padding=15)
        frame.pack(fill='both', expand=True)
        ttk.Label(frame, text='Сверьте компьютеры и отпечатки перед вводом пароля.', font=('Segoe UI', 11, 'bold')).pack(anchor='w')
        ttk.Label(frame, text='Каталог собран в школьной сети. Независимая сверка новых ключей не выполнялась.\nЕсли есть сомнение, отмените. Пароль ещё никуда не отправлен.', wraplength=750).pack(anchor='w', pady=10)
        text = tk.Text(frame, wrap='none', height=17, font=('Consolas', 10))
        text.insert('1.0', details)
        text.configure(state='disabled')
        text.pack(fill='both', expand=True)
        bar = ttk.Frame(frame)
        bar.pack(fill='x', pady=(12, 0))
        def accept():
            result[0] = True
            dialog.destroy()
        ttk.Button(bar, text='Доверять этим компьютерам', command=accept).pack(side='left')
        cancel = ttk.Button(bar, text='Отмена', command=dialog.destroy)
        cancel.pack(side='right')
        dialog.bind('<Escape>', lambda event: dialog.destroy())
        dialog.grab_set()
        cancel.focus_set()
        self.window.wait_window(dialog)
        return result[0]

    def distribute_files(self, host_map, rows, password, job, events=None, control=None, host_controls=None):
        events = events or self.events
        host_controls = host_controls or {}
        # Prepare each source once; every selected PC gets an independent SFTP session.
        total = sum(Path(path).stat().st_size for path in job['files'])
        done = 0
        last_prepare = 0
        def preparation(count):
            nonlocal done, last_prepare
            if control:
                control.check()
            if rows and all(name in host_controls and host_controls[name].cancelled.is_set() for name in (pin['name'] for pin in rows)):
                raise OperationCancelled('Раздача отменена пользователем')
            done += count
            now = time.monotonic()
            if now - last_prepare >= .2:
                events.put(('scan_progress', 'Подготовка файлов для всех ПК: SHA-256 ' + str(round(done * 100 / total) if total else 100) + '%'))
                last_prepare = now
        events.put(('scan_progress', 'Подготовка файлов для одновременной раздачи…'))
        try:
            prepared = {str(Path(path).resolve()): prepare_transfer(path, progress=preparation) for path in job['files']}
        except OperationCancelled as error:
            results = [dict(name=pin['name'], ip=pin['ip'], action='upload', ok=False, cancelled=True, files=[], message=str(error)) for pin in rows]
            for result in results:
                events.put(('result', result))
            return results
        batch = job.get('batch') or uuid.uuid4().hex
        gate = TransferAccessGate(control)
        events.put(('distribution_started', [pin['name'] for pin in rows]))
        def worker(pin):
            name = pin['name']
            worker_control = host_controls.get(name, control)
            last_update = 0
            last_phase = None
            def progress(value):
                nonlocal last_update, last_phase
                now = time.monotonic()
                stage = (value['phase'], value.get('file', ''))
                if stage != last_phase or now - last_update >= .2:
                    events.put(('distribution_progress', dict(value, name=name)))
                    last_update, last_phase = now, stage
            def on_conflict(path):
                answer = queue.Queue(maxsize=1)
                events.put(('overwrite', (name, path, answer)))
                while True:
                    if worker_control:
                        worker_control.check()
                    try:
                        return answer.get(timeout=.2)
                    except queue.Empty:
                        continue
            try:
                result = transfer_files(host_map[name], pin, password, job['files'], batch,
                                        destination=job['destination'], progress=progress,
                                        on_conflict=on_conflict, access_gate=gate, prepared=prepared, **(dict(control=worker_control) if worker_control else {}))
            except Exception as error:
                result = dict(name=name, ip=pin['ip'], action='upload', ok=False,
                              message=str(error).replace(password, '[СКРЫТО]'))
                if isinstance(error, OperationCancelled):
                    result['cancelled'] = True
            result['requested_destination'] = job['destination']
            events.put(('result', result))
            return result
        if not rows:
            return []
        # Every selected PC gets its own worker; no worker waits for another file.
        with ThreadPoolExecutor(max_workers=len(rows)) as pool:
            pending = {pool.submit(worker, pin): pin['name'] for pin in rows}
            results = {pending[future]: future.result() for future in as_completed(pending)}
        return [results[pin['name']] for pin in rows]

    def update_distribution_summary(self):
        state = self.distribution_state
        complete = sum(item['complete'] for item in state.values())
        percent = sum(item['percent'] for item in state.values()) / len(state) if state else 100
        self.progress.stop()
        self.progress.configure(mode='determinate', maximum=100, value=percent)
        self.summary.set('Раздача файлов: завершено ПК ' + str(complete) + '/' + str(len(state))
                         + '. Прогресс каждого ПК — в столбце «Состояние / результат».')

    def send_commands(self, host_map, rows, password, job, events, control=None, host_controls=None):
        gate = TransferAccessGate(control)
        host_controls = host_controls or {}
        events.put(('command_waiting', [pin['name'] for pin in rows]))
        def worker(pin):
            name = pin['name']
            target = job.get('targets', {}).get(name, {})
            worker_control = host_controls.get(name, control)
            options = dict(control=worker_control) if worker_control else {}
            try:
                result = execute_command(host_map[name], pin, password, job['script'], job['sudo'], job['timeout'],
                                         cwd=target.get('cwd', job.get('cwd', '~')), expected_file=target.get('expected_file'),
                                         progress=lambda value: events.put(('command_progress', dict(value, name=name))),
                                         access_gate=gate, **options)
            except Exception as error:
                result = dict(name=name, ip=pin['ip'], action='command', ok=False,
                              message=str(error).replace(password, '[СКРЫТО]'))
            if result.get('stop'):
                gate.stopped.set()
            events.put(('result', result))
            return result
        if not rows:
            return []
        with ThreadPoolExecutor(max_workers=len(rows)) as pool:
            pending = {pool.submit(worker, pin): pin['name'] for pin in rows}
            results = {pending[future]: future.result() for future in as_completed(pending)}
        return [results[pin['name']] for pin in rows]

    def send(self, host_map, rows, password, action, minutes, initial_results, job=None, events=None, control=None, host_controls=None):
        events = events or self.events
        options = dict(control=control) if control else {}
        results = list(initial_results)
        try:
            if action == 'distribute':
                results.extend(self.distribute_files(host_map, rows, password, job, events, control, host_controls))
            if action == 'command':
                results.extend(self.send_commands(host_map, rows, password, job, events, control, host_controls))
            for index, pin in enumerate([] if action in ('distribute', 'command') else rows):
                if control:
                    control.check()
                label = pin['name'] + ' • ПК ' + str(index + 1) + '/' + str(len(rows))
                events.put(('operation_status', label + ': подключение и проверка имени/ОС…'))
                result = execute(host_map[pin['name']], pin, password, action, minutes, **options)
                results.append(result)
                events.put(('result', result))
                if result.get('stop'):
                    for skipped in rows[index + 1:]:
                        result = dict(name=skipped['name'], ip=skipped['ip'], ok=False, message='Пропущен после ошибки доступа; повторных попыток нет')
                        results.append(result)
                        events.put(('result', result))
                    break
            report = self.data / 'reports' / (datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:6] + '.json')
            atomic_json(report, results)
            events.put(('finished', (results, str(report))))
        except Exception as error:
            events.put(('error', str(error).replace(password, '[СКРЫТО]')))
        finally:
            password = None

    def handle_event(self, kind, value, operation_id=None):
        operation = self.operations.active.get(operation_id) if operation_id else None
        if operation_id and operation is None:
            if kind == 'overwrite':
                value[2].put(False)
            return
        if operation_id and kind == 'distribution_progress':
            target_control = operation.get('controls', {}).get(value['name'])
            if target_control and target_control.cancelled.is_set():
                return
        if operation_id and kind in ('result', 'command_progress', 'distribution_progress'):
            if self.operations.owners.get(value['name']) != operation_id:
                return  # Late events cannot replace a newer operation's row.
        progress_state = operation['progress'] if operation else getattr(self, 'distribution_state', {})
        def show_progress():
            if operation_id:
                self.update_activity()
            else:
                self.update_distribution_summary()
        if kind == 'discovered':
            self.discovered(*value, operation_id=operation_id) if operation_id else self.discovered(*value)
        elif kind == 'result':
            if value.get('action') in ('upload', 'download') and value['name'] in progress_state:
                progress_state[value['name']] = dict(percent=100, complete=True)
                show_progress()
            if value.get('action') in ('upload', 'download') and value.get('files'):
                self.last_upload_directory = value['requested_destination']
            if operation_id:
                operation['results'].append(value)
                self.operations.release(operation_id, value['name'])
            self.statuses[value['name']] = (value['message'], not value['ok'])
            self.refresh()
            if operation_id:
                self.update_activity()
        elif kind == 'finished':
            results, report = value
            self.last_results = results
            good = sum(r['ok'] for r in results)
            cancelled = sum(bool(r.get('cancelled')) for r in results)
            if operation_id:
                self.finish_operation(operation_id)
            else:
                self.set_busy(False)
            self.summary.set('Готово: успешно ' + str(good) + ', отменено ' + str(cancelled) + ', ошибок/пропусков ' + str(len(results) - good - cancelled) + '. Отчёт: ' + report)
            if operation_id and self.operations.active:
                self.update_activity()
        elif kind == 'command_waiting':
            for name in value:
                target_control = operation.get('controls', {}).get(name) if operation else None
                stopping = isinstance(target_control, CommandControl) and target_control.stop_requested.is_set()
                self.statuses[name] = ('Остановка команды…' if stopping else 'Ожидает выполнения команды', False)
            self.refresh()
        elif kind == 'command_progress':
            name = value['name']
            target_control = operation.get('controls', {}).get(name) if operation else None
            if isinstance(target_control, CommandControl) and target_control.stop_requested.is_set() and value['phase'] != 'Остановка команды':
                return
            output = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', value['output'])
            lines = output.replace('\r', '\n').splitlines()
            latest = next((line.strip() for line in reversed(lines) if line.strip()), '')
            label = value['phase'] + ' • ' + str(value['elapsed']) + ' с'
            if latest:
                label += ' • ' + latest[:180]
            else:
                label += ' • ожидание вывода'
            self.statuses[name] = (label, False)
            if self.table.exists(name):
                self.table.set(name, 'status', label)
            self.summary.set(name + ': ' + label)
        elif kind == 'distribution_started':
            states = {name: dict(percent=0, complete=False) for name in value}
            if operation:
                operation['progress'] = states
            else:
                self.distribution_state = states
            for name in value:
                target_control = operation.get('controls', {}).get(name) if operation else None
                self.statuses[name] = ('Отмена раздачи…' if target_control and target_control.cancelled.is_set() else 'Ожидает подключения для раздачи', False)
            self.refresh()
            show_progress()
        elif kind == 'distribution_progress':
            name = value['name']
            state = progress_state.get(name)
            if state is not None and not state['complete']:
                percent = min(99, value['done'] * 100 / value['total']) if value['total'] else 0
                state['percent'] = percent
                label = value['phase'] + ' ' + value.get('file', '') + ' • ' + str(int(percent)) + '%'
                self.statuses[name] = (label, False)
                if self.table.exists(name):
                    self.table.set(name, 'status', label)
                show_progress()
        elif kind == 'range_found':
            self.range_found(value)
        elif kind == 'range_inspected':
            self.range_results(value)
        elif kind == 'overwrite':
            name, path, answer = value
            target_control = operation.get('controls', {}).get(name) if operation else None
            if target_control and target_control.cancelled.is_set():
                answer.put(False)
                return
            try:
                overwrite = messagebox.askyesno('Перезаписать файл?', name + '\nФайл уже существует:\n' + path + '\n\nЗаменить его выбранным файлом учителя? При ответе «Нет» этот файл будет пропущен.', default='no', icon='warning', parent=self.window)
            except Exception:
                answer.put(False)
                raise
            answer.put(overwrite)
        elif kind == 'operation_status':
            self.progress.stop()
            self.progress.configure(mode='indeterminate', maximum=100, value=0)
            self.progress.start(12)
            self.summary.set(value)
        elif kind == 'scan_progress':
            self.summary.set(value)
        elif kind == 'error':
            if operation_id:
                self.finish_operation(operation_id)
            else:
                self.set_busy(False)
            self.summary.set('Операция завершилась с ошибкой; проверьте результаты перед повтором.')
            messagebox.showerror('Ошибка', value, parent=self.window)

    def poll(self):
        if getattr(self, 'closing', False):
            return
        if getattr(self, 'asking_exit', False):
            self.window.after(100, self.poll)
            return
        while not getattr(self, 'closing', False):
            identifier = None
            try:
                kind, value = self.events.get_nowait()
                if kind == 'operation_event':
                    identifier, kind, value = value
                self.handle_event(kind, value, identifier)
            except queue.Empty:
                break
            except Exception as error:
                if getattr(self, 'closing', False):
                    return
                if identifier:
                    self.finish_operation(identifier)
                else:
                    self.set_busy(False)
                messagebox.showerror('Ошибка', str(error), parent=self.window)
        if not getattr(self, 'closing', False):
            self.window.after(100, self.poll)

    def close(self):
        if getattr(self, 'closing', False) or getattr(self, 'asking_exit', False):
            return
        active = getattr(getattr(self, 'operations', None), 'active', {})
        if active or self.busy:
            titles = {'distribute': 'Раздача файлов', 'command': 'Выполнение команды',
                      'off': 'Выключение', 'reboot': 'Перезагрузка', 'cancel': 'Отмена выключения', 'scan': 'Проверка связи'}
            details = []
            for operation in active.values():
                names = sorted(operation['pending'])
                details.append(titles.get(operation['action'], operation['action']) + ': ' + str(len(names))
                               + ' ПК — ' + ', '.join(names[:8]) + ('…' if len(names) > 8 else ''))
            if self.busy and not getattr(self, 'preparing_operation', None):
                details.append('Поиск или подготовка компьютеров ещё выполняется')
            text = 'Ещё есть незавершённые операции:\n\n' + '\n'.join(details)
            text += ('\n\nЗакрыть CM? Передачи будут прерваны. Уже отправленные команды установки '
                     'или питания могут продолжить работу на ПК. Отчёт незавершённых операций '
                     'будет сохранён; проверьте ПК перед повтором.')
            self.asking_exit = True
            try:
                answer = messagebox.askyesno('Закрыть программу с незавершёнными операциями?', text,
                                            icon='warning', default='no', parent=self.window)
            finally:
                self.asking_exit = False
            if not answer:
                return
        self.closing = True
        # Save uncertainty explicitly; a later result must never be invented as success.
        for operation in list(active.values()):
            results = list(operation['results'])
            results.extend(dict(name=name, action=operation['action'], ok=False,
                                message='CM закрыт пользователем; результат не подтверждён. Проверьте ПК перед повтором')
                           for name in sorted(operation['pending']))
            try:
                atomic_json(self.data / 'reports' / (datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-interrupted-' + operation['id'] + '.json'), results)
            except OSError as error:
                messagebox.showwarning('Отчёт не сохранён', str(error), parent=self.window)
        control = getattr(self, 'shutdown', None)
        if control:
            control.cancel()
        self.window.destroy()


def main():
    window = tk.Tk()
    try:
        Manager(window)
    except Exception as error:
        messagebox.showerror('CM Astra не запущен', str(error), parent=window)
        window.destroy()
        return
    window.mainloop()


if __name__ == '__main__':
    main()
