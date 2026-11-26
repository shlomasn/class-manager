"""Class Manager for a Windows teacher computer controlling Astra over SSH."""
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, replace
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

from cm_core import Host, atomic_json, classify_key, execute, load_hosts, probe, hostname, room_name, validate_hosts, load_inventory, load_profile_inventory, save_inventory, transfer_files, execute_command, parse_addresses, probe_address, inspect_address, same_key, remote_path, DEFAULT_INBOX, file_launch_spec, prepare_transfer, TransferAccessGate, OperationControl, OperationCancelled, CommandControl, synchronize_time, load_csv, dns_domain, detect_local_networks, automatic_scan_plan, mac_address, wake_plan, collect_mac, wake_computer
import credential_store
import cm_ui

ROOT = Path(__file__).resolve().parent


def password_for(passwords, name):
    return passwords[name] if isinstance(passwords, dict) else passwords


def hide_passwords(text, passwords):
    values = passwords.values() if isinstance(passwords, dict) else [passwords]
    for value in sorted(set(v for v in values if v), key=len, reverse=True):
        text = text.replace(value, '[СКРЫТО]')
    return text


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
        # A PC can be reused before the rest of its original batch finishes.
        if self.owners.get(name) == identifier:
            del self.owners[name]

    def finish(self, identifier):
        operation = self.active.get(identifier)
        if operation:
            for name in list(operation['pending']):
                self.release(identifier, name)
            del self.active[identifier]


# Workers send events through the queue. Only the Tk thread applies them to widgets.
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
        self.ui_file = self.data / 'ui.json'
        self.theme = tk.StringVar(value=cm_ui.load_theme(self.ui_file))
        self.host_file = self.data / 'computers.json'
        self.trust_file = self.data / 'trusted-keys.json'
        self.inventory_file = self.data / 'inventory.json'
        legacy_network = self.data / 'network.json'
        if self.inventory_file.exists():
            self.rooms, self.hosts, self.domain = load_profile_inventory(
                self.inventory_file, legacy_network=legacy_network)
        else:
            self.hosts = load_hosts(self.host_file if self.host_file.exists() else ROOT / 'computers.json')
            self.rooms = sorted({host.room for host in self.hosts})
            self.domain = self.hosts[0].domain if self.hosts else ''
            if legacy_network.exists():
                self.domain = dns_domain(json.loads(legacy_network.read_text(encoding='utf-8')).get('domain', ''))
                if self.host_file.exists():
                    self.hosts = [replace(host, domain=self.domain) if not host.domain else host for host in self.hosts]
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
        self.sort_column = None
        self.sort_reverse = False
        self.statuses = {}
        self.busy = False
        self.events = queue.Queue()
        self.controls = []
        window.title('CM Astra 2.7 — управление школьными компьютерами')
        window.geometry(str(min(1220, window.winfo_screenwidth() - 60)) + 'x' + str(min(800, window.winfo_screenheight() - 90)))
        window.minsize(850, 600)
        window.protocol('WM_DELETE_WINDOW', self.close)
        self.build()
        self.refresh()
        cm_ui.color_widgets(self.window, self.palette)
        self.window.after(100, self.poll)

    def button(self, frame, text, command, style=None):
        widget = ttk.Button(frame, text=text, command=command, style=style or 'TButton')
        widget.pack(side='left', padx=(0, 7))
        self.controls.append(widget)
        return widget

    def menu_action(self, menu, text, command, inventory=False):
        menu.add_command(label=text, command=command)
        self.menu_controls.append((menu, menu.index('end'), inventory))

    def build(self):
        self.palette = cm_ui.PALETTES[self.theme.get()]
        cm_ui.configure_styles(self.window, self.theme.get())
        self.menu_controls = []
        self.window.grid_rowconfigure(0, weight=1)
        self.window.grid_columnconfigure(1, weight=1)
        sidebar = self.sidebar = ttk.Frame(self.window, style='Surface.TFrame', padding=(14, 20), width=184)
        sidebar.grid(row=0, column=0, sticky='nsew')
        sidebar.grid_propagate(False)
        sidebar.grid_columnconfigure(0, weight=1)
        sidebar.grid_rowconfigure(2, weight=1)
        brand = ttk.Frame(sidebar, style='Surface.TFrame')
        brand.grid(row=0, column=0, sticky='ew', pady=(0, 22))
        ttk.Label(brand, text='CM', style='Brand.TLabel').pack(side='left', padx=(0, 10))
        ttk.Label(brand, text='Управление\nклассом', style='Surface.TLabel').pack(side='left')
        ttk.Label(sidebar, text='КАБИНЕТЫ', style='Side.TLabel').grid(row=1, column=0, sticky='w', pady=(0, 8))
        room_frame = ttk.Frame(sidebar, style='Surface.TFrame')
        room_frame.grid(row=2, column=0, sticky='nsew')
        self.room = tk.StringVar(value='Все кабинеты')
        self.room_list = ttk.Treeview(room_frame, show='tree', selectmode='browse', style='Rooms.Treeview', height=5)
        self.room_list.column('#0', width=142, minwidth=80, stretch=True)
        self.room_list.pack(side='left', fill='both', expand=True)
        room_scroll = ttk.Scrollbar(room_frame, orient='vertical', command=self.room_list.yview)
        room_scroll.pack(side='right', fill='y')
        self.room_list.configure(yscrollcommand=room_scroll.set)
        self.room_list.bind('<<TreeviewSelect>>', self.room_selected)

        settings = self.settings_button = ttk.Menubutton(sidebar, text='Управление и\nнастройки')
        settings.grid(row=3, column=0, sticky='ew', pady=(15, 10))
        self.controls.append(settings)
        menu = tk.Menu(settings, tearoff=False)
        settings.configure(menu=menu)
        sidebar.bind('<Configure>', self.fit_sidebar, add='+')
        computers = tk.Menu(menu, tearoff=False)
        menu.add_cascade(label='Компьютеры', menu=computers)
        for text, command in [('Добавить ПК…', self.add_host), ('Изменить выбранную строку…', self.edit_host),
                              ('Удалить отмеченные ПК…', self.remove_hosts), ('Перенести отмеченные в кабинет…', self.move_hosts),
                              ('Импорт списка .csv / .lst / .json…', self.import_list), ('Получить MAC выбранных ПК…', lambda: self.begin('collect_mac')), ('Найти ПК в моей сети…', self.scan_local_network), ('Найти ПК по IP…', self.scan_range)]:
            self.menu_action(computers, text, command, inventory=True)
        rooms = tk.Menu(menu, tearoff=False)
        menu.add_cascade(label='Кабинеты', menu=rooms)
        self.menu_action(rooms, 'Добавить кабинет…', self.add_room, inventory=True)
        self.menu_action(rooms, 'Удалить текущий кабинет…', self.remove_room, inventory=True)
        menu.add_separator()
        profile = tk.Menu(menu, tearoff=False)
        menu.add_cascade(label='Данные школы', menu=profile)
        self.menu_action(profile, 'Сохранить копию…', self.export_profile, inventory=True)
        self.menu_action(profile, 'Восстановить из копии…', self.restore_profile, inventory=True)
        self.menu_action(menu, 'Настройки сети…', self.network_settings, inventory=True)
        self.menu_action(menu, 'Сохранить / изменить пароль…', self.save_password)
        self.menu_action(menu, 'Забыть сохранённый пароль', self.forget_password)
        menu.add_separator()
        self.menu_action(menu, 'Результаты последней операции', self.show_results)
        self.credential_status = tk.StringVar(value='Пароль хранится в системном хранилище')
        ttk.Label(sidebar, textvariable=self.credential_status, style='Side.TLabel', wraplength=150).grid(row=4, column=0, sticky='w')
        appearance = ttk.Frame(sidebar, style='Surface.TFrame')
        appearance.grid(row=5, column=0, sticky='ew', pady=(14, 0))
        ttk.Label(appearance, text='ОФОРМЛЕНИЕ', style='Side.TLabel').pack(anchor='w', pady=(0, 4))
        for text, value in [('Светлая', 'light'), ('Тёмная', 'dark')]:
            ttk.Radiobutton(appearance, text=text, value=value, variable=self.theme, command=self.apply_theme).pack(anchor='w')
        ttk.Label(sidebar, text='CM 2.7 · Windows / Astra', style='Side.TLabel').grid(row=6, column=0, sticky='w', pady=(14, 0))

        main = ttk.Frame(self.window, padding=(22, 18))
        main.grid(row=0, column=1, sticky='nsew')
        main.grid_columnconfigure(0, weight=1)
        main.grid_rowconfigure(4, weight=1, minsize=85)
        header = ttk.Frame(main)
        header.grid(row=0, column=0, sticky='ew', pady=(0, 8))
        self.room_title = tk.StringVar(value='Все кабинеты')
        header.grid_columnconfigure(0, weight=1)
        ttk.Label(header, textvariable=self.room_title, style='Title.TLabel').grid(row=0, column=0, sticky='ew', padx=(0, 12))
        check = ttk.Button(header, text='Проверить связь', command=lambda: self.begin('scan'))
        check.grid(row=0, column=1, sticky='e')
        self.controls.append(check)
        self.time_sync_button = ttk.Button(header, text='Синхронизировать время', command=self.sync_time_dialog)
        self.time_sync_button.grid(row=0, column=2, sticky='e', padx=(8, 0))
        self.controls.append(self.time_sync_button)
        self.overview = tk.StringVar(value='Компьютеры учеников')
        ttk.Label(main, textvariable=self.overview, style='Muted.TLabel').grid(row=1, column=0, sticky='w', pady=(0, 12))

        toolbar = ttk.Frame(main, style='Surface.TFrame', padding=(10, 9))
        toolbar.grid(row=2, column=0, sticky='ew', pady=(0, 8))
        self.button(toolbar, 'Раздать файлы', self.distribute_dialog, 'Primary.TButton')
        self.button(toolbar, 'Команда…', self.command_dialog)
        self.button(toolbar, 'Запустить файл…', self.launch_dialog)
        power = ttk.Menubutton(toolbar, text='Питание')
        power.pack(side='left')
        self.controls.append(power)
        power_menu = tk.Menu(power, tearoff=False)
        power.configure(menu=power_menu)
        self.menu_action(power_menu, 'Включить выбранные ПК…', lambda: self.begin('wake'))
        self.menu_action(power_menu, 'Выключить…', lambda: self.begin('off'))
        self.menu_action(power_menu, 'Перезагрузить…', lambda: self.begin('reboot'))
        self.menu_action(power_menu, 'Отменить запланированное выключение / перезагрузку…', lambda: self.begin('cancel'))
        stopping = ttk.Menubutton(toolbar, text='Остановить')
        stopping.pack(side='right')
        self.controls.append(stopping)
        stop_menu = tk.Menu(stopping, tearoff=False)
        stopping.configure(menu=stop_menu)
        self.menu_action(stop_menu, 'Отменить раздачу выбранным', self.cancel_distribution)
        self.menu_action(stop_menu, 'Остановить команды выбранным…', self.stop_commands)
        self.menu_action(stop_menu, 'Остановить ожидание включения выбранным…', self.stop_wake_wait)

        selection = ttk.Frame(main)
        selection.grid(row=3, column=0, sticky='ew', pady=(0, 8))
        self.counter = tk.StringVar()
        ttk.Label(selection, textvariable=self.counter, style='Section.TLabel').pack(side='left', padx=(0, 12))
        self.button(selection, 'Выбрать свободные', self.select_visible)
        self.button(selection, 'Снять выбор', self.clear_selection)
        ttk.Label(selection, text='Питание через', style='Muted.TLabel').pack(side='left', padx=(8, 5))
        self.delay = tk.StringVar(value='1')
        self.delay_box = ttk.Combobox(selection, textvariable=self.delay, state='readonly', values=('0', '1', '2', '5', '10', '15', '30'), width=3)
        self.delay_box.pack(side='left')
        ttk.Label(selection, text='мин.', style='Muted.TLabel').pack(side='left', padx=(4, 0))

        table_frame = ttk.Frame(main, style='Surface.TFrame')
        table_frame.grid(row=4, column=0, sticky='nsew')
        table_frame.grid_columnconfigure(0, weight=1)
        table_frame.grid_rowconfigure(0, weight=1)
        columns = ('check', 'name', 'ip', 'status', 'stop')
        self.table = ttk.Treeview(table_frame, columns=columns, show='headings', selectmode='browse', height=8)
        self.column_titles = {}
        for name, title, width, minimum in [('check', 'Выбор', 52, 48), ('name', 'Компьютер', 135, 112),
                                            ('ip', 'IP-адрес', 133, 115), ('status', 'Состояние / результат', 370, 155),
                                            ('stop', 'Действие', 90, 85)]:
            self.column_titles[name] = title
            self.table.heading(name, text=title, command=lambda column=name: self.sort_table(column))
            self.table.column(name, width=width, minwidth=minimum, stretch=name == 'status')
        self.table.tag_configure('chosen', background=self.palette['tint'])
        self.table.tag_configure('error', foreground=self.palette['error'])
        self.table.grid(row=0, column=0, sticky='nsew')
        scrollbar = ttk.Scrollbar(table_frame, orient='vertical', command=self.table.yview)
        scrollbar.grid(row=0, column=1, sticky='ns')
        horizontal = ttk.Scrollbar(table_frame, orient='horizontal', command=self.table.xview)
        horizontal.grid(row=1, column=0, sticky='ew')
        self.table.configure(yscrollcommand=scrollbar.set, xscrollcommand=horizontal.set)
        self.table.bind('<Button-1>', self.clicked)
        self.table.bind('<space>', self.key_toggle)
        self.table.bind('<Return>', lambda event: self.stop_for_host(self.table.focus()))

        tasks = ttk.Frame(main)
        tasks.grid(row=5, column=0, sticky='ew', pady=(12, 8))
        task_header = ttk.Frame(tasks)
        task_header.pack(fill='x', pady=(0, 5))
        self.task_caption = tk.StringVar(value='Текущие операции')
        ttk.Label(task_header, textvariable=self.task_caption, style='Section.TLabel').pack(side='left')
        results = self.button(task_header, 'Результаты', self.show_results)
        results.pack_configure(side='right', padx=0)
        task_body = ttk.Frame(tasks, style='Surface.TFrame')
        task_body.pack(fill='x')
        self.task_table = ttk.Treeview(task_body, columns=('action', 'hosts', 'state'), show='headings', height=2, selectmode='browse')
        for name, title, width in [('action', 'Операция', 200), ('hosts', 'Компьютеры', 140), ('state', 'Ход выполнения', 260)]:
            self.task_table.heading(name, text=title)
            self.task_table.column(name, width=width, minwidth=100, stretch=True)
        self.task_table.pack(side='left', fill='x', expand=True)
        task_scroll = ttk.Scrollbar(task_body, orient='vertical', command=self.task_table.yview)
        task_scroll.pack(side='right', fill='y')
        self.task_table.configure(yscrollcommand=task_scroll.set)
        self.task_table.bind('<Double-1>', lambda event: self.show_operation())
        self.task_table.bind('<Return>', lambda event: self.show_operation())

        footer = ttk.Frame(main)
        footer.grid(row=6, column=0, sticky='ew')
        self.progress = ttk.Progressbar(footer, mode='indeterminate')
        self.progress.pack(fill='x', pady=(0, 6))
        self.summary = tk.StringVar(value='Отметьте нужные ПК. Для остановки можно отметить и занятые компьютеры.')
        self.summary_label = ttk.Label(footer, textvariable=self.summary, style='Muted.TLabel', wraplength=730)
        self.summary_label.pack(fill='x', anchor='w')
        main.bind('<Configure>', lambda event: self.summary_label.configure(wraplength=max(240, event.width - 44)))

    def apply_theme(self):
        value = self.theme.get()
        if value not in cm_ui.PALETTES:
            return
        self.palette = cm_ui.PALETTES[value]
        cm_ui.configure_styles(self.window, value)
        cm_ui.color_widgets(self.window, self.palette)
        self.table.tag_configure('chosen', background=self.palette['tint'])
        self.table.tag_configure('error', foreground=self.palette['error'])
        try:
            atomic_json(self.ui_file, dict(version=1, theme=value))
        except OSError as error:
            messagebox.showerror('Оформление', 'Тема применена, но сохранить выбор не удалось: ' + str(error), parent=self.window)

    def refresh_rooms(self):
        entries = cm_ui.room_entries(self.rooms, self.hosts)
        self.room_ids = {'room-' + str(index): name for index, (name, count) in enumerate(entries)}
        expected = set(self.room_ids)
        for identifier in self.room_list.get_children():
            if identifier not in expected:
                self.room_list.delete(identifier)
        for index, (name, count) in enumerate(entries):
            identifier = 'room-' + str(index)
            text = ('Все кабинеты' if index == 0 else 'Кабинет ' + name) + '  ·  ' + str(count)
            if self.room_list.exists(identifier):
                self.room_list.item(identifier, text=text)
            else:
                self.room_list.insert('', 'end', iid=identifier, text=text)
            if name == self.room.get():
                self.room_list.selection_set(identifier)

    def room_selected(self, event=None):
        if self.busy:
            return
        selection = self.room_list.selection()
        name = self.room_ids.get(selection[0]) if selection else None
        if name is not None and name != self.room.get():
            self.room.set(name)
            self.change_room()

    def refresh_dashboard(self):
        if not hasattr(self, 'task_table'):
            return
        visible = self.visible()
        occupied = self.operations.owners
        busy = sum(host.name in occupied for host in visible)
        selected = sum(host.name in self.selected for host in visible)
        errors = sum(self.statuses.get(host.name, ('', False))[1] for host in visible if host.name not in occupied)
        self.room_title.set(self.room.get() if self.room.get() == 'Все кабинеты' else 'Кабинет ' + self.room.get())
        self.overview.set(str(len(visible)) + ' ПК в списке  ·  Занято: ' + str(busy) + '  ·  Требуют внимания: ' + str(errors))
        self.counter.set('Выбрано: ' + str(selected))
        rows = cm_ui.operation_entries(self.operations.active)
        self.task_caption.set('Текущие операции · ' + str(len(rows)))
        if not rows:
            rows = [('idle', ('Нет активных операций', '', 'Можно начать новую задачу'))]
        cm_ui.sync_rows(self.task_table, [(identifier, values, ()) for identifier, values in rows])

    def show_operation(self):
        selection = self.task_table.selection()
        operation = self.operations.active.get(selection[0]) if selection else None
        if not operation:
            return
        dialog = tk.Toplevel(self.window)
        dialog.title('Ход операции')
        dialog.geometry('800x460')
        frame = ttk.Frame(dialog, padding=16)
        frame.pack(fill='both', expand=True)
        text = tk.Text(frame, wrap='word')
        text.pack(side='left', fill='both', expand=True)
        scroll = ttk.Scrollbar(frame, command=text.yview)
        scroll.pack(side='right', fill='y')
        text.configure(yscrollcommand=scroll.set)
        def update():
            if not dialog.winfo_exists():
                return
            data = dict(state='Выполняется' if operation['id'] in self.operations.active else 'Завершена',
                        pending={name: self.statuses.get(name, ('Ожидание', False))[0] for name in sorted(operation['pending'])},
                        results=operation['results'])
            position = text.yview()[0]
            text.configure(state='normal')
            text.delete('1.0', 'end')
            lines = ['Статус: ' + data['state'], '', 'Компьютеры в работе:']
            lines.extend(name + ': ' + status for name, status in data['pending'].items())
            if not data['pending']:
                lines.append('Нет')
            lines.extend(['', 'Завершившиеся компьютеры:', '', cm_ui.format_results(data['results'])])
            text.insert('1.0', '\n'.join(lines))
            text.configure(state='disabled')
            text.yview_moveto(position)
            dialog.after(500, update)
        update()

    def stop_for_host(self, name):
        if self.busy or not name:
            return
        operation = self.operations.active.get(self.operations.owners.get(name), {})
        action = operation.get('action')
        if action not in ('distribute', 'command', 'wake'):
            return
        previous = set(self.selected)
        control = operation.get('controls', {}).get(name)
        self.selected = {name}
        try:
            (self.cancel_distribution if action == 'distribute' else self.stop_wake_wait if action == 'wake' else self.stop_commands)()
        finally:
            self.selected = previous
            if control and (control.cancelled.is_set() or isinstance(control, CommandControl) and control.stop_requested.is_set()):
                self.selected.discard(name)
            self.refresh()
        return 'break'

    def visible(self):
        room = self.room.get()
        return [h for h in self.hosts if room == 'Все кабинеты' or h.room == room]

    def refresh(self):
        if hasattr(self, 'room_list'):
            self.refresh_rooms()
        else:
            self.room_box['values'] = ['Все кабинеты'] + sorted(self.rooms)
        rows = []
        for host in self.visible():
            chosen = host.name in self.selected
            status, failed = self.statuses.get(host.name, ('Не проверен', False))
            tags = (['chosen'] if chosen else []) + (['error'] if failed else [])
            operation = self.operations.active.get(self.operations.owners.get(host.name), {})
            stop = 'Остановить' if operation.get('action') in ('distribute', 'command', 'wake') else ''
            rows.append((host.name, ('☑' if chosen else '☐', host.name,
                         self.last_ips.get(host.name, 'Авто (DNS)' if host.mode == 'dns' else host.ip), status, stop), tags))
        # Sort the view only. Selection and operation ownership use stable host names.
        cm_ui.sync_rows(self.table, cm_ui.sorted_computer_rows(rows, self.sort_column, self.sort_reverse))
        self.counter.set('Выбрано: ' + str(len(self.selected)))
        self.refresh_dashboard()

    def fit_sidebar(self, event=None):
        # Include theme padding and the menu arrow in the measured request, also at high DPI.
        width = max(184, self.settings_button.winfo_reqwidth() + 28)
        if self.sidebar.cget('width') != width:
            self.sidebar.configure(width=width)
        self.window.minsize(850 + width - 184, 600)

    def sort_table(self, column):
        self.sort_reverse = not self.sort_reverse if self.sort_column == column else False
        self.sort_column = column
        for name, title in self.column_titles.items():
            arrow = (' ▼' if self.sort_reverse else ' ▲') if name == column else ''
            self.table.heading(name, text=title + arrow)
        self.refresh()

    def change_room(self):
        # A hidden selection must never shut down computers from another classroom.
        self.selected.clear()
        self.refresh()

    def clicked(self, event):
        if self.busy:
            return
        column = self.table.identify_column(event.x)
        name = self.table.identify_row(event.y)
        if column == '#5':
            return self.stop_for_host(name)
        if column != '#1':
            return
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
        if name in owners and name not in self.selected and operation.get('action') not in ('distribute', 'command', 'wake'):
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

    def export_profile(self):
        path = filedialog.asksaveasfilename(parent=self.window, title='Копия данных школы',
            initialfile='CM-school-backup.json', defaultextension='.json', filetypes=[('JSON CM', '*.json')])
        if not path:
            return
        try:
            save_inventory(path, self.rooms, self.hosts, domain=self.domain)
        except Exception as error:
            messagebox.showerror('Копия не сохранена', str(error), parent=self.window)
            return
        self.summary.set('Копия данных школы сохранена: ' + Path(path).name)

    def restore_profile(self):
        path = filedialog.askopenfilename(parent=self.window, title='Восстановить данные школы',
            filetypes=[('JSON CM', '*.json')])
        if not path:
            return
        try:
            rooms, hosts, domain = load_profile_inventory(path)
            preview = f'Файл: {Path(path).name}\nКабинетов: {len(rooms)}\nКомпьютеров: {len(hosts)}\nДомен: {domain or "не задан"}'
            if not messagebox.askokcancel('Заменить данные школы?', preview +
                    '\n\nТекущие кабинеты, список ПК и домен будут заменены.',
                    default='cancel', parent=self.window):
                return
            save_inventory(self.inventory_file, rooms, hosts, domain=domain)
        except Exception as error:
            messagebox.showerror('Данные не восстановлены', str(error), parent=self.window)
            return
        self.rooms, self.hosts, self.domain = rooms, hosts, domain
        self.last_results = []
        self.last_upload_directory = None
        self.last_ips.clear()
        self.selected.clear()
        self.statuses.clear()
        self.room.set('Все кабинеты')
        self.refresh()
        self.summary.set('Данные школы восстановлены: ' + Path(path).name)

    def import_list(self):
        path = filedialog.askopenfilename(parent=self.window, title='Список компьютеров CM', filetypes=[('Списки CM', '*.lst *.json *.csv'), ('Все файлы', '*.*')])
        if not path:
            return
        try:
            if Path(path).suffix.lower() == '.csv':
                self.import_csv(path)
                return
            raw = json.loads(Path(path).read_text(encoding='utf-8')) if Path(path).suffix.lower() == '.json' else None
            if isinstance(raw, dict) and raw.get('version') == 2:
                rooms, rows = load_inventory(path)
            else:
                rows = load_hosts(path)
                rooms = sorted({host.room for host in rows})
            save_inventory(self.inventory_file, rooms, rows, domain=self.domain)
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

    def import_csv(self, path):
        incoming = load_csv(path)
        current = {host.name: host for host in self.hosts}
        for host in incoming:
            old = current.get(host.name)
            current[host.name] = replace(old, room=host.room, username=host.username,
                credential_mode='host') if old else replace(host, domain=self.domain)
        hosts = list(current.values())
        rooms = sorted(set(self.rooms) | {host.room for host in incoming})
        # Validate the entire merge before asking for confirmation or saving.
        validate_hosts([asdict(host) for host in hosts])
        preview = '\n'.join(host.room + ' / ' + host.name + ' / ' + host.username for host in incoming)
        if not messagebox.askokcancel('Импорт CSV', 'Добавить или обновить ПК: ' + str(len(incoming)) +
                '\n' + preview + '\n\nПароли не импортируются. Для этих ПК используются индивидуальные учётные записи. Остальные ПК сохраняются.',
                default='cancel', parent=self.window):
            return
        save_inventory(self.inventory_file, rooms, hosts, domain=self.domain)
        self.rooms, self.hosts = rooms, hosts
        self.selected.clear()
        self.last_ips.clear()
        self.statuses.clear()
        self.room.set('Все кабинеты')
        self.refresh()
        self.summary.set('CSV импортирован. Пароли задаются в карточках ПК или при подключении.')

    def network_settings(self):
        value = simpledialog.askstring('Настройки сети',
            'Домен школы (необязательно). Пусто — использовать введённое имя.\n'
            'DNS-сервер берётся из настроек ОС учителя.\n'
            'Если имя не находится, задайте IP или используйте поиск по диапазону.\n'
            'Изменение применяется к домену всех ПК, SSH-ключи сохраняются:',
            initialvalue=self.domain, parent=self.window)
        if value is None:
            return
        try:
            domain = dns_domain(value)
            hosts = [replace(host, domain=domain) for host in self.hosts]
            save_inventory(self.inventory_file, self.rooms, hosts, domain=domain)
            self.hosts = hosts
            self.domain = domain
            self.last_ips.clear()
            self.statuses.clear()
            self.refresh()
        except Exception as error:
            messagebox.showerror('Настройки сети', str(error), parent=self.window)

    def persist(self):
        save_inventory(self.inventory_file, self.rooms, self.hosts, domain=self.domain)

    def add_room(self):
        value = simpledialog.askstring('Добавить класс', 'Название класса, например 208:', parent=self.window)
        if value is None:
            return
        try:
            name = room_name(value)
            if name in self.rooms:
                raise ValueError('Такой класс уже есть')
            save_inventory(self.inventory_file, self.rooms + [name], self.hosts, domain=self.domain)
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
            save_inventory(self.inventory_file, rooms, hosts, domain=self.domain)
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
        username = tk.StringVar(value=original.username if original else 'user')
        password = tk.StringVar()
        credentials = tk.StringVar(value='Общий user' if not original or original.credential_mode == 'shared' else 'Для этого ПК')
        erase = tk.BooleanVar(value=False)
        mac = tk.StringVar(value=original.mac if original else '')
        broadcast = tk.StringVar(value=original.wol_broadcast if original else '')
        for row, (label, widget) in enumerate([
            ('Имя ПК:', ttk.Entry(frame, textvariable=name, width=42)),
            ('Класс:', ttk.Combobox(frame, textvariable=room, values=sorted(self.rooms), state='readonly', width=39)),
            ('Адресация:', ttk.Combobox(frame, textvariable=mode, values=('По имени (DHCP / DNS)', 'Постоянный IP'), state='readonly', width=39)),
            ('Постоянный IP:', ttk.Entry(frame, textvariable=ip, width=42)),
            ('Логин SSH:', ttk.Entry(frame, textvariable=username, width=42)),
            ('Пароль:', ttk.Entry(frame, textvariable=password, show='*', width=42)),
            ('Учётная запись:', ttk.Combobox(frame, textvariable=credentials, values=('Общий user', 'Для этого ПК'), state='readonly', width=39)),
            ('MAC адаптера:', ttk.Entry(frame, textvariable=mac, width=42)),
            ('Адрес рассылки WoL:', ttk.Entry(frame, textvariable=broadcast, width=42))]):
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
        ttk.Label(frame, text='Имя разрешается через настройки сети учителя.\nMAC-адаптер: ' + ((original.mac_interface or 'не указан') + ' · ' + {'wifi': 'Wi-Fi (включение не гарантируется)', 'ethernet': 'Ethernet', 'manual': 'введён вручную', '': 'тип не определён'}.get(original.mac_type, '') if original else 'не определён')).grid(row=9, columnspan=2, sticky='w', pady=12)
        ttk.Checkbutton(frame, text='Удалить индивидуальный сохранённый пароль', variable=erase).grid(row=10, columnspan=2, sticky='w')
        ttk.Label(frame, text='Пустой пароль сохраняет прежний. Новый пароль хранится только\nв системном хранилище; для другого логина выберите «Для этого ПК».').grid(row=11, columnspan=2, sticky='w', pady=8)
        def save():
            try:
                dns = mode.get().startswith('По имени')
                candidate = dict(name=hostname(name.get()), room=room.get(), ip='' if dns else ip.get(), mode='dns' if dns else 'fixed', username=username.get(), credential_mode='host' if credentials.get() == 'Для этого ПК' or password.get() else 'shared', domain=original.domain if original else self.domain, mac=mac.get(), wol_broadcast=broadcast.get(),
                    mac_type=original.mac_type if original and mac.get() and mac_address(mac.get()) == original.mac else ('manual' if mac.get() else ''),
                    mac_interface=original.mac_interface if original and mac.get() and mac_address(mac.get()) == original.mac else '')
                rows = [asdict(h) for h in self.hosts if original is None or h.name != original.name]
                rows.append(candidate)
                hosts = validate_hosts(rows)
                updated = next(h for h in hosts if h.name == candidate['name'])
                if password.get() and erase.get():
                    raise ValueError('Выберите замену или удаление пароля')
                if password.get():
                    credential_store.save(password.get(), updated.username, updated.name)
                elif erase.get():
                    credential_store.delete(updated.username, updated.name)
                save_inventory(self.inventory_file, self.rooms, hosts, domain=self.domain)
                password.set('')
                self.hosts = hosts
                self.selected.clear()
                self.last_ips.clear()
                self.statuses.clear()
                self.refresh()
                dialog.destroy()
            except Exception as error:
                messagebox.showerror('Компьютер не сохранён', str(error), parent=dialog)
        bar = ttk.Frame(frame)
        bar.grid(row=12, columnspan=2, sticky='ew')
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
            save_inventory(self.inventory_file, self.rooms, hosts, domain=self.domain)
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

    def get_host_passwords(self, hosts):
        if all(host.credential_mode == 'shared' for host in hosts):
            return self.get_password()
        passwords = {}
        shared = None
        try:
            for host in hosts:
                if host.credential_mode == 'shared':
                    if shared is None:
                        shared = self.get_password()
                    secret = shared
                else:
                    secret = credential_store.load(host.username, host.name)
                    if not secret:
                        secret = simpledialog.askstring('Пароль для ПК', host.name + ' — логин ' + host.username +
                            '\nПароль для этой операции (сохранить можно в карточке ПК):', show='*', parent=self.window)
                if not secret:
                    return None
                credential_store.validate(secret)
                passwords[host.name] = secret
            return passwords
        except Exception:
            messagebox.showerror('Учётные записи', 'Не удалось получить пароль из системного хранилища. Проверьте связку ключей и карточку ПК.', parent=self.window)
            return None

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
                hosts = [replace(h, room=destination.get() if h.name in targets else h.room) for h in self.hosts]
                save_inventory(self.inventory_file, self.rooms, hosts, domain=self.domain)
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
            '~/ — домашняя папка выбранного пользователя; можно указать /полный/путь.\n'
            'Недостающие папки будут созданы. При совпадении имени будет вопрос о перезаписи.\n'
            'Передача не запускает файлы. Права записи — у выбранного пользователя.',
            initialvalue=DEFAULT_INBOX, parent=self.window)
        if destination is None:
            return
        try:
            destination = remote_path(destination)
        except ValueError as error:
            messagebox.showerror('Папка назначения', str(error), parent=self.window)
            return
        self.begin('distribute', dict(files=list(files), batch=batch, destination=destination))

    def sync_time_dialog(self):
        self.begin('time_sync')

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
        ttk.Label(frame, text='Рабочая папка НА УЧЕНИЧЕСКИХ ПК (~ — домашняя папка выбранного пользователя):').pack(anchor='w')
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
        dialog.title('Результаты последней операции')
        dialog.geometry('850x550')
        frame = ttk.Frame(dialog, padding=16)
        frame.pack(fill='both', expand=True)
        tabs = ttk.Notebook(frame)
        tabs.pack(fill='both', expand=True)
        for label, content in [('Результаты', cm_ui.format_results(self.last_results)),
                               ('JSON', json.dumps(self.last_results, ensure_ascii=False, indent=2))]:
            page = ttk.Frame(tabs)
            tabs.add(page, text=label)
            text = tk.Text(page, wrap='word')
            text.pack(side='left', fill='both', expand=True)
            scroll = ttk.Scrollbar(page, command=text.yview)
            scroll.pack(side='right', fill='y')
            text.configure(yscrollcommand=scroll.set)
            text.insert('1.0', content)
            text.configure(state='disabled')
        cm_ui.color_widgets(dialog, self.palette)

    def scan_local_network(self):
        self.set_busy(True)
        self.summary.set('Определение локальных IPv4-сетей компьютера учителя…')
        threading.Thread(target=self.detect_network_worker, daemon=True).start()

    def detect_network_worker(self):
        try:
            self.events.put(('local_networks', detect_local_networks()))
        except Exception as error:
            self.events.put(('error', str(error)))

    def choose_local_network(self, rows):
        self.set_busy(False)
        if not rows:
            messagebox.showinfo('Локальные сети', 'Активных локальных IPv4-сетей не найдено. Проверьте подключение или используйте ручной диапазон IP.', parent=self.window)
            return
        dialog = tk.Toplevel(self.window)
        dialog.title('Найти ПК в моей сети')
        dialog.transient(self.window)
        frame = ttk.Frame(dialog, padding=18)
        frame.pack(fill='both', expand=True)
        ttk.Label(frame, text='Выберите школьное подключение. VPN и виртуальные интерфейсы тоже могут быть в списке.').pack(anchor='w')
        labels = [row['interface'] + ' · IP ' + row['ip'] + ' · сеть ' + row['network'] for row in rows]
        choice = ttk.Combobox(frame, values=labels, state='readonly', width=85)
        choice.pack(fill='x', pady=10)
        choice.current(0)
        info = tk.StringVar()
        ttk.Label(frame, textvariable=info, wraplength=640).pack(anchor='w', pady=6)
        part = tk.StringVar()
        part_row = ttk.Frame(frame)
        part_row.pack(fill='x', pady=6)
        ttk.Label(part_row, text='Часть большой сети:').pack(side='left')
        number = ttk.Spinbox(part_row, from_=1, to=1, textvariable=part, width=8)
        number.pack(side='left', padx=8)
        preview = tk.StringVar()
        ttk.Label(frame, textvariable=preview, wraplength=640).pack(anchor='w', pady=8)
        own_ips = {row['ip'] for row in rows}
        def show_plan(*args):
            try:
                plan = automatic_scan_plan(rows[choice.current()], int(part.get()), own_ips)
                preview.set('Будет проверено: ' + plan['network'] + ', адресов: ' + str(len(plan['addresses'])) + '. Компьютер учителя исключён.')
            except (ValueError, IndexError):
                preview.set('Выберите допустимый номер части сети.')
        def selected(event=None):
            plan = automatic_scan_plan(rows[choice.current()], exclude=own_ips)
            number.configure(to=plan['parts'], state='normal' if plan['partial'] else 'disabled')
            info.set('Подсеть большая: будет проверена только выбранная часть /24. По умолчанию — часть с компьютером учителя. Для остальных частей меняйте номер и повторяйте поиск.' if plan['partial'] else 'Будет проверена вся выбранная подсеть (до 512 адресов).')
            part.set(str(plan['part']))
        part.trace_add('write', show_plan)
        choice.bind('<<ComboboxSelected>>', selected)
        selected()
        ttk.Label(frame, text='Поиск обнаруживает доступные SSH-серверы. Затем проверяются имя и Astra;\nвы сами выбираете, какие ПК добавить. Без SSH компьютер не появится в результатах.').pack(anchor='w', pady=8)
        bar = ttk.Frame(frame)
        bar.pack(fill='x', pady=8)
        def search():
            try:
                plan = automatic_scan_plan(rows[choice.current()], int(part.get()), own_ips)
                if not plan['addresses']:
                    raise ValueError('В этой сети нет других адресов для поиска')
            except (ValueError, IndexError) as error:
                messagebox.showerror('Локальная сеть', str(error), parent=dialog)
                return
            dialog.destroy()
            self.start_scan(plan['addresses'])
        ttk.Button(bar, text='Найти компьютеры', command=search).pack(side='left')
        ttk.Button(bar, text='Отмена', command=dialog.destroy).pack(side='right')
        cm_ui.color_widgets(dialog, self.palette)
        dialog.grab_set()
        self.window.wait_window(dialog)

    def start_scan(self, addresses):
        self.set_busy(True)
        self.summary.set('Поиск SSH-серверов: ' + str(len(addresses)) + ' адресов; без команд и паролей…')
        threading.Thread(target=self.scan_worker, args=(addresses,), daemon=True).start()

    def scan_range(self):
        value = simpledialog.askstring('Найти компьютеры', 'IP, диапазон, подсеть или список через запятую. До 512 адресов.\nПример: 192.168.22.1-192.168.22.32, 192.168.201.39', parent=self.window)
        if value is None:
            return
        try:
            addresses = parse_addresses(value)
        except Exception as error:
            messagebox.showerror('Диапазон IP', str(error), parent=self.window)
            return
        self.start_scan(addresses)

    def scan_worker(self, addresses):
        try:
            with ThreadPoolExecutor(max_workers=16) as pool:
                control = getattr(self, 'shutdown', None)
                options = dict(control=control) if control else {}
                pending = [pool.submit(probe_address, ip, **options) for ip in addresses]
                rows = []
                for future in as_completed(pending):
                    if control:
                        control.check()
                    rows.append(future.result())
                    self.events.put(('scan_progress', 'Поиск SSH: проверено ' + str(len(rows)) + ' из ' + str(len(addresses))))
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
        login = simpledialog.askstring('Учётная запись для поиска', 'Логин SSH на найденных ПК:', initialvalue='user', parent=self.window)
        if not login:
            self.set_busy(False)
            return
        try:
            from cm_core import login_name
            login = login_name(login)
        except ValueError as error:
            self.set_busy(False)
            messagebox.showerror('Логин SSH', str(error), parent=self.window)
            return
        password = self.get_password() if login == 'user' else simpledialog.askstring('Пароль для поиска', 'Пароль SSH для ' + login + ':', show='*', parent=self.window)
        if not password:
            self.set_busy(False)
            return
        self.summary.set('Проверка имён и версии Astra через SSH; команды питания не отправляются…')
        threading.Thread(target=self.inspect_worker, args=(rows, password, login), daemon=True).start()
        password = None

    def inspect_worker(self, rows, password, username='user'):
        results = []
        try:
            for row in rows:
                control = getattr(self, 'shutdown', None)
                options = dict(control=control) if control else {}
                if control:
                    control.check()
                result = inspect_address(row, password, username=username, **options)
                result['username'] = username
                results.append(result)
                self.events.put(('scan_progress', 'Проверено SSH-узлов: ' + str(len(results)) + ' из ' + str(len(rows))))
                if result.get('stop'):
                    break
            self.events.put(('range_inspected', results))
        except Exception as error:
            self.events.put(('error', hide_passwords(str(error), password)))
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
                        old = next((h for h in self.hosts if h.name == row['name']), None)
                        hosts.append(replace(old, ip=row['ip'], room=destination.get(), mode='fixed' if self.domain else row['mode']) if old else Host(row['name'], row['ip'], destination.get(), 'fixed' if self.domain else row['mode'], row.get('username', 'user'), 'host', self.domain))
                        new_trust[row['name']] = {key: row[key] for key in ('type', 'key', 'fingerprint', 'name')}
                new_rooms = list(self.rooms)
                if destination.get() not in new_rooms:
                    new_rooms.append(destination.get())
                save_inventory(self.inventory_file, new_rooms, hosts, domain=self.domain)
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
        if hasattr(self, 'room_list'):
            self.room_list.state(['disabled'] if value else ['!disabled'])
        else:
            self.room_box.configure(state='disabled' if value else 'readonly')
        for menu, index, inventory in getattr(self, 'menu_controls', []):
            menu.entryconfigure(index, state='disabled' if value or active and inventory else 'normal')
        self.delay_box.configure(state='disabled' if value else 'readonly')
        if value:
            self.progress.configure(mode='indeterminate', value=0, maximum=100)
            self.progress.start(12)
        elif not active:
            self.progress.stop()

    def stop_wake_wait(self):
        targets = [(op, name) for op in self.operations.active.values() if op['action'] == 'wake'
                   for name in op['pending'] if name in self.selected]
        if not targets:
            return
        if messagebox.askokcancel('Остановить ожидание включения', 'Прекратить проверку выбранных ПК? Уже отправленные пакеты WoL не отменяются.', default='cancel', parent=self.window):
            for op, name in targets:
                op['controls'][name].cancel()
                self.statuses[name] = ('Остановка ожидания включения…', False)
            self.refresh()

    def prepare_wake(self, hosts, events):
        try:
            events.put(('wake_ready', (hosts, detect_local_networks())))
        except Exception as error:
            events.put(('error', str(error)))

    def wake_ready(self, hosts, networks, identifier):
        operation = self.operations.active[identifier]
        try:
            if len({mac_address(host.mac) for host in hosts}) != len(hosts):
                raise ValueError('У выбранных ПК повторяется MAC: проверьте карточки')
            plans = {host.name: wake_plan(host, networks) for host in hosts}
            keys = {host.name: dict(self.trusted.get(host.name) or self.catalog.get(host.name) or {}) for host in hosts}
            missing = [host.name for host in hosts if not keys[host.name]]
            if missing:
                raise ValueError('Сначала получите MAC по SSH на включённых ПК (нужен доверенный ключ): ' + ', '.join(missing))
        except ValueError as error:
            self.finish_operation(identifier)
            messagebox.showerror('Включение не подготовлено', str(error), parent=self.window)
            return
        details = '\n'.join(host.name + (' [Wi-Fi: включение не гарантируется]' if host.mac_type == 'wifi' else '') + ' · ' + plans[host.name]['mac'] + ' → ' + plans[host.name]['broadcast'] + ' (с ' + plans[host.name]['source'] + ')' for host in hosts)
        if not messagebox.askokcancel('Включить выбранные ПК', details + '\n\nОтправить Wake-on-LAN и до 180 секунд проверять появление SSH с доверенным ключом?\nНужны проводная сеть, питание и заранее включённый WoL в BIOS/ОС. Пакет не гарантирует включение. Автоповтора нет.', default='cancel', parent=self.window):
            self.finish_operation(identifier)
            return
        operation['state'] = 'running'
        operation['job'] = dict(plans=plans, keys=keys)
        self.preparing_operation = None
        self.selected.difference_update(host.name for host in hosts)
        self.set_busy(False)
        self.refresh()
        self.update_activity()
        events = OperationEvents(self.events, identifier)
        threading.Thread(target=self.wake_worker, args=(hosts, plans, keys, operation['controls'], events), daemon=True).start()

    def wake_worker(self, hosts, plans, keys, controls, events):
        try:
            def worker(host):
                result = wake_computer(host, plans[host.name], keys[host.name], control=controls[host.name],
                    progress=lambda text: events.put(('wake_progress', dict(name=host.name, text=text))))
                events.put(('result', result))
                return result
            with ThreadPoolExecutor(max_workers=len(hosts)) as pool:
                results = list(pool.map(worker, hosts))
            report = self.data / 'reports' / ('wake-' + uuid.uuid4().hex + '.json')
            atomic_json(report, results)
            events.put(('finished', (results, str(report))))
        except Exception as error:
            events.put(('error', str(error)))

    def send_mac(self, host_map, rows, passwords, events, control):
        gate = TransferAccessGate(control)
        def worker(pin):
            host = host_map[pin['name']]
            result = collect_mac(host, pin, password_for(passwords, host.name), control=control, access_gate=gate)
            events.put(('result', result))
            return result
        with ThreadPoolExecutor(max_workers=len(rows)) as pool:
            return list(pool.map(worker, rows))

    def save_collected_macs(self, results):
        values = {row['name']: row for row in results if row.get('action') == 'collect_mac' and row.get('ok')}
        if not values:
            return ''
        try:
            hosts = [replace(host, mac=values[host.name]['mac'], wol_broadcast=values[host.name]['wol_broadcast'], mac_type=values[host.name].get('mac_type', ''), mac_interface=values[host.name].get('interface', '')) if host.name in values else host for host in self.hosts]
            save_inventory(self.inventory_file, self.rooms, hosts, domain=self.domain)
            self.hosts = hosts
            return ' MAC и адреса рассылки сохранены.'
        except Exception:
            messagebox.showerror('MAC не сохранены', 'MAC получены, но записать список не удалось. Проверьте доступ к файлу настроек и повторите получение MAC.', parent=self.window)
            return ' Внимание: MAC получены, но не сохранены.'

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
        elif action == 'time_sync':
            operation['controls'] = {host.name: OperationControl(parent=self.shutdown) for host in hosts}
        # Reserve hosts before discovery. After confirmation, unrelated free PCs can start another job.
        self.preparing_operation = operation['id']
        self.set_busy(True)
        self.summary.set('Подготовка включения…' if action == 'wake' else 'Проверка SSH без пароля…')
        events = OperationEvents(self.events, operation['id'])
        if action == 'wake':
            operation['controls'] = {host.name: OperationControl(parent=self.shutdown) for host in hosts}
            threading.Thread(target=self.prepare_wake, args=(hosts, events), daemon=True).start()
        else:
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
        # A link check stops after the SSH handshake. It neither authenticates nor records new trust.
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
        verb = {'off': 'Выключить', 'reboot': 'Перезагрузить', 'cancel': 'Отменить запланированное выключение / перезагрузку на', 'distribute': 'Раздать файлы на', 'command': 'Выполнить команду на', 'time_sync': 'Синхронизировать время на', 'collect_mac': 'Получить MAC адаптера подключения на'}[action]
        text = verb + ' ' + str(len(permitted)) + (' компьютерах?' if action == 'cancel' else ' компьютеров?') + '\n\n' + names
        if action == 'time_sync':
            now = datetime.datetime.now().astimezone().strftime('%d.%m.%Y %H:%M:%S %Z (UTC%z)')
            text = 'Синхронизировать время на выбранных ПК (' + str(len(permitted)) + ')?\n\n' + names
            text += ('\n\nИсточник — этот компьютер учителя. Сейчас: ' + now
                     + '\nПеред установкой каждый ПК получит свежее время учителя с учётом задержки связи.'
                       '\nЧасовой пояс, аппаратные часы и настройки NTP не меняются.'
                       '\nПотребуются права sudo. Убедитесь, что часы учителя правильные: время ученических ПК может измениться скачком.')
        if action in ('off', 'reboot'):
            text += ('\n\nНЕМЕДЛЕННО, без возможности отмены после выполнения.' if minutes == 0 else '\n\nЧерез ' + str(minutes) + ' мин. после отправки каждому ПК.')
            text += ' Несохранённые данные будут потеряны.'
        if action == 'distribute':
            text += '\n\nФайлы: ' + ', '.join(Path(value).name for value in job['files']) + '\nПапка на ученических ПК: ' + job['destination'] + '\n~ — домашняя папка выбранного пользователя. При совпадении имени будет вопрос о перезаписи. Автоматического запуска нет.'
        if action == 'command':
            text += '\n\n' + ('ПРАВА ROOT (sudo)' if job['sudo'] else 'Права выбранного пользователя') + '\nРабочая папка: ' + job['cwd'] + '\n' + job['script'][:2000]
        if action == 'distribute':
            text += '\nФайлы раздаются всем выбранным ПК параллельно. После передачи проверяется SHA-256.'
        if action == 'command' and job.get('targets'):
            text += '\n\nПроверка SHA-256 и запуск файлов:\n' + '\n'.join(row['name'] + ': ' + job['targets'][row['name']]['expected_file']['path'] for row in permitted)
        text += '\n\nУчётные записи SSH:\n' + '\n'.join(row['name'] + ': ' + host_map[row['name']].username for row in permitted)
        if initial_results:
            text += '\n\nНедоступные или заблокированные ПК пропущены: ' + str(len(initial_results)) + '.'
        if not messagebox.askokcancel('Подтверждение команды учителя', text, icon='warning', default='cancel', parent=self.window):
            finish()
            self.summary.set('Отменено. Команды питания не отправлялись.')
            return
        password = self.get_host_passwords([host_map[row['name']] for row in permitted])
        if not password:
            finish()
            self.summary.set('Отменено. Команды питания не отправлялись.')
            return
        if isinstance(password, str) and ('\n' in password or '\r' in password):
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
            secret = password_for(password, name)
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
                result = transfer_files(host_map[name], pin, secret, job['files'], batch,
                                        destination=job['destination'], progress=progress,
                                        on_conflict=on_conflict, access_gate=gate, prepared=prepared, **(dict(control=worker_control) if worker_control else {}))
            except Exception as error:
                result = dict(name=name, ip=pin['ip'], action='upload', ok=False,
                              message=hide_passwords(str(error), password))
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
            secret = password_for(password, name)
            target = job.get('targets', {}).get(name, {})
            worker_control = host_controls.get(name, control)
            options = dict(control=worker_control) if worker_control else {}
            try:
                result = execute_command(host_map[name], pin, secret, job['script'], job['sudo'], job['timeout'],
                                         cwd=target.get('cwd', job.get('cwd', '~')), expected_file=target.get('expected_file'),
                                         progress=lambda value: events.put(('command_progress', dict(value, name=name))),
                                         access_gate=gate, **options)
            except Exception as error:
                result = dict(name=name, ip=pin['ip'], action='command', ok=False,
                              message=hide_passwords(str(error), password))
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

    def send_time_sync(self, host_map, rows, password, events, control=None, host_controls=None):
        gate = TransferAccessGate(control)
        host_controls = host_controls or {}
        def worker(pin):
            name = pin['name']
            secret = password_for(password, name)
            worker_control = host_controls.get(name, control)
            try:
                result = synchronize_time(host_map[name], pin, secret,
                                          progress=lambda value: events.put(('command_progress', dict(value, name=name))),
                                          control=worker_control, access_gate=gate)
            except Exception as error:
                result = dict(name=name, ip=pin['ip'], action='time_sync', ok=False, message=hide_passwords(str(error), password))
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
            if action == 'time_sync':
                results.extend(self.send_time_sync(host_map, rows, password, events, control, host_controls))
            if action == 'collect_mac':
                results.extend(self.send_mac(host_map, rows, password, events, control))
            for index, pin in enumerate([] if action in ('distribute', 'command', 'time_sync', 'collect_mac') else rows):
                if control:
                    control.check()
                label = pin['name'] + ' • ПК ' + str(index + 1) + '/' + str(len(rows))
                events.put(('operation_status', label + ': подключение и проверка имени/ОС…'))
                result = execute(host_map[pin['name']], pin, password_for(password, pin['name']), action, minutes, **options)
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
            events.put(('error', hide_passwords(str(error), password)))
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
        if operation_id and kind in ('result', 'command_progress', 'distribution_progress', 'wake_progress'):
            if self.operations.owners.get(value['name']) != operation_id:
                return  # Late events cannot replace a newer operation's row.
        progress_state = operation['progress'] if operation else getattr(self, 'distribution_state', {})
        def show_progress():
            if operation_id:
                self.update_activity()
            else:
                self.update_distribution_summary()
        if kind == 'wake_ready':
            self.wake_ready(*value, operation_id)
        elif kind == 'wake_progress':
            self.statuses[value['name']] = (value['text'], False)
            self.refresh()
        elif kind == 'discovered':
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
            mac_note = self.save_collected_macs(results)
            good = sum(r['ok'] for r in results)
            cancelled = sum(bool(r.get('cancelled')) for r in results)
            if operation_id:
                self.finish_operation(operation_id)
            else:
                self.set_busy(False)
            self.summary.set('Готово: успешно ' + str(good) + ', отменено ' + str(cancelled) + ', ошибок/пропусков ' + str(len(results) - good - cancelled) + '. Отчёт: ' + report + mac_note)
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
                if self.sort_column == 'status':
                    self.refresh()
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
                    if self.sort_column == 'status':
                        self.refresh()
                show_progress()
        elif kind == 'local_networks':
            self.choose_local_network(value)
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
        self.refresh_dashboard()

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
                      'off': 'Выключение', 'reboot': 'Перезагрузка', 'cancel': 'Отмена выключения', 'scan': 'Проверка связи', 'time_sync': 'Синхронизация времени', 'wake': 'Включение WoL', 'collect_mac': 'Получение MAC'}
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
