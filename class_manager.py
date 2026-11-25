"""Class Manager for a Windows teacher computer controlling Astra over SSH."""
from concurrent.futures import ThreadPoolExecutor
import datetime
import json
import os
from pathlib import Path
import queue
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
import uuid

from cm_core import Host, atomic_json, classify_key, execute, load_hosts, probe, hostname, room_name, validate_hosts, load_inventory, save_inventory, transfer_files, execute_command, parse_addresses, probe_address, inspect_address, same_key, remote_path
import credential_store

ROOT = Path(__file__).resolve().parent


def data_directory():
    base = Path(os.environ.get('APPDATA', str(Path.home() / '.local/share')))
    return base / 'CM-Astra'


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
        self.job = {}
        self.last_results = []
        self.last_ips = {}
        self.selected = set()
        self.statuses = {}
        self.busy = False
        self.events = queue.Queue()
        self.controls = []
        window.title('CM Astra 1.3 — управление школьными компьютерами')
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
        ttk.Label(outer, text='Отметьте нужные компьютеры. Команды отправляются через SSH от имени локального user.').pack(anchor='w', pady=(5, 15))
        toolbar = ttk.Frame(outer)
        toolbar.pack(fill='x', pady=(0, 10))
        ttk.Label(toolbar, text='Кабинет:').pack(side='left', padx=(0, 6))
        self.room = tk.StringVar(value='Все кабинеты')
        self.room_box = ttk.Combobox(toolbar, textvariable=self.room, state='readonly', width=17)
        self.room_box.pack(side='left', padx=(0, 15))
        self.room_box.bind('<<ComboboxSelected>>', lambda event: self.change_room())
        self.button(toolbar, 'Выбрать все в списке', self.select_visible)
        self.button(toolbar, 'Снять выбор', self.clear_selection)
        self.button(toolbar, 'Открыть .lst / .json', self.import_list)
        editing = ttk.Frame(outer)
        editing.pack(fill='x', pady=(0, 10))
        self.button(editing, 'Добавить ПК', self.add_host)
        self.button(editing, 'Изменить ПК', self.edit_host)
        self.button(editing, 'Удалить отмеченные', self.remove_hosts)
        groups = ttk.Frame(outer)
        groups.pack(fill='x', pady=(0, 10))
        self.button(groups, 'Добавить класс', self.add_room)
        self.button(groups, 'Удалить класс', self.remove_room)
        self.button(groups, 'Перенести отмеченные в класс…', self.move_hosts)
        self.button(groups, 'Поиск по диапазону IP…', self.scan_range)
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
        self.button(remote, 'Передать файлы…', self.upload_dialog)
        self.button(remote, 'Выполнить команду…', self.command_dialog)
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
        if name in self.selected:
            self.selected.remove(name)
        else:
            self.selected.add(name)
        self.refresh()
        self.table.focus(name)

    def select_visible(self):
        self.selected = {h.name for h in self.visible()}
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

    def upload_dialog(self):
        files = filedialog.askopenfilenames(parent=self.window, title='Программы и файлы для передачи (до 20 файлов)')
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
            'Недостающие папки будут созданы. Существующие файлы не перезаписываются.\n'
            'Передача не запускает файлы. Права записи — у user.',
            initialvalue='~/CM-Inbox/' + batch, parent=self.window)
        if destination is None:
            return
        try:
            destination = remote_path(destination)
        except ValueError as error:
            messagebox.showerror('Папка назначения', str(error), parent=self.window)
            return
        self.begin('upload', dict(files=list(files), batch=batch, destination=destination))

    def command_dialog(self):
        dialog = tk.Toplevel(self.window)
        dialog.title('Команда на выбранных ПК Astra')
        dialog.transient(self.window)
        frame = ttk.Frame(dialog, padding=16)
        frame.pack(fill='both', expand=True)
        ttk.Label(frame, text='Введите команду Bash. Выполнение начнётся после выбора и подтверждения списка ПК.').pack(anchor='w')
        text = tk.Text(frame, width=85, height=10, wrap='word')
        text.insert('1.0', 'hostname; uptime')
        text.pack(fill='both', expand=True, pady=10)
        ttk.Label(frame, text='Рабочая папка НА УЧЕНИЧЕСКИХ ПК (~ — домашняя папка user):').pack(anchor='w')
        cwd = tk.StringVar(value='~')
        ttk.Entry(frame, textvariable=cwd, width=85).pack(fill='x', pady=4)
        if self.last_upload_directory:
            ttk.Button(frame, text='Подставить папку последней передачи',
                       command=lambda: cwd.set(self.last_upload_directory)).pack(anchor='w')
        ttk.Label(frame, text="Пример для переданного скрипта: sh './setup.sh'\n"
                  "Для .deb с sudo: apt-get install -y './package.deb'\n"
                  'Если папки нет, команда не запускается. ~ означает папку user и при sudo.').pack(anchor='w', pady=6)
        sudo = tk.BooleanVar(value=False)
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
                rows = list(pool.map(probe_address, addresses))
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
                result = inspect_address(row, password)
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
        for control in self.controls:
            control.configure(state='disabled' if value else 'normal')
        self.room_box.configure(state='disabled' if value else 'readonly')
        self.delay_box.configure(state='disabled' if value else 'readonly')
        if value:
            self.progress.configure(mode='indeterminate', value=0, maximum=100)
            self.progress.start(12)
        else:
            self.progress.stop()

    def begin(self, action, job=None):
        hosts = [h for h in self.visible() if h.name in self.selected]
        if not hosts:
            messagebox.showinfo('Выберите компьютеры', 'Поставьте отметки в столбце «Выбор».', parent=self.window)
            return
        minutes = int(self.delay.get())
        self.job = job or {}
        self.set_busy(True)
        self.summary.set('Проверка SSH без пароля…')
        threading.Thread(target=self.discover, args=(hosts, action, minutes), daemon=True).start()

    def discover(self, hosts, action, minutes):
        try:
            with ThreadPoolExecutor(max_workers=6) as pool:
                rows = list(pool.map(probe, hosts))
            self.events.put(('discovered', (hosts, action, minutes, rows)))
        except Exception as error:
            self.events.put(('error', str(error)))

    def discovered(self, hosts, action, minutes, rows):
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
        self.refresh()
        if action == 'scan':
            self.set_busy(False)
            self.summary.set('Проверка завершена. SSH доступен: ' + str(len(permitted)) + ' из ' + str(len(rows)) + '. Команды питания не отправлялись.')
            return
        if not permitted:
            self.set_busy(False)
            self.summary.set('Нет доступных компьютеров с подходящими SSH-ключами. Команды не отправлялись.')
            return
        if fresh:
            details = '\n'.join(r['name'] + '  ' + r['ip'] + '\n' + r['fingerprint'] for r in fresh)
            answer = self.trust_dialog(details)
            if not answer:
                self.set_busy(False)
                self.summary.set('Отменено. Пароль и команды питания не отправлялись.')
                return
            for row in fresh:
                self.trusted[row['name']] = {k: row[k] for k in ('type', 'key', 'fingerprint', 'name')}
            atomic_json(self.trust_file, self.trusted)
        names = ', '.join(row['name'] for row in permitted)
        verb = {'off': 'Выключить', 'reboot': 'Перезагрузить', 'cancel': 'Отменить запланированное выключение / перезагрузку на', 'upload': 'Передать файлы на', 'command': 'Выполнить команду на'}[action]
        text = verb + ' ' + str(len(permitted)) + (' компьютерах?' if action == 'cancel' else ' компьютеров?') + '\n\n' + names
        if action in ('off', 'reboot'):
            text += ('\n\nНЕМЕДЛЕННО, без возможности отмены после выполнения.' if minutes == 0 else '\n\nЧерез ' + str(minutes) + ' мин. после отправки каждому ПК.')
            text += ' Несохранённые данные будут потеряны.'
        if action == 'upload':
            text += '\n\nФайлы: ' + ', '.join(Path(value).name for value in self.job['files']) + '\nПапка на ученических ПК: ' + self.job['destination'] + '\n~ — домашняя папка user. Существующие файлы не перезаписываются. Автоматического запуска нет.'
        if action == 'command':
            text += '\n\n' + ('ПРАВА ROOT (sudo)' if self.job['sudo'] else 'Права локального user') + '\nРабочая папка: ' + self.job['cwd'] + '\n' + self.job['script'][:2000]
        if initial_results:
            text += '\n\nНедоступные или заблокированные ПК пропущены: ' + str(len(initial_results)) + '.'
        if not messagebox.askokcancel('Подтверждение команды учителя', text, icon='warning', default='cancel', parent=self.window):
            self.set_busy(False)
            self.summary.set('Отменено. Команды питания не отправлялись.')
            return
        password = self.get_password()
        if not password:
            self.set_busy(False)
            self.summary.set('Отменено. Команды питания не отправлялись.')
            return
        if '\n' in password or '\r' in password:
            self.set_busy(False)
            messagebox.showerror('Пароль', 'Пароль не должен содержать перевод строки.', parent=self.window)
            return
        self.summary.set('Передача файлов: подключение…' if action == 'upload' else 'Выполнение: подключение…')
        threading.Thread(target=self.send, args=(host_map, permitted, password, action, minutes, initial_results, self.job), daemon=True).start()
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

    def send(self, host_map, rows, password, action, minutes, initial_results, job=None):
        results = list(initial_results)
        try:
            for index, pin in enumerate(rows):
                label = pin['name'] + ' • ПК ' + str(index + 1) + '/' + str(len(rows))
                self.events.put(('operation_status', label + ': подключение и проверка имени/ОС…'))
                if action == 'upload':
                    last_update = 0
                    last_phase = None
                    def progress(value):
                        nonlocal last_update, last_phase
                        now = time.monotonic()
                        stage = (value['phase'], value['file'])
                        if stage != last_phase or now - last_update >= 0.1:
                            self.events.put(('upload_progress', dict(value, label=label)))
                            last_update, last_phase = now, stage
                    result = transfer_files(host_map[pin['name']], pin, password, job['files'], job['batch'],
                                            destination=job.get('destination'), progress=progress)
                elif action == 'command':
                    self.events.put(('operation_status', label + ': проверка и выполнение команды; ожидание до ' + str(job['timeout']) + ' с. Папка: ' + job.get('cwd', '~')))
                    result = execute_command(host_map[pin['name']], pin, password, job['script'], job['sudo'], job['timeout'], cwd=job.get('cwd', '~'))
                else:
                    result = execute(host_map[pin['name']], pin, password, action, minutes)
                if action == 'upload':
                    result['requested_destination'] = job.get('destination', '~/CM-Inbox/' + job['batch'])
                results.append(result)
                self.events.put(('result', result))
                if result.get('stop'):
                    for skipped in rows[index + 1:]:
                        result = dict(name=skipped['name'], ip=skipped['ip'], ok=False, message='Пропущен после ошибки доступа; повторных попыток нет')
                        results.append(result)
                        self.events.put(('result', result))
                    break
            report = self.data / 'reports' / (datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:6] + '.json')
            atomic_json(report, results)
            self.events.put(('finished', (results, str(report))))
        except Exception as error:
            self.events.put(('error', str(error).replace(password, '[СКРЫТО]')))
        finally:
            password = None

    def poll(self):
        try:
            while True:
                kind, value = self.events.get_nowait()
                if kind == 'discovered':
                    self.discovered(*value)
                elif kind == 'result':
                    if value.get('action') == 'upload' and value.get('files'):
                        self.last_upload_directory = value['requested_destination']
                    self.statuses[value['name']] = (value['message'], not value['ok'])
                    self.refresh()
                elif kind == 'finished':
                    results, report = value
                    self.last_results = results
                    good = sum(r['ok'] for r in results)
                    self.set_busy(False)
                    self.summary.set('Готово: успешно ' + str(good) + ', ошибок/пропусков ' + str(len(results) - good) + '. Отчёт: ' + report)
                elif kind == 'range_found':
                    self.range_found(value)
                elif kind == 'range_inspected':
                    self.range_results(value)
                elif kind == 'operation_status':
                    self.progress.stop()
                    self.progress.configure(mode='indeterminate', maximum=100, value=0)
                    self.progress.start(12)
                    self.summary.set(value)
                elif kind == 'upload_progress':
                    self.progress.stop()
                    percent = min(100, value['done'] * 100 / value['total']) if value['total'] else (100 if value['phase'] == 'Готово' else 0)
                    if value['phase'] == 'Подключение и проверка имени/ОС':
                        self.progress.configure(mode='indeterminate', maximum=100, value=0)
                        self.progress.start(12)
                    else:
                        self.progress.configure(mode='determinate', maximum=100, value=percent)
                    self.summary.set(value['label'] + ': ' + value['phase'] + ' ' + value['file']
                                     + ' • ' + str(round(percent)) + '% (подготовка + передача + проверка)'
                                     + '\nПапка на ПК: ' + value['destination'])
                elif kind == 'scan_progress':
                    self.summary.set(value)
                elif kind == 'error':
                    self.set_busy(False)
                    self.summary.set('Операция завершилась с ошибкой; проверьте результаты перед повтором.')
                    messagebox.showerror('Ошибка', value, parent=self.window)
        except queue.Empty:
            pass
        except Exception as error:
            self.set_busy(False)
            messagebox.showerror('Ошибка', str(error), parent=self.window)
        self.window.after(100, self.poll)

    def close(self):
        if self.busy:
            messagebox.showinfo('Операция выполняется', 'Дождитесь окончания отправки команд. Запланированное выключение отменяется отдельной кнопкой.', parent=self.window)
            return
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
