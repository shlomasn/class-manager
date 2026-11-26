"""Shared Tk presentation for Windows and Astra. No network or inventory writes."""
from collections import Counter
import ipaddress
import re
from tkinter import font, ttk

PALETTES = {
    'light': dict(background='#f3f6fa', surface='#ffffff', foreground='#1b2940', muted='#64748b',
                  line='#e0e7f0', accent='#245dcf', accent_text='#ffffff', tint='#eaf1ff',
                  success='#257247', error='#a33139', heading='#edf2f8', selected='#dbe8ff',
                  active='#1e52bc', pressed='#1748ad', disabled='#8995a6', disabled_accent='#a7bde6',
                  trough='#e5ecf6', scroll='#bdc9d9'),
    'dark': dict(background='#131b27', surface='#1c2738', foreground='#edf2fa', muted='#a8b8ce',
                 line='#35455c', accent='#8bb3ff', accent_text='#132749', tint='#273c5e',
                 success='#95d8ac', error='#ffadb7', heading='#25344a', selected='#2d4870',
                 active='#a7c4ff', pressed='#729dee', disabled='#708199', disabled_accent='#3e577d',
                 trough='#2c3b52', scroll='#536986')
}
COLORS = PALETTES['light']


def load_theme(path):
    import json
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
        value = data.get('theme') if isinstance(data, dict) else None
    except (OSError, ValueError):
        value = None
    return value if isinstance(value, str) and value in PALETTES else 'light'


def configure_styles(window, theme='light'):
    families = set(font.families(window))
    family = next((name for name in ('Segoe UI', 'DejaVu Sans', 'Arial', 'Helvetica') if name in families), 'TkDefaultFont')
    for name in ('TkDefaultFont', 'TkTextFont', 'TkMenuFont', 'TkHeadingFont', 'TkTooltipFont'):
        font.nametofont(name, root=window).configure(family=family, size=10)
    palette = PALETTES[theme]
    window.configure(background=palette['background'])
    for widget in ('Menu', 'Text', 'Entry', 'Listbox', 'Label', 'Button', 'Checkbutton', 'Radiobutton'):
        window.option_add('*' + widget + '.background', palette['surface'] if widget in ('Menu', 'Text', 'Entry', 'Listbox') else palette['background'])
        window.option_add('*' + widget + '.foreground', palette['foreground'])
    style = ttk.Style(window)
    if style.theme_use() != 'clam' and 'clam' in style.theme_names():
        style.theme_use('clam')
    style.configure('.', font=(family, 10), background=palette['background'], foreground=palette['foreground'])
    style.configure('TFrame', background=palette['background'])
    style.configure('Surface.TFrame', background=palette['surface'])
    style.configure('TLabel', background=palette['background'], foreground=palette['foreground'])
    style.configure('Surface.TLabel', background=palette['surface'])
    style.configure('Muted.TLabel', foreground=palette['muted'])
    style.configure('Side.TLabel', background=palette['surface'], foreground=palette['muted'])
    style.configure('Brand.TLabel', background=palette['accent'], foreground=palette['accent_text'], padding=(10, 8), font=(family, 14, 'bold'))
    style.configure('Title.TLabel', font=(family, 19, 'bold'))
    style.configure('Section.TLabel', font=(family, 10, 'bold'))
    style.configure('TButton', padding=(11, 7), background=palette['surface'], foreground=palette['foreground'], bordercolor=palette['line'], lightcolor=palette['line'], darkcolor=palette['line'], relief='flat')
    style.map('TButton', background=[('pressed', palette['tint']), ('active', palette['tint'])], foreground=[('disabled', palette['disabled'])])
    style.configure('Primary.TButton', background=palette['accent'], foreground=palette['accent_text'], bordercolor=palette['accent'])
    style.map('Primary.TButton', background=[('disabled', palette['disabled_accent']), ('pressed', palette['pressed']), ('active', palette['active'])], foreground=[('disabled', palette['muted']), ('!disabled', palette['accent_text'])])
    style.configure('TMenubutton', background=palette['surface'], foreground=palette['foreground'], arrowcolor=palette['foreground'], padding=(10, 7), bordercolor=palette['line'], lightcolor=palette['line'], darkcolor=palette['line'], relief='flat')
    style.map('TMenubutton', background=[('active', palette['tint'])], foreground=[('disabled', palette['disabled']), ('!disabled', palette['foreground'])])
    row_height = max(32, font.nametofont('TkDefaultFont', root=window).metrics('linespace') + 13)
    style.configure('Treeview', background=palette['surface'], fieldbackground=palette['surface'], foreground=palette['foreground'], rowheight=row_height, borderwidth=0, bordercolor=palette['line'], lightcolor=palette['line'], darkcolor=palette['line'])
    style.configure('Treeview.Heading', background=palette['heading'], foreground=palette['muted'], font=(family, 9), padding=(8, 8), relief='flat')
    style.map('Treeview', background=[('selected', palette['selected'])], foreground=[('selected', palette['foreground'])])
    style.configure('Rooms.Treeview', rowheight=row_height + 6, font=(family, 10))
    style.map('Rooms.Treeview', background=[('selected', palette['tint'])], foreground=[('selected', palette['accent'])])
    style.layout('Rooms.Treeview', [('Treeview.treearea', {'sticky': 'nswe'})])
    style.configure('Horizontal.TProgressbar', background=palette['accent'], troughcolor=palette['trough'], bordercolor=palette['background'], lightcolor=palette['background'], darkcolor=palette['background'], borderwidth=0, thickness=5)
    style.configure('TCombobox', padding=(5, 5), fieldbackground=palette['surface'], background=palette['surface'], foreground=palette['foreground'], arrowcolor=palette['foreground'], bordercolor=palette['line'], lightcolor=palette['line'], darkcolor=palette['line'])
    style.map('TCombobox', fieldbackground=[('readonly', palette['surface']), ('disabled', palette['background'])], foreground=[('readonly', palette['foreground']), ('disabled', palette['disabled'])], selectbackground=[('readonly', palette['selected'])], selectforeground=[('readonly', palette['foreground'])])
    style.configure('TRadiobutton', background=palette['surface'], foreground=palette['foreground'], padding=(0, 4))
    style.map('TRadiobutton', background=[('active', palette['surface'])])
    style.configure('TCheckbutton', background=palette['background'], foreground=palette['foreground'])
    style.configure('TNotebook', background=palette['background'], borderwidth=0)
    style.configure('TNotebook.Tab', background=palette['background'], foreground=palette['muted'], padding=(12, 7))
    style.map('TNotebook.Tab', background=[('selected', palette['surface'])], foreground=[('selected', palette['foreground'])])
    style.configure('TEntry', fieldbackground=palette['surface'], foreground=palette['foreground'], insertcolor=palette['foreground'], bordercolor=palette['line'])
    for direction in ('Horizontal', 'Vertical'):
        style.configure(direction + '.TScrollbar', background=palette['scroll'], troughcolor=palette['surface'], arrowcolor=palette['muted'], bordercolor=palette['surface'], lightcolor=palette['surface'], darkcolor=palette['surface'], arrowsize=12)
        style.map(direction + '.TScrollbar', background=[('active', palette['muted'])])
    return family


def color_widgets(widget, palette):
    """Restyle existing classic Tk widgets; ttk widgets use the shared styles."""
    kind = widget.winfo_class()
    if kind in ('Tk', 'Toplevel'):
        widget.configure(background=palette['background'])
    elif kind in ('Text', 'Entry', 'Listbox'):
        widget.configure(background=palette['surface'], foreground=palette['foreground'],
                         selectbackground=palette['selected'], selectforeground=palette['foreground'],
                         highlightbackground=palette['line'])
        if kind in ('Text', 'Entry'):
            widget.configure(insertbackground=palette['foreground'])
    elif kind == 'Menu':
        widget.configure(background=palette['surface'], foreground=palette['foreground'],
                         activebackground=palette['tint'], activeforeground=palette['foreground'],
                         disabledforeground=palette['disabled'], borderwidth=0)
    elif kind in ('Label', 'Button', 'Checkbutton', 'Radiobutton', 'Frame', 'Labelframe'):
        widget.configure(background=palette['background'])
        if kind not in ('Frame', 'Labelframe'):
            widget.configure(foreground=palette['foreground'])
    if kind == 'TCombobox':
        popup = widget.tk.call('ttk::combobox::PopdownWindow', widget)
        widget.tk.call(str(popup) + '.f.l', 'configure', '-background', palette['surface'], '-foreground', palette['foreground'], '-selectbackground', palette['selected'], '-selectforeground', palette['foreground'])
    for child in list(widget.children.values()):
        color_widgets(child, palette)


def format_results(records):
    lines = []
    for result in records:
        state = 'Успешно' if result.get('ok') else 'Отменено' if result.get('cancelled') else 'Требует проверки'
        name = result.get('name', result.get('ip', 'Компьютер'))
        lines.extend([str(name) + ' — ' + state, str(result.get('message', ''))])
        if result.get('cwd'):
            lines.append('Рабочая папка: ' + str(result['cwd']))
        if result.get('command'):
            lines.extend(['Команда:', str(result['command'])])
        if result.get('files'):
            lines.append('Проверенные файлы:')
            lines.extend('  ' + item['path'] for item in result['files'])
        if result.get('output'):
            lines.extend(['Вывод:', str(result['output'])])
        lines.extend(['', '—' * 40, ''])
    return '\n'.join(lines) if lines else 'Пока нет результатов действий.'


def room_entries(rooms, hosts):
    counts = Counter(host.room for host in hosts)
    return [('Все кабинеты', len(hosts))] + [(name, counts[name]) for name in sorted(rooms)]


def operation_entries(operations):
    titles = {'distribute': 'Раздача файлов', 'command': 'Команда Bash', 'off': 'Выключение',
              'reboot': 'Перезагрузка', 'cancel': 'Отмена выключения', 'scan': 'Проверка связи', 'time_sync': 'Синхронизация времени', 'wake': 'Включение WoL', 'collect_mac': 'Получение MAC'}
    rows = []
    for identifier, operation in operations.items():
        title = titles.get(operation['action'], operation['action'])
        if operation['action'] == 'command' and operation['job'].get('sudo'):
            title += ' · sudo'
        pending, finished = len(operation['pending']), len(operation['results'])
        if operation['state'] == 'preparing':
            status = 'Проверка подключения'
        elif not pending:
            status = 'Сохранение отчёта'
        elif operation['action'] == 'distribute' and operation['progress']:
            values = operation['progress'].values()
            status = str(int(sum(item['percent'] for item in values) / len(operation['progress']))) + '% · передача / проверка'
        elif operation['action'] == 'distribute':
            status = 'Подготовка файлов'
        else:
            status = 'Выполняется'
        rows.append((identifier, (title, 'Готово ' + str(finished) + ' / ' + str(finished + pending), status)))
    return rows


def sync_rows(tree, rows):
    """Update data without resetting keyboard focus, selection or scroll position."""
    expected = {identifier for identifier, values, tags in rows}
    for identifier in tree.get_children():
        if identifier not in expected:
            tree.delete(identifier)
    for index, (identifier, values, tags) in enumerate(rows):
        if tree.exists(identifier):
            if tuple(tree.item(identifier, 'values')) != tuple(str(value) for value in values) or tuple(tree.item(identifier, 'tags')) != tuple(tags):
                tree.item(identifier, values=values, tags=tags)
            tree.move(identifier, '', index)
        else:
            tree.insert('', index, iid=identifier, values=values, tags=tags)


def sorted_computer_rows(rows, column, reverse=False):
    """Sort displayed values only; stable host IDs keep selection and operation ownership."""
    if column is None:
        return rows
    index = ('check', 'name', 'ip', 'status', 'stop').index(column)

    def natural(value):
        return tuple((1, int(part)) if part.isdigit() else (0, part.casefold())
                     for part in re.split(r'(\d+)', str(value)))

    def key(row):
        value = row[1][index]
        if column == 'ip':
            try:
                primary = (0, int(ipaddress.IPv4Address(value)))
            except ipaddress.AddressValueError:
                primary = (1, natural(value))
        else:
            primary = natural(value)
        return primary, natural(row[0])

    return sorted(rows, key=key, reverse=reverse)
