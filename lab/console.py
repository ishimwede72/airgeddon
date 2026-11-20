#!/usr/bin/env python3
"""Image-inspired terminal presentation. No radio, network, or command execution."""
import argparse
from datetime import datetime
import os
import platform
import re
import shutil
import sys

# Original terminal artwork, not an embedded Kali trademark or raster image.
DRAGON = r'''
             /\       /\
        ____/  \_/\__/  \
     __/  _       _   /\ \
    /  __/ \_____/ \_/  \_\
   / _/     /  /\   __
  / /    __/  /  \_/  \___
 / /  __/    /   /  /\    \
 | | /  ___ /   /__/  \_/\ \
 | |/  /  //      _.-^^\  \_\
 |    /  //   _.-'  o  /\
  \  /  //_.-'    __  /  >
   \   / /   ___/  \/  /
    \_/ / __/  /\___/\/
      / / /   /  \__/  >
     / / /   /        /
    / / /___/   /\___/
   / /______   / /\
  /_/       \_/ /  \
  \___________/ /\  \
      \________/  \__/
        ASSESS / ANALYZE
            SECURE
'''.strip('\n').splitlines()

MENU = [
    ('01', 'Select network interface'),
    ('02', 'Monitor mode'),
    ('03', 'Managed mode'),
    ('04', 'DoS assessment menu'),
    ('05', 'Handshake / PMKID tools'),
    ('06', 'Offline WPA/WPA2 menu'),
    ('07', 'Evil Twin menu'),
    ('08', 'WPS assessment menu'),
    ('09', 'WEP assessment menu'),
    ('10', 'Enterprise authentication'),
    ('11', 'WPA3 research menu'),
    ('12', 'About / Credits'),
    ('13', 'Options / Language'),
    ('00', 'Exit / cleanup'),
]


def clean(value):
    """Single-cell ASCII prevents control injection and ambiguous terminal widths."""
    return ''.join(char if ord(char) <= 126 else '?' for char in str(value) if ord(char) >= 32 and ord(char) != 127)[:256]


def dimension(value, default, maximum):
    value = str(value)
    return max(1, min(int(value), maximum)) if re.fullmatch(r'[0-9]{1,3}', value) else default


def box(title, body, width):
    inner = width - 4
    top = '+-' + (' ' + clean(title) + ' ').ljust(width - 4, '-')[:width - 4] + '-+'
    return [top, *('| ' + clean(line)[:inner].ljust(inner) + ' |' for line in body), '+' + '-' * (width - 2) + '+']


def columns(panels, widths):
    for row in range(max(map(len, panels))):
        yield '  '.join(panel[row].ljust(width) if row < len(panel) else ' ' * width
                        for panel, width in zip(panels, widths)).rstrip()


def menu_lines():
    return [f'[{key}] {label}' for key, label in MENU]


def render(width, height, version, interface, mode, windows, preview=False):
    width = dimension(width, 80, 160)
    height = dimension(height, 24, 120)
    version, interface, mode, windows = map(clean, (version, interface, mode, windows))
    title = f'AIRGEDDON v{version} | WIRELESS SECURITY PLATFORM'
    clock = datetime.now().strftime('%H:%M:%S')
    host = f'{clean(platform.system())} / {clock}'
    if len(title) + len(host) + 3 <= width:
        title = title.ljust(width - len(host)) + host
    lines = [title, '=' * width]
    context = [f'INTERFACE {interface}', f'MODE {mode}  |  WINDOWS {windows}']
    notice = 'PREVIEW ONLY | Authorized testing only | No wireless operations performed.' if preview else 'Authorized testing only | Status is not proof of network safety.'
    if width >= 132 and height >= 38:
        left, right = 34, 34
        center = width - left - right - 4
        dragon = box('DRAGON / LAB CONSOLE', DRAGON, left)
        dragon += [''] + box('PRINCIPLE', ['Hack smart.', 'Test securely.', 'Document the evidence.', '', 'Authorized testing only'], left)
        middle = ['AIRGEDDON'.center(center), 'WIRELESS SECURITY PLATFORM'.center(center),
                  'ASSESS  /  ANALYZE  /  SECURE'.center(center), '']
        middle += box('EXISTING FEATURE MENUS', menu_lines(), center)
        middle += [''] + box('OFFLINE DEFENSIVE TOOLS', ['PCAP / approved-AP comparison', 'Dictionary catalog / policy', 'Synthetic benchmark / reports', 'h Help  |  q Quit'], center)
        status = box('SYSTEM OVERVIEW', ['Console : MENU', f'Host    : {platform.system()}',
                                            f'Version : {version}', 'Scope   : user responsibility'], right)
        status += [''] + box('WIRELESS STATUS', [f'Interface: {interface}', f'Mode     : {mode}',
                                                f'Windows  : {windows}', 'Enforcement: not verified'], right)
        status += [''] + box('NETWORK INFO', ['IP / gateway: not queried', 'No live telemetry in this UI.',
                                             'No simulated signal bars.'], right)
        status += [''] + box('QUICK ACTIONS', ['[H] Help / offline commands', '[Q] Exit through cleanup',
                                               'Use an existing menu number.'], right)
        lines += list(columns([dragon, middle, status], [left, center, right]))
    elif width >= 94 and height >= 30:
        left = width - 36
        right = 34
        middle = box('AIRGEDDON / FEATURE MENUS', menu_lines(), left)
        status = box('SYSTEM OVERVIEW', ['Console: MENU', f'Host: {platform.system()}', f'Version: {version}'], right)
        status += [''] + box('WIRELESS STATUS', [f'Interface: {interface}', f'Mode: {mode}', f'Windows: {windows}', 'Enforcement: not verified'], right)
        status += [''] + box('OFFLINE TOOLS', ['PCAP / AP baseline / catalog', 'Policy / benchmark / reports', 'h Help  |  q Quit'], right)
        lines += ['<=={>  WIRELESS AUDIT CONSOLE / ASSESS - ANALYZE - SECURE', *columns([middle, status], [left, right])]
    else:
        lines += ['<=={> WIRELESS AUDIT CONSOLE', *context, *menu_lines(), 'h Help  |  q Quit']
    lines += ['-' * width, notice]
    return [line[:width] for line in lines]


def paint(line):
    """Color trusted layout after measuring text width; no cursor manipulation."""
    line = re.sub(r'([+|=]|-{2,}|\[[0-9A-Z]+\])', '\x1b[1;31m\\1\x1b[0m', line)
    if line.startswith('AIRGEDDON') or 'ASSESS  /' in line:
        line = '\x1b[1;31m' + line + '\x1b[0m'
    return line


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version-label', default='unknown')
    parser.add_argument('--interface', default='not selected')
    parser.add_argument('--mode', default='unknown')
    parser.add_argument('--windows', default='xterm')
    parser.add_argument('--preview', action='store_true')
    args = parser.parse_args(argv)
    size = shutil.get_terminal_size((80, 24))
    width, height = os.environ.get('COLUMNS', size.columns), os.environ.get('LINES', size.lines)
    color = sys.stdout.isatty() and 'NO_COLOR' not in os.environ and os.environ.get('TERM', 'dumb') != 'dumb'
    lines = render(width, height, args.version_label, args.interface, args.mode, args.windows, args.preview)
    for line in lines:
        print(paint(line) if color else line)
    return 0


if __name__ == '__main__':
    sys.exit(main())
