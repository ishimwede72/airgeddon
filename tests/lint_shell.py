#!/usr/bin/env python3
"""Bound ShellCheck memory use by checking complete top-level function batches."""
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
failed = False
for path in [ROOT / 'airgeddon.sh', ROOT / 'language_strings.sh', *sorted((ROOT / 'plugins').glob('*.sh'))]:
    lines = path.read_text().splitlines(keepends=True)
    starts = [0]
    for i, line in enumerate(lines):
        if re.match(r'^(?:function \w+\(\)|\w+\(\))\s*\{', line):
            start = i
            while start > starts[-1] and (not lines[start - 1].strip() or lines[start - 1].startswith('#')):
                start -= 1
            if start > starts[-1]:
                starts.append(start)
    starts.append(len(lines))
    for a, b in zip(starts, starts[1:]):
        text = '#!/usr/bin/env bash\n# shellcheck disable=SC2154,SC2034\n' + ''.join(lines[a:b])
        result = subprocess.run(['shellcheck', '--severity=warning', '--shell=bash', '-'], input=text, text=True, capture_output=True)
        if result.returncode:
            failed = True
            print(f'{path.relative_to(ROOT)} (section starting at line {a + 1}):')
            print(result.stdout, end='')
            print(result.stderr, end='')
sys.exit(1 if failed else 0)
