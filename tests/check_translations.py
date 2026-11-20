#!/usr/bin/env python3
"""Static translation key/version checks; never execute translation shell code."""
from collections import defaultdict
from pathlib import Path
import re

root = Path(__file__).resolve().parent.parent
script = (root / 'airgeddon.sh').read_text()
strings = (root / 'language_strings.sh').read_text()
expected = re.search(r'^language_strings_expected_version="([^"]+)"', script, re.M)[1]
actual = re.search(r'^\s*language_strings_version="([^"]+)"', strings, re.M)[1]
assert expected == actual, f'Language version mismatch: {expected} != {actual}'
languages = set(re.findall(r'\["[a-z]+"\]="([A-Z]+)"', script))
keys = defaultdict(set)
for array, language, index in re.findall(r'^\s*(\w+)\["([A-Z]+)"(?:,([^\]]+))?\]=', strings, re.M):
    keys[(array, language)].add(index)
errors = []
for array in sorted({array for array, language in keys if language == 'ENGLISH'}):
    reference = keys[(array, 'ENGLISH')]
    for language in sorted(languages):
        missing = reference - keys[(array, language)]
        extra = keys[(array, language)] - reference
        if missing or extra:
            errors.append(f'{array}/{language}: missing={sorted(missing)}, extra={sorted(extra)}')
assert not errors, '\n'.join(errors)
print(f'Translation versions and key coverage match across {len(languages)} languages.')
