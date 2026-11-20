"""Resource-bounded local input helpers."""
import json
from pathlib import Path
import stat

from .assess import MAX_INPUT_BYTES, ValidationError, _unique_keys

MAX_DICTIONARY_BYTES = 64 * 1024 * 1024
MAX_LINES = 250000
MAX_LINE_BYTES = 4096


def regular_file(path, limit):
    info = Path(path).stat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
        raise ValidationError('Input must be a bounded regular file')


def load_json(path):
    regular_file(path, MAX_INPUT_BYTES)
    with Path(path).open('rb') as source:
        value = source.read(MAX_INPUT_BYTES + 1)
    if len(value) > MAX_INPUT_BYTES:
        raise ValidationError('JSON input too large')
    return json.loads(value, object_pairs_hook=_unique_keys)


def dictionary_lines(path):
    regular_file(path, MAX_DICTIONARY_BYTES)
    total = 0
    with Path(path).open('rb') as source:
        for number in range(MAX_LINES + 1):
            value = source.readline(MAX_LINE_BYTES + 1)
            if not value:
                return
            total += len(value)
            if number >= MAX_LINES or len(value) > MAX_LINE_BYTES or total > MAX_DICTIONARY_BYTES:
                raise ValidationError('Dictionary size, line count, or line length limit exceeded')
            yield value
