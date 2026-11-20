#!/usr/bin/env python3
"""Offline defensive utilities: no live capture, credential harvesting, or cracking."""
import argparse
import getpass
import hashlib
import json
from pathlib import Path
import re
import secrets
import sys
import time

from .assess import ValidationError, _markdown_text, _object, _text, assess
from .capture import analyze_capture, compare_baseline
from .resources import dictionary_lines, load_json


def catalog(manifest_path):
    manifest_path = Path(manifest_path)
    data = load_json(manifest_path)
    _object(data, {'schema_version', 'dictionaries'}, {'schema_version', 'dictionaries'}, 'manifest')
    if type(data['schema_version']) is not int or data['schema_version'] != 1:
        raise ValidationError('Invalid manifest version')
    entries = data['dictionaries']
    if not isinstance(entries, list) or not 1 <= len(entries) <= 20:
        raise ValidationError('Expected 1–20 dictionaries')
    result, identifiers = [], set()
    for entry in entries:
        fields = {'id', 'path', 'source', 'license', 'language', 'sha256'}
        _object(entry, fields, fields, 'dictionary')
        for field in fields:
            if field != 'path':
                _text(entry[field], field)
        if entry['id'] in identifiers:
            raise ValidationError('Duplicate dictionary id')
        identifiers.add(entry['id'])
        if not re.fullmatch('[0-9a-f]{64}', entry['sha256']):
            raise ValidationError('Expected lowercase SHA-256')
        if not isinstance(entry['path'], str) or not entry['path'] or len(entry['path']) > 4096:
            raise ValidationError('Invalid local dictionary path')
        path = Path(entry['path'])
        if not path.is_absolute():
            path = manifest_path.parent / path
        digest, seen = hashlib.sha256(), set()
        counts = dict(bytes=0, lines=0, unique_entries=0, duplicates=0, empty_lines=0, invalid_utf8=0, credential_like_lines=0)
        for raw in dictionary_lines(path):
            digest.update(raw)
            counts['bytes'] += len(raw)
            counts['lines'] += 1
            value = raw.rstrip(b'\r\n')
            if not value:
                counts['empty_lines'] += 1
                continue
            try:
                value.decode('utf-8')
            except UnicodeDecodeError:
                counts['invalid_utf8'] += 1
            # A heuristic only, not a guarantee that a file contains no secrets.
            if re.search(rb'[^\s:@]+@[^\s:]+:[^\s]+', value) or re.search(rb'(?i)(?:password|passwd|token|secret)\s*[:=]\s*\S+', value):
                counts['credential_like_lines'] += 1
            fingerprint = hashlib.sha256(value).digest()
            counts['duplicates' if fingerprint in seen else 'unique_entries'] += 1
            seen.add(fingerprint)
        actual = digest.hexdigest()
        result.append(dict(id=entry['id'], source=entry['source'], license=entry['license'], language=entry['language'],
                           sha256=actual, checksum_matches=actual == entry['sha256'], **counts))
    return dict(schema_version=1, assessment_type='local-dictionary-catalog', dictionaries=result,
                limitations=['No dictionary contents, entry hashes, or local paths are included in this report.',
                             'Duplicate counts use exact line bytes after CR/LF removal; no candidate lists are generated.',
                             'Source/license metadata is user-declared, not verified; credential detection is heuristic.',
                             'No dictionaries are downloaded, bundled, or passed to cracking tools.'])


def evaluate_password(password, blocklist, minimum=15):
    if type(minimum) is not int or not 8 <= minimum <= 128:
        raise ValidationError('Minimum length must be 8–128')
    if not isinstance(password, str) or len(password) > 1024:
        raise ValidationError('Password exceeds local assessment limit')
    encoded = password.encode('utf-8')
    blocked = False
    for raw in dictionary_lines(blocklist):
        if secrets.compare_digest(encoded, raw.rstrip(b'\r\n')):
            blocked = True
    checks = [dict(check_id='PASSWORD-MINIMUM-LENGTH', status='pass' if len(password) >= minimum else 'fail'),
              dict(check_id='PASSWORD-LOCAL-BLOCKLIST', status='fail' if blocked else 'pass'),
              dict(check_id='PASSWORD-CONTROL-CHARACTERS', status='fail' if any(ord(c) < 32 or ord(c) == 127 for c in password) else 'pass')]
    return dict(schema_version=1, assessment_type='offline-password-policy', minimum_length=minimum, checks=checks,
                limitations=['The password, its length, and derived hashes are never included in the report.',
                             'Only exact UTF-8 blocklist membership and declared local policy are tested.',
                             'This does not estimate crack time or establish password strength or account security.',
                             'Use disposable test passwords. Python cannot guarantee secret erasure from memory.'])


def benchmark(samples=1000, seconds=1.0):
    if type(samples) is not int or not 1 <= samples <= 10000 or not 0.01 <= seconds <= 5:
        raise ValidationError('Benchmark requires 1–10000 samples and 0.01–5 seconds')
    # Generated fixtures, not passwords or hashes supplied by a user. No search/recovery loop.
    started = time.perf_counter()
    passed = failed = completed = 0
    for index in range(samples):
        if time.perf_counter() - started >= seconds:
            break
        fixture = ('synthetic-policy-fixture-' if index % 2 else 'short-') + str(index)
        valid = len(fixture) >= 15
        passed += valid
        failed += not valid
        completed += 1
    elapsed = time.perf_counter() - started
    return dict(schema_version=1, assessment_type='synthetic-policy-benchmark', requested_samples=samples,
                completed_samples=completed, passing_fixtures=passed, failing_fixtures=failed,
                elapsed_seconds=round(elapsed, 6), time_budget_seconds=seconds,
                limitations=['Measures synthetic length-policy evaluation/report plumbing only, not password cracking.',
                             'No production passwords, hashes, dictionaries, targets, or network inputs are accepted.',
                             'The deadline is checked between fixtures; wall-clock limits are best-effort, not OS isolation.'])


def combined(inventory, capture=None, baseline=None, manifest=None):
    if baseline and not capture:
        raise ValidationError('A baseline requires a capture')
    reports = [assess(load_json(inventory))]
    if capture:
        observed = analyze_capture(capture)
        reports.append(observed)
        if baseline:
            reports.append(compare_baseline(observed, load_json(baseline)))
    if manifest:
        reports.append(catalog(manifest))
    return dict(schema_version=1, assessment_type='combined-offline-assessment', reports=reports,
                limitations=['Sections retain distinct evidence types: declarations versus advertised observations.',
                             'No global security score or certification is inferred from these results.',
                             'Password submissions are intentionally excluded from combined reports.'])


def markdown(value):
    # JSON in an HTML-escaped code block keeps arbitrary metadata inert in Markdown renderers.
    import html
    name = _markdown_text(value['assessment_type'])
    body = html.escape(json.dumps(value, indent=2, ensure_ascii=True))
    return f'# {name}\n\nOffline evidence only; review all limitations.\n\n<pre>\n{body}\n</pre>\n'


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--format', choices=('json', 'markdown'), default='json')
    parser.add_argument('--output', type=Path, help='Private report path; must not already exist')
    commands = parser.add_subparsers(dest='command', required=True)
    command = commands.add_parser('catalog', help='Index licensed, locally supplied dictionaries; no content output')
    command.add_argument('manifest', type=Path)
    command = commands.add_parser('capture', help='Analyze existing classic-PCAP beacons only')
    command.add_argument('pcap', type=Path)
    command.add_argument('--baseline', type=Path)
    command = commands.add_parser('policy', help='Prompt locally for a disposable test password (never put it in argv)')
    command.add_argument('--blocklist', required=True, type=Path)
    command.add_argument('--minimum-length', type=int, default=15)
    command = commands.add_parser('benchmark', help='Bounded synthetic policy/report benchmark; no cracking')
    command.add_argument('--samples', type=int, default=1000)
    command.add_argument('--seconds', type=float, default=1.0)
    command = commands.add_parser('report', help='Combine configuration, beacon/baseline, and catalog evidence')
    command.add_argument('inventory', type=Path)
    command.add_argument('--pcap', type=Path)
    command.add_argument('--baseline', type=Path)
    command.add_argument('--manifest', type=Path)
    args = parser.parse_args(argv)
    try:
        # No overwrite mode: in particular, never clobber an input, manifest, or dictionary.
        if args.output and (args.output.exists() or args.output.is_symlink()):
            raise ValidationError('Output exists')
        if args.command == 'catalog':
            result = catalog(args.manifest)
        elif args.command == 'capture':
            result = analyze_capture(args.pcap)
            if args.baseline:
                result = dict(schema_version=1, assessment_type='capture-and-baseline', reports=[result, compare_baseline(result, load_json(args.baseline))])
        elif args.command == 'policy':
            if not sys.stdin.isatty() or not sys.stderr.isatty():
                raise ValidationError('Password input requires an interactive terminal')
            # Refuse echo-fallback, even when stdin is a terminal but /dev/tty cannot disable echo.
            import warnings
            with warnings.catch_warnings():
                warnings.simplefilter('error', getpass.GetPassWarning)
                password = getpass.getpass('Disposable test password (hidden): ')
            result = evaluate_password(password, args.blocklist, args.minimum_length)
            del password
        elif args.command == 'benchmark':
            result = benchmark(args.samples, args.seconds)
        else:
            result = combined(args.inventory, args.pcap, args.baseline, args.manifest)
        text = json.dumps(result, indent=2, ensure_ascii=True) + '\n' if args.format == 'json' else markdown(result)
        if args.output:
            # O_EXCL prevents races and symlink following; mode is private from creation.
            import os
            fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                with os.fdopen(fd, 'w', encoding='utf-8') as target:
                    target.write(text)
            except BaseException:
                args.output.unlink(missing_ok=True)
                raise
        else:
            print(text, end='')
        return 0
    except (OSError, ValueError, RecursionError, getpass.GetPassWarning, EOFError):
        print('Offline utility failed: invalid/unsupported input, resource limit, terminal, or output path. See lab/TOOLKIT.md.', file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print('Offline assessment cancelled.', file=sys.stderr)
        return 130


if __name__ == '__main__':
    sys.exit(main())
