#!/usr/bin/env python3
"""Assess declared wireless configuration. No shell commands or network access."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile

SCHEMA_VERSION = 1
MAX_INPUT_BYTES = 1024 * 1024
MAX_NETWORKS = 1000


class ValidationError(ValueError):
    """The inventory is invalid; no assessment should be issued."""


def _object(value, allowed, required, location):
    if not isinstance(value, dict):
        raise ValidationError(f'{location}: expected an object')
    if set(value) - allowed:
        raise ValidationError(f'{location}: unknown fields (secrets and executable actions are not supported)')
    if required - set(value):
        raise ValidationError(f'{location}: missing required fields')


def _text(value, location):
    if not isinstance(value, str) or not value.strip() or len(value) > 128:
        raise ValidationError(f'{location}: expected nonempty text of at most 128 characters')
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValidationError(f'{location}: control characters are not allowed')


def _enum(value, choices, location):
    if not isinstance(value, str) or value not in choices:
        raise ValidationError(f'{location}: expected one of {", ".join(choices)}')


def validate_inventory(data):
    _object(data, {'schema_version', 'scope', 'networks'}, {'schema_version', 'scope', 'networks'}, 'inventory')
    if type(data['schema_version']) is not int or data['schema_version'] != SCHEMA_VERSION:
        raise ValidationError('inventory: unsupported schema_version')
    _object(data['scope'], {'label', 'authorized'}, {'label', 'authorized'}, 'scope')
    _text(data['scope']['label'], 'scope.label')
    if data['scope']['authorized'] is not True:
        raise ValidationError('scope.authorized must explicitly be true')
    networks = data['networks']
    if not isinstance(networks, list) or not 1 <= len(networks) <= MAX_NETWORKS:
        raise ValidationError(f'networks: expected 1–{MAX_NETWORKS} entries')
    seen = set()
    for i, network in enumerate(networks):
        loc = f'networks[{i}]'
        _object(network, {'id', 'security', 'pmf', 'enterprise'}, {'id', 'security', 'pmf'}, loc)
        _text(network['id'], f'{loc}.id')
        if network['id'] in seen:
            raise ValidationError(f'{loc}: duplicate network id')
        seen.add(network['id'])
        _enum(network['security'], ('open', 'wpa2-personal', 'wpa3-personal', 'wpa2-wpa3-personal', 'wpa2-enterprise', 'wpa3-enterprise', 'unknown'), f'{loc}.security')
        _enum(network['pmf'], ('disabled', 'optional', 'required', 'unknown'), f'{loc}.pmf')
        if 'enterprise' in network:
            if network['security'] not in ('wpa2-enterprise', 'wpa3-enterprise'):
                raise ValidationError(f'{loc}: enterprise settings require enterprise security')
            enterprise = network['enterprise']
            _object(enterprise, {'eap_methods', 'validate_server_certificate', 'trusted_ca_configured', 'server_names_configured'}, set(), f'{loc}.enterprise')
            if 'eap_methods' in enterprise:
                methods = enterprise['eap_methods']
                if not isinstance(methods, list) or not methods or len(methods) > 4:
                    raise ValidationError(f'{loc}: eap_methods must be a nonempty list')
                for method in methods:
                    _enum(method, ('tls', 'peap', 'ttls', 'unknown'), f'{loc}.eap_methods')
                if len(set(methods)) != len(methods):
                    raise ValidationError(f'{loc}: duplicate EAP method')
            for field in ('validate_server_certificate', 'trusted_ca_configured', 'server_names_configured'):
                if field in enterprise and type(enterprise[field]) is not bool:
                    raise ValidationError(f'{loc}.{field}: expected a boolean; omit when unknown')
    return data


def assess(data):
    """Produce deterministic findings from validated declarations, never observations."""
    validate_inventory(data)
    findings = []

    def add(network, check, status, severity, evidence, recommendation):
        findings.append(dict(network_id=network['id'], check_id=check, status=status,
                             severity=severity, evidence=evidence, recommendation=recommendation))

    for network in sorted(data['networks'], key=lambda item: item['id']):
        security, pmf = network['security'], network['pmf']
        add(network, 'WIRELESS-ENCRYPTION',
            'unknown' if security == 'unknown' else 'fail' if security == 'open' else 'pass',
            'high' if security == 'open' else 'info',
            f'Declared security: {security}.', 'Use an authenticated, encrypted network appropriate to the deployment.')
        add(network, 'WPA-TRANSITION',
            'unknown' if security == 'unknown' else 'fail' if security == 'wpa2-wpa3-personal' else 'pass',
            'medium' if security == 'wpa2-wpa3-personal' else 'info',
            f'Declared security: {security}.', 'Prefer WPA3-only where the supported client population permits it.')
        add(network, 'PMF-REQUIRED',
            'unknown' if pmf == 'unknown' else 'pass' if pmf == 'required' else 'fail',
            'high' if pmf in ('disabled', 'optional') and security.startswith('wpa3-') else 'medium' if pmf in ('disabled', 'optional') else 'info',
            f'Declared PMF policy: {pmf}; this does not verify enforcement.', 'Require PMF where supported and verify enforcement in an isolated lab.')
        if security in ('wpa2-enterprise', 'wpa3-enterprise'):
            enterprise = network.get('enterprise', {})
            for field, check, recommendation in (
                ('validate_server_certificate', 'EAP-SERVER-CERTIFICATE', 'Enable server certificate validation on every client profile.'),
                ('trusted_ca_configured', 'EAP-TRUST-ANCHOR', 'Configure an explicitly trusted CA for the authentication server.'),
                ('server_names_configured', 'EAP-SERVER-NAME', 'Restrict client profiles to the intended authentication server names.'),
            ):
                value = enterprise.get(field)
                add(network, check, 'unknown' if value is None else 'pass' if value else 'fail',
                    'high' if value is False else 'info',
                    f'Declared {field}: {"unknown" if value is None else str(value).lower()}.', recommendation)
            methods = enterprise.get('eap_methods', [])
            add(network, 'EAP-METHOD-REVIEW', 'unknown' if not methods or 'unknown' in methods else 'review', 'info',
                f'Declared EAP methods: {", ".join(methods) or "unknown"}.',
                'Review inner methods, TLS versions, certificate lifecycle, RADIUS policy, and actual client profiles. An EAP method name alone does not establish security.')
    canonical = json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()
    return dict(schema_version=SCHEMA_VERSION, assessment_type='offline-declarations',
                scope=data['scope']['label'], inventory_sha256=hashlib.sha256(canonical).hexdigest(),
                limitations=['No radios, network services, credentials, or external tools were accessed.',
                             'Pass means a declared setting matches a check, not that runtime behavior was verified.',
                             'Unknown or omitted settings are not treated as secure. This is not a compliance certification.'],
                summary={status: sum(f['status'] == status for f in findings) for status in ('pass', 'fail', 'unknown', 'review')},
                findings=findings)


def _markdown_text(value):
    # Escape user-supplied text, including HTML and table delimiters.
    import html
    value = html.escape(str(value), quote=True)
    for char in ('\\', '`', '*', '_', '[', ']', '|', '#'):
        value = value.replace(char, '\\' + char)
    return value


def markdown_report(report):
    lines = ['# Offline wireless configuration assessment', '', f'Scope: {_markdown_text(report["scope"])}', '',
             f'Inventory SHA-256: `{report["inventory_sha256"]}`', '', '## Limitations', '']
    lines.extend(f'- {item}' for item in report['limitations'])
    lines.extend(['', '## Summary', '', ', '.join(f'{key}: {value}' for key, value in report['summary'].items()), '',
                  '## Findings', '', '| Network | Check | Status | Severity | Evidence | Recommendation |',
                  '| --- | --- | --- | --- | --- | --- |'])
    for finding in report['findings']:
        lines.append('| ' + ' | '.join(_markdown_text(finding[key]) for key in
                     ('network_id', 'check_id', 'status', 'severity', 'evidence', 'recommendation')) + ' |')
    return '\n'.join(lines) + '\n'


def _unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError('Duplicate JSON object key')
        result[key] = value
    return result


def load_inventory(path):
    with path.open('rb') as source:
        raw = source.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise ValidationError('Inventory exceeds 1 MiB')
    return validate_inventory(json.loads(raw, object_pairs_hook=_unique_keys))


def write_private(path, text):
    """Atomically replace one report, without following an existing output symlink."""
    fd, staged = tempfile.mkstemp(prefix='.assessment-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as target:
            target.write(text)
        os.replace(staged, path)
    finally:
        if os.path.exists(staged):
            os.unlink(staged)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('inventory', type=Path, help='Authorized, normalized JSON inventory; never include secrets')
    parser.add_argument('--format', choices=('json', 'markdown'), default='markdown')
    parser.add_argument('--output', type=Path, help='Private output file (default: stdout)')
    parser.add_argument('--fail-on-findings', action='store_true', help='Exit 1 if any check fails or remains unknown/review')
    args = parser.parse_args(argv)
    try:
        if args.output and args.output.resolve() == args.inventory.resolve():
            raise ValidationError('Output must not overwrite the inventory')
        report = assess(load_inventory(args.inventory))
        text = json.dumps(report, indent=2, ensure_ascii=True) + '\n' if args.format == 'json' else markdown_report(report)
        if args.output:
            write_private(args.output, text)
        else:
            print(text, end='')
        return int(args.fail_on_findings and any(report['summary'][key] for key in ('fail', 'unknown', 'review')))
    except (OSError, ValueError, RecursionError):
        # Do not echo input, secrets, terminal escapes, or untrusted filenames in diagnostics.
        print('Assessment failed: invalid inventory or inaccessible input/output. See lab/README.md for the schema.', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
