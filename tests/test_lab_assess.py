"""Offline tests: synthetic inventories, temp directories, no radio or root work."""
import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from lab.assess import (ValidationError, assess, load_inventory, main,
                        markdown_report, validate_inventory, write_private)


def inventory(**updates):
    network = dict(id='synthetic', security='wpa3-personal', pmf='required')
    network.update(updates)
    return dict(schema_version=1, scope=dict(label='Unit test', authorized=True), networks=[network])


class AssessmentTests(unittest.TestCase):
    def test_modern_personal(self):
        report = assess(inventory())
        self.assertEqual(report['summary'], {'pass': 3, 'fail': 0, 'unknown': 0, 'review': 0})
        self.assertEqual(report['assessment_type'], 'offline-declarations')

    def test_transition_and_pmf(self):
        report = assess(inventory(security='wpa2-wpa3-personal', pmf='optional'))
        self.assertEqual(report['summary']['fail'], 2)
        high = assess(inventory(pmf='disabled'))
        self.assertEqual(high['findings'][2]['severity'], 'high')

    def test_open_and_unknown(self):
        self.assertEqual(assess(inventory(security='open'))['findings'][0]['status'], 'fail')
        unknown = assess(inventory(security='unknown', pmf='unknown'))
        self.assertEqual(unknown['summary']['unknown'], 3)

    def test_missing_enterprise_is_unknown(self):
        report = assess(inventory(security='wpa2-enterprise'))
        self.assertEqual(report['summary']['unknown'], 4)

    def test_enterprise_certificate_and_method_review(self):
        report = assess(inventory(security='wpa3-enterprise', enterprise={
            'validate_server_certificate': False, 'trusted_ca_configured': True,
            'server_names_configured': False, 'eap_methods': ['tls']}))
        self.assertEqual(report['summary']['fail'], 2)
        self.assertEqual(report['summary']['review'], 1)
        self.assertEqual(report['findings'][3]['severity'], 'high')

    def test_deterministic_and_nonmutating(self):
        data = inventory()
        before = copy.deepcopy(data)
        first = assess(data)
        self.assertEqual(first, assess(data))
        self.assertEqual(data, before)
        data['networks'][0]['pmf'] = 'optional'
        self.assertNotEqual(first['inventory_sha256'], assess(data)['inventory_sha256'])

    def test_invalid_inputs(self):
        cases = []
        for field, value in [('schema_version', True), ('schema_version', 2), ('networks', []), ('networks', 'invalid')]:
            data = inventory()
            data[field] = value
            cases.append(data)
        data = inventory()
        data['scope']['authorized'] = False
        cases.append(data)
        data = inventory()
        data['networks'] *= 2
        cases.append(data)
        cases.extend([inventory(pmf='REQUIRED'), inventory(security=[]), inventory(id='bad\x1b[31m'),
                      inventory(password='secret'), inventory(enterprise={}),
                      inventory(security='wpa2-enterprise', enterprise={'trusted_ca_configured': 'yes'}),
                      inventory(security='wpa2-enterprise', enterprise={'eap_methods': ['tls', 'tls']})])
        for data in cases:
            with self.subTest(data=data), self.assertRaises(ValidationError):
                validate_inventory(data)

    def test_markdown_escapes_untrusted_labels(self):
        data = inventory(id='<script>|[link](url)')
        data['scope']['label'] = '<img src=x>'
        text = markdown_report(assess(data))
        self.assertNotIn('<script>', text)
        self.assertNotIn('<img', text)
        self.assertIn('\\|', text)
        self.assertIn('\\[link\\]', text)

    def test_assessor_does_not_call_network_or_process_tools(self):
        with patch('socket.socket', side_effect=AssertionError('network access')), patch('subprocess.Popen', side_effect=AssertionError('process execution')):
            assess(inventory())


class FileAndCliTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.source = self.root / 'inventory.json'
        self.source.write_text(json.dumps(inventory()))

    def test_duplicate_json_keys_and_oversize(self):
        self.source.write_text('{"schema_version": 1, "schema_version": 1}')
        with self.assertRaises(ValidationError):
            load_inventory(self.source)
        self.source.write_bytes(b' ' * (1024 * 1024 + 1))
        with self.assertRaises(ValidationError):
            load_inventory(self.source)

    def test_private_atomic_output_does_not_follow_symlink(self):
        protected = self.root / 'protected'
        protected.write_text('unchanged')
        output = self.root / 'report'
        output.symlink_to(protected)
        write_private(output, 'report')
        self.assertEqual(protected.read_text(), 'unchanged')
        self.assertFalse(output.is_symlink())
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        self.assertFalse(list(self.root.glob('.assessment-*')))

    def test_cli_json_and_exit_codes(self):
        output = self.root / 'report.json'
        self.assertEqual(main([str(self.source), '--format', 'json', '--output', str(output), '--fail-on-findings']), 0)
        self.assertEqual(json.loads(output.read_text())['summary']['pass'], 3)
        self.source.write_text(json.dumps(inventory(security='unknown', pmf='unknown')))
        self.assertEqual(main([str(self.source), '--output', str(output), '--fail-on-findings']), 1)
        self.assertEqual(main([str(self.source), '--output', str(output)]), 0)

    def test_bad_input_does_not_clobber_output_or_expose_content(self):
        output = self.root / 'report'
        output.write_text('existing report')
        self.source.write_text('super-secret-invalid-json')
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors):
            self.assertEqual(main([str(self.source), '--output', str(output)]), 2)
        self.assertNotIn('super-secret', errors.getvalue())
        self.assertEqual(output.read_text(), 'existing report')

    def test_inventory_cannot_be_output(self):
        before = self.source.read_bytes()
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main([str(self.source), '--output', str(self.source)]), 2)
        self.assertEqual(self.source.read_bytes(), before)

    def test_io_errors(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main([str(self.root / 'missing')]), 2)
            self.assertEqual(main([str(self.source), '--output', str(self.root / 'missing-dir' / 'report')]), 2)


if __name__ == '__main__':
    unittest.main()
