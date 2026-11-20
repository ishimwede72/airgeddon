"""Generated beacons and synthetic dictionary/password fixtures only."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import socket
import struct
import tempfile
import unittest
from unittest.mock import patch

from lab.assess import ValidationError
from lab.capture import _beacon, _radiotap, _rsn, analyze_capture, compare_baseline
from lab.toolkit import benchmark, catalog, combined, evaluate_password, main, markdown
from lab.resources import dictionary_lines

BSSID = '02:00:00:00:00:01'


def rsn(akms=(2,), caps=0xC0):
    return (b'\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04' +
            struct.pack('<H', len(akms)) + b''.join(b'\x00\x0f\xac' + bytes([v]) for v in akms) + struct.pack('<H', caps))


def beacon(ssid=b'fixture', akms=(2,), caps=0xC0):
    header = b'\x80\x00\x00\x00' + b'\xff' * 6 + bytes.fromhex(BSSID.replace(':', '')) * 2 + b'\x00\x00'
    fixed = b'\x00' * 8 + b'\x64\x00' + (b'\x10\x00' if akms is not None else b'\x00\x00')
    ies = b'\x00' + bytes([len(ssid)]) + ssid
    if akms is not None:
        value = rsn(akms, caps)
        ies += bytes([48, len(value)]) + value
    return header + fixed + ies


def pcap(frames, endian='<', linktype=105):
    magic = b'\xd4\xc3\xb2\xa1' if endian == '<' else b'\xa1\xb2\xc3\xd4'
    header = magic + struct.pack(endian + 'HHIIII', 2, 4, 0, 0, 65535, linktype)
    return header + b''.join(struct.pack(endian + 'IIII', 0, 0, len(frame), len(frame)) + frame for frame in frames)


def baseline():
    return dict(schema_version=1, scope=dict(label='Synthetic fixture', authorized=True), approved_aps=[
        dict(bssid=BSSID, ssid_hex=b'fixture'.hex(), security='wpa2-personal', pmf='required')])


class ToolkitTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.capture = self.root / 'capture.pcap'
        self.capture.write_bytes(pcap([beacon(), beacon()]))
        self.words = self.root / 'synthetic.txt'
        self.words.write_bytes(b'synthetic-weak\nsynthetic-weak\n\ninvalid-\xff\npassword=synthetic-fixture\n')
        self.manifest = self.root / 'manifest.json'
        self.manifest.write_text(json.dumps(dict(schema_version=1, dictionaries=[dict(
            id='fixture', path=self.words.name, source='generated test fixture', license='CC0-1.0',
            language='en', sha256=hashlib.sha256(self.words.read_bytes()).hexdigest())])))

    def test_catalog_counts_without_content_or_paths(self):
        result = catalog(self.manifest)
        entry = result['dictionaries'][0]
        self.assertEqual(entry['duplicates'], 1)
        self.assertEqual(entry['unique_entries'], 3)
        self.assertEqual(entry['empty_lines'], 1)
        self.assertEqual(entry['invalid_utf8'], 1)
        self.assertEqual(entry['credential_like_lines'], 1)
        self.assertTrue(entry['checksum_matches'])
        self.assertNotIn('synthetic-weak', json.dumps(result))
        self.assertNotIn(str(self.words), json.dumps(result))

    def test_catalog_checksum_mismatch(self):
        self.words.write_bytes(b'changed\n')
        self.assertFalse(catalog(self.manifest)['dictionaries'][0]['checksum_matches'])

    def test_catalog_rejects_unknown_fields(self):
        self.manifest.write_text('{"schema_version":1,"dictionaries":[],"command":"bad"}')
        with self.assertRaises(ValidationError):
            catalog(self.manifest)

    def test_dictionary_bounds(self):
        self.words.write_bytes(b'x' * 4097)
        with self.assertRaises(ValidationError):
            list(dictionary_lines(self.words))
        with patch('lab.resources.MAX_LINES', 1):
            self.words.write_bytes(b'one\ntwo\n')
            with self.assertRaises(ValidationError):
                list(dictionary_lines(self.words))

    def test_policy_redacts_and_does_not_derive_hashes(self):
        secret = 'synthetic-weak'
        with patch('hashlib.sha256', side_effect=AssertionError('Do not hash passwords')):
            result = evaluate_password(secret, self.words)
        self.assertEqual(result['checks'][0]['status'], 'fail')
        self.assertEqual(result['checks'][1]['status'], 'fail')
        self.assertNotIn(secret, json.dumps(result))
        self.assertEqual(evaluate_password('an unlisted synthetic phrase', self.words)['checks'][1]['status'], 'pass')

    def test_policy_bounds(self):
        for password, minimum in [('x' * 1025, 15), ('test', 1), ('test', True)]:
            with self.subTest(minimum=minimum), self.assertRaises(ValidationError):
                evaluate_password(password, self.words, minimum)

    def test_benchmark_is_bounded(self):
        result = benchmark(20, 1)
        self.assertEqual(result['completed_samples'], 20)
        self.assertEqual(result['passing_fixtures'], 10)
        self.assertEqual(result['failing_fixtures'], 10)
        for samples, seconds in [(10001, 1), (0, 1), (1, 6), (1, float('nan'))]:
            with self.assertRaises(ValidationError):
                benchmark(samples, seconds)

    def test_beacon_analysis_deduplicates(self):
        result = analyze_capture(self.capture)
        self.assertEqual(result['observations'][0]['beacon_count'], 2)
        self.assertEqual(result['observations'][0]['pmf'], 'required')
        self.assertEqual(result['capture_sha256'], hashlib.sha256(self.capture.read_bytes()).hexdigest())
        self.assertEqual(len(result['observations']), 1)

    def test_big_endian_and_radiotap(self):
        self.capture.write_bytes(pcap([beacon()], endian='>'))
        self.assertEqual(analyze_capture(self.capture)['packet_count'], 1)
        radiotap = b'\x00\x00\x09\x00\x02\x00\x00\x00\x10'
        self.capture.write_bytes(pcap([radiotap + beacon() + b'FCS!'], linktype=127))
        self.assertEqual(analyze_capture(self.capture)['observations'][0]['bssid'], BSSID)

    def test_rsn_modes(self):
        for suites, expected in [((2,), 'wpa2-personal'), ((8,), 'wpa3-personal'), ((2, 8), 'wpa2-wpa3-personal'), ((1,), 'rsn-enterprise'), ((99,), 'unknown')]:
            self.assertEqual(_rsn(rsn(suites))[0], expected)
        self.assertEqual(_rsn(rsn(caps=0x80))[1], 'optional')
        with self.assertRaises(ValidationError):
            _rsn(rsn(caps=0x40))

    def test_radiotap_malformed_flags_and_extensions(self):
        for raw in (b'', b'\x00\x00\x08\x00\x01\x00\x00\x00',
                    b'\x00\x00\x08\x00\x02\x00\x00\x00',
                    b'\x00\x00\x08\x00\x00\x00\x00\x80',
                    b'\x00\x00\x09\x00\x02\x00\x00\x00\x40' + beacon()):
            with self.subTest(raw=raw[:8]), self.assertRaises(ValidationError):
                _radiotap(raw)

    def test_structurally_valid_beacon_requires_consistent_privacy(self):
        frame = bytearray(beacon())
        frame[34] = 0
        with self.assertRaises(ValidationError):
            _beacon(frame)

    def test_benchmark_deadline_stops_work(self):
        with patch('lab.toolkit.time.perf_counter', side_effect=[0.0, 1.0, 1.1]):
            self.assertEqual(benchmark(100, 0.1)['completed_samples'], 0)

    def test_open_hidden_and_nonutf8_ssids(self):
        for ssid in (b'', b'\xff\x00'):
            item = _beacon(beacon(ssid=ssid, akms=None))
            self.assertEqual(item['ssid_hex'], ssid.hex())
            self.assertEqual(item['security'], 'open')

    def test_payloads_are_ignored(self):
        self.capture.write_bytes(pcap([b'\x08\x00' + b'synthetic-password-payload']))
        result = analyze_capture(self.capture)
        self.assertEqual(result['ignored_packets'], 1)
        self.assertEqual(result['observations'], [])
        self.assertNotIn('synthetic-password-payload', json.dumps(result))

    def test_malformed_beacon_not_trusted(self):
        self.capture.write_bytes(pcap([beacon()[:-1], b'\x80\x00']))
        result = analyze_capture(self.capture)
        self.assertEqual(result['malformed_or_truncated'], 2)
        self.assertEqual(result['observations'], [])

    def test_unsupported_and_truncated_capture(self):
        for raw in (b'pcapng', pcap([beacon()])[:-3], pcap([], linktype=1)):
            self.capture.write_bytes(raw)
            with self.assertRaises(ValidationError):
                analyze_capture(self.capture)

    def test_capture_limits(self):
        with patch('lab.capture.MAX_PACKETS', 1), self.assertRaises(ValidationError):
            analyze_capture(self.capture)
        with patch('lab.capture.MAX_CAPTURE_BYTES', 10), self.assertRaises(ValidationError):
            analyze_capture(self.capture)

    def test_baseline_match_and_changes(self):
        capture = analyze_capture(self.capture)
        self.assertEqual(compare_baseline(capture, baseline())['findings'], [])
        data = baseline()
        data['approved_aps'][0]['pmf'] = 'optional'
        self.assertEqual(compare_baseline(capture, data)['findings'][0]['check_id'], 'AP-POLICY-CHANGED')
        data['approved_aps'][0]['bssid'] = '02:00:00:00:00:02'
        checks = {f['check_id'] for f in compare_baseline(capture, data)['findings']}
        self.assertEqual(checks, {'AP-UNEXPECTED', 'AP-NOT-OBSERVED'})

    def test_baseline_authorization_and_duplicates(self):
        data = baseline()
        data['scope']['authorized'] = False
        with self.assertRaises(ValidationError):
            compare_baseline(analyze_capture(self.capture), data)
        data = baseline()
        data['approved_aps'] *= 2
        with self.assertRaises(ValidationError):
            compare_baseline(analyze_capture(self.capture), data)

    def test_combined_retains_evidence_types(self):
        report = combined(Path(__file__).resolve().parent.parent / 'lab/examples/inventory.json', self.capture, manifest=self.manifest)
        self.assertEqual(len(report['reports']), 3)
        self.assertEqual(report['reports'][0]['assessment_type'], 'offline-declarations')
        self.assertEqual(report['reports'][1]['assessment_type'], 'offline-beacon-analysis')

    def test_cli_output_is_private_and_never_overwrites(self):
        output = self.root / 'report.json'
        self.assertEqual(main(['--output', str(output), 'benchmark', '--samples', '10']), 0)
        before = output.read_bytes()
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(['--output', str(output), 'benchmark']), 2)
        self.assertEqual(output.read_bytes(), before)

    def test_cli_rejects_output_symlinks_and_redacts_errors(self):
        output = self.root / 'output'
        output.symlink_to(self.words)
        before = self.words.read_bytes()
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors):
            self.assertEqual(main(['--output', str(output), 'catalog', str(self.manifest)]), 2)
        self.assertNotIn(str(self.words), errors.getvalue())
        self.assertEqual(self.words.read_bytes(), before)

    def test_cli_policy_rejects_noninteractive_passwords(self):
        with patch('sys.stdin.isatty', return_value=False), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(['policy', '--blocklist', str(self.words)]), 2)

    def test_markdown_escapes_hostile_metadata(self):
        result = markdown(dict(assessment_type='test', text='</pre><script>bad</script>'))
        self.assertNotIn('<script>', result)
        self.assertIn('&lt;script&gt;', result)

    def test_offline_operations_never_open_network_or_subprocess(self):
        with patch.object(socket, 'socket', side_effect=AssertionError('network')), patch('subprocess.Popen', side_effect=AssertionError('process')):
            catalog(self.manifest)
            analyze_capture(self.capture)
            evaluate_password('synthetic', self.words)
            benchmark(10)


if __name__ == '__main__':
    unittest.main()
