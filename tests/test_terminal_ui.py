"""Presentation-only CLI tests; never invoke main or wireless tools."""
import os
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parent.parent


class TerminalUiTests(unittest.TestCase):
    def preview(self, columns='80', lines='40', **extra):
        env = dict(os.environ, COLUMNS=columns, LINES=lines, TERM='dumb', **extra)
        return subprocess.run(['bash', 'airgeddon.sh', '--ui-preview'], cwd=ROOT,
                              env=env, text=True, capture_output=True, check=True)

    def test_large_banner_and_truthful_status(self):
        result = self.preview(columns='140')
        self.assertIn('WIRELESS SECURITY PLATFORM', result.stdout)
        self.assertIn('DRAGON / LAB CONSOLE', result.stdout)
        self.assertIn('SYSTEM OVERVIEW', result.stdout)
        self.assertIn('Authorized testing only', result.stdout)
        self.assertIn('PREVIEW ONLY', result.stdout)
        self.assertIn('Interface: not selected', result.stdout)
        self.assertIn('[07] Evil Twin', result.stdout)
        self.assertNotIn('Line:', result.stdout)
        self.assertEqual(result.stderr, '')

    def test_help_exits_without_starting_a_session(self):
        result = subprocess.run(['bash', 'airgeddon.sh', '--help'], cwd=ROOT,
                                text=True, capture_output=True, check=True)
        self.assertIn('--ui-preview', result.stdout)
        self.assertIn('python3 -m lab.assess', result.stdout)
        self.assertEqual(result.stderr, '')

    def test_compact_and_narrow_layouts(self):
        compact = self.preview(lines='24').stdout
        self.assertIn('<=={>', compact)
        self.assertNotIn('____/', compact)
        narrow = self.preview(columns='32').stdout
        self.assertTrue(all(len(line) <= 32 for line in narrow.splitlines()))

    def test_invalid_terminal_size_is_bounded(self):
        for width in ('invalid', '99999999999999999', '-5', '0', '008'):
            with self.subTest(width=width):
                result = self.preview(columns=width)
                self.assertEqual(result.stderr, '')
                self.assertTrue(all(len(line) <= 100 for line in result.stdout.splitlines()))

    def test_redirected_output_contains_no_ansi(self):
        self.assertNotIn('\x1b', self.preview(NO_COLOR='1').stdout)

    def test_padded_menu_labels_dispatch_without_hardware(self):
        # Stub presentation, bookkeeping, and the selected action; never run a tool.
        result = subprocess.run(['bash', '-c', r'''
source ./airgeddon.sh
debug_print() { :; }
clear() { :; }
print_cli_dashboard() { cli_dashboard_complete=1; }
initialize_menu_and_print_selections() { :; }
select_interface() { printf 'SELECTED-INTERFACE'; exit 0; }
main_menu <<< '01'
'''], cwd=ROOT, text=True, capture_output=True, check=True)
        self.assertEqual(result.stdout, 'SELECTED-INTERFACE')

    def test_nonenglish_preserves_legacy_fallback(self):
        result = subprocess.run(['bash', '-c', r'''
source ./airgeddon.sh
debug_print() { :; }
language=GERMAN
initialize_colors
print_cli_dashboard
printf 'fallback=%s' "${cli_dashboard_complete}"
'''], cwd=ROOT, text=True, capture_output=True, check=True)
        self.assertIn('fallback=0', result.stdout)
        self.assertNotIn('SYSTEM OVERVIEW', result.stdout)

    def test_untrusted_status_text_is_not_interpreted(self):
        result = subprocess.run(['bash', '-c', r'''
source ./airgeddon.sh
debug_print() { :; }
initialize_colors
interface=$'test\033[31m\\n'
ifacemode=Managed
print_cli_dashboard
'''], cwd=ROOT, text=True, capture_output=True, check=True,
            env=dict(os.environ, TERM='dumb', NO_COLOR='1'))
        self.assertNotIn('\x1b', result.stdout)
        self.assertIn('test[31m\\n', result.stdout)
        self.assertIn('MODE Managed', result.stdout)


if __name__ == '__main__':
    unittest.main()
