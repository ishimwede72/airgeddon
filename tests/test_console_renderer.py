"""Reference-layout tests; no hardware dependencies or real operations."""
import unittest
from unittest.mock import patch

from lab.console import MENU, box, clean, paint, render


class ConsoleRendererTests(unittest.TestCase):
    def render(self, width, height=40):
        return render(width, height, '12.10', 'wlan-test', 'unknown', 'tmux', True)

    def test_three_columns_follow_reference(self):
        lines = self.render(140)
        text = '\n'.join(lines)
        for title in ('DRAGON / LAB CONSOLE', 'SYSTEM OVERVIEW', 'WIRELESS STATUS', 'NETWORK INFO', 'QUICK ACTIONS', 'OFFLINE DEFENSIVE TOOLS'):
            self.assertIn(title, text)
        self.assertTrue(any('DRAGON / LAB CONSOLE' in line and 'SYSTEM OVERVIEW' in line for line in lines))
        self.assertLessEqual(len(lines), 38)

    def test_all_numbered_actions_remain_visible(self):
        for width in (80, 94, 132, 160):
            text = '\n'.join(self.render(width))
            for key, label in MENU:
                self.assertIn(f'[{key}] {label}', text)

    def test_responsive_width_and_height(self):
        for width in (1, 20, 32, 80, 94, 131, 132, 160, 999):
            for height in (24, 30, 38, 50):
                lines = self.render(width, height)
                self.assertTrue(all(len(line) <= min(width, 160) for line in lines))
                self.assertLessEqual(len(lines), height)

    def test_no_invented_telemetry_or_version(self):
        text = '\n'.join(self.render(140))
        for bogus in ('15.0.0', 'Kali Linux 2026.3', 'READY', 'Connected', 'Monitor Ready', '47 Tests', '10.17.'):
            self.assertNotIn(bogus, text)
        self.assertIn('not queried', text)
        self.assertIn('not verified', text)
        self.assertIn('12.10', text)

    def test_no_escape_or_wide_text_injection(self):
        self.assertEqual(clean('\x1b[31m\r\n漢字'), '[31m??')
        lines = render(140, 40, '12.10', '\x1b[2J' + 'x' * 1000, 'Mode\nINJECTED', 'tmux')
        self.assertNotIn('\x1b', '\n'.join(lines))
        self.assertTrue(all(len(line) <= 140 for line in lines))

    def test_paint_contains_only_color_controls(self):
        import re
        text = '[01] Test | menu'
        colored = paint(text)
        self.assertIn('\x1b[1;31m', colored)
        self.assertEqual(re.sub(r'\x1b\[[0-9;]*m', '', colored), text)

    def test_renderer_never_opens_network_or_starts_processes(self):
        with patch('socket.socket', side_effect=AssertionError('network')), patch('subprocess.Popen', side_effect=AssertionError('process')):
            self.render(140)

    def test_box_is_fixed_width(self):
        self.assertTrue(all(len(line) == 34 for line in box('TITLE', ['x' * 100], 34)))


if __name__ == '__main__':
    unittest.main()
