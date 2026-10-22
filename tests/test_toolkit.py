import tempfile
import os
import unittest
from pathlib import Path
from unittest.mock import patch
from php2shell.core import assess, parse_version
from php2shell.defender import defend, transform
from php2shell.scanner import main
from contextlib import redirect_stdout
from io import StringIO

class VersionTests(unittest.TestCase):
    def test_boundaries(self):
        for branch, low, fixed in [("8.2", "34", "35"), ("8.3", "35", "36"), ("8.4", "26", "27"), ("8.5", "11", "12")]:
            self.assertEqual(assess(f'{branch}.{low}')['status'], 'potentially_vulnerable')
            self.assertEqual(assess(f'{branch}.{fixed}')['status'], 'patched_upstream')
    def test_old_and_future(self):
        self.assertEqual(assess('7.4.33')['status'], 'legacy_review_required')
        self.assertEqual(assess('8.6.0')['status'], 'unknown_branch')
    def test_parse(self):
        self.assertEqual(parse_version('PHP 8.5.12 (cli)'), (8, 5, 12))
        with self.assertRaises(ValueError):
            parse_version('abc')
    def test_cli(self):
        with redirect_stdout(StringIO()):
            self.assertEqual(main(['--version', '8.4.26', '--json']), 2)
            self.assertEqual(main(['--version', '8.4.27', '--json']), 0)
            self.assertEqual(main(['--version', 'oops', '--json']), 3)

class DefenderTests(unittest.TestCase):
    def test_transform_idempotent(self):
        src = '; comment\nsession.upload_progress.enabled = 1\n'
        first = transform(src, {'session.upload_progress.enabled': '0'})
        self.assertEqual(first, transform(first, {'session.upload_progress.enabled': '0'}))
    @unittest.skipIf(os.name == "nt", "Windows automatic apply is intentionally disabled")
    def test_plan_apply_backup(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / 'php.ini'
            original = 'memory_limit = 128M\nsession.upload_progress.enabled = 1\n'
            p.write_text(original)
            plan = defend(str(p), '8.5.11')
            self.assertTrue(plan['changed'])
            self.assertEqual(p.read_text(), original)
            with self.assertRaises(ValueError):
                defend(str(p), '8.5.11', apply=True)
            out = defend(str(p), '8.5.11', apply=True, acknowledge=True)
            self.assertEqual(Path(out['backup']).read_text(), original)
            self.assertIn('fatal_error_backtraces = 0', p.read_text())
            self.assertEqual(defend(str(p), '8.5.11', apply=True, acknowledge=True)['changed'], False)
    def test_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'real.ini'
            target.write_text('x=1\n')
            alias = Path(directory) / 'alias.ini'
            alias.symlink_to(target)
            with self.assertRaises(ValueError):
                defend(str(alias), '8.4.26')

if __name__ == '__main__':
    unittest.main()
