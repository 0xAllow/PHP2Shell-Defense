import json
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from php2shell.compromise import inspect_log, inspect_webroot, read_tail, scan, main


class CompromiseTests(unittest.TestCase):
    def test_log_indicators(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / 'error.log'
            f.write_text('PHP Fatal error: Allowed memory size of 1024 bytes exhausted\n'
                         'child 42 exited on signal 11 (SIGSEGV)\n'
                         '"POST /upload HTTP/1.1" 500 123\n')
            hits, error = inspect_log(f)
            self.assertIsNone(error)
            self.assertEqual({h['category'] for h in hits},
                             {'php_memory_exhaustion', 'worker_crash', 'http_post_error'})

    def test_clean_log(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / 'access.log'
            f.write_text('"GET / HTTP/1.1" 200 512\n')
            hits, error = inspect_log(f)
            self.assertEqual(hits, [])
            self.assertIsNone(error)

    def test_recent_web_file_and_symlink_skip(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            recent = root / 'index.php'
            recent.write_text('<?php echo 1;')
            (root / 'alias.php').symlink_to(recent)
            hits, errors = inspect_webroot(root, datetime(2026, 10, 17, tzinfo=timezone.utc))
            self.assertEqual(len(hits), 1)
            self.assertEqual(Path(hits[0]['location']), recent)
            self.assertFalse(errors)

    def test_missing_log_reports_incomplete(self):
        with tempfile.TemporaryDirectory() as d:
            result = scan([str(Path(d) / 'missing')], [], datetime.now(timezone.utc), False)
            self.assertEqual(result['assessment'], 'NO_INDICATORS_IN_CHECKED_SOURCES')
            self.assertTrue(result['errors'])
            self.assertFalse(result['compromise_confirmed'])

    def test_log_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            orig = Path(d) / 'orig'
            orig.write_text('safe')
            link = Path(d) / 'link'
            link.symlink_to(orig)
            hits, error = inspect_log(link)
            self.assertFalse(hits)
            self.assertIsNotNone(error)

    def test_json_cli_exit(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'err.log'
            p.write_text('Out of memory\n')
            output = StringIO()
            with redirect_stdout(output):
                rc = main(['--log', str(p), '--no-processes', '--json'])
            self.assertEqual(rc, 2)
            self.assertEqual(json.loads(output.getvalue())['assessment'], 'REVIEW_REQUIRED')

if __name__ == '__main__':
    unittest.main()
