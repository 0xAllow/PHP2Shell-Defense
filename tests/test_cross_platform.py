import json
from io import StringIO
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import unittest
from php2shell import preflight, scanner, compromise, defender
from php2shell.__main__ import main

class CrossPlatformTests(unittest.TestCase):
    def test_preflight_valid_directory(self):
        with TemporaryDirectory() as d:
            self.assertTrue(preflight.check(d, 0)['ready_for_local_audit'])
    def test_preflight_invalid_path(self):
        with TemporaryDirectory() as d:
            self.assertFalse(preflight.check(str(Path(d) / 'missing'))['ready_for_local_audit'])
    def test_unified_cli(self):
        with redirect_stdout(StringIO()) as output:
            self.assertEqual(main(['scanner', '--version', '8.5.12', '--json']), 0)
        self.assertEqual(json.loads(output.getvalue())['results'][0]['status'], 'patched_upstream')
    def test_windows_discovery_exe(self):
        with TemporaryDirectory() as d:
            executable = Path(d) / 'php.exe'
            executable.write_bytes(b'test')
            with patch.object(scanner.platform, 'system', return_value='Windows'):
                self.assertIn(str(executable.resolve()), scanner.discover([d]))
    def test_windows_process_parent(self):
        fake = [{'ProcessId': 12, 'ParentProcessId': 0, 'Name': 'php-cgi.exe'},
                {'ProcessId': 13, 'ParentProcessId': 12, 'Name': 'cmd.exe', 'CommandLine': 'cmd.exe /c whoami'}]
        class Result:
            returncode = 0
            stdout = json.dumps(fake)
        with patch('shutil.which', return_value='powershell.exe'), patch.object(compromise.subprocess, 'run', return_value=Result()):
            found, errs = compromise.inspect_windows_processes()
        self.assertFalse(errs)
        self.assertEqual(found[0]['category'], 'unexpected_web_child')
    def test_windows_apply_refusal(self):
        with TemporaryDirectory() as d:
            p = Path(d) / 'php.ini'
            p.write_text('session.upload_progress.enabled = 1\n')
            with patch.object(defender.platform, 'system', return_value='Windows'):
                with self.assertRaisesRegex(ValueError, 'Windows apply'):
                    defender.defend(str(p), '8.4.26', apply=True, acknowledge=True)
            self.assertIn('= 1', p.read_text())
    def test_windows_process_failure_is_reported(self):
        with patch('shutil.which', return_value=None):
            found, errs = compromise.inspect_windows_processes()
        self.assertFalse(found)
        self.assertTrue(errs)

if __name__ == '__main__':
    unittest.main()
