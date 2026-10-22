"""Safe regression tests: section scope, backups, metadata, PHP CLI parsing."""
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from php2shell.defender import defend, transform

class IniScopeTests(unittest.TestCase):
    def test_insert_before_first_non_php_section(self):
        result = transform('[custom]\nfoo=bar\n', {'session.upload_progress.enabled': '0'})
        self.assertTrue(result.startswith('session.upload_progress.enabled = 0\n[custom]'))
    def test_insert_inside_php_section(self):
        result = transform('[PHP]\nmemory_limit=128M\n[custom]\nfoo=bar\n', {'session.upload_progress.enabled':'0'})
        self.assertIn('session.upload_progress.enabled = 0\n[custom]', result)
    def test_outside_scope_setting_refused(self):
        with self.assertRaises(ValueError):
            transform('[custom]\nsession.upload_progress.enabled=1\n', {'session.upload_progress.enabled':'0'})
    def test_crlf_and_idempotence(self):
        original='[PHP]\r\nmemory_limit=128M\r\n[custom]\r\nx=1\r\n'
        once=transform(original, {'session.upload_progress.enabled':'0'})
        self.assertEqual(once, transform(once, {'session.upload_progress.enabled':'0'}))
        self.assertNotIn('\n', once.replace('\r\n', ''))
    def test_duplicate_php_sections_refused(self):
        with self.assertRaises(ValueError):
            transform('[PHP]\nx=1\n[PHP]\ny=2\n', {'session.upload_progress.enabled':'0'})

class SafeApplyTests(unittest.TestCase):
    def test_mode_backup_content_and_repeat(self):
        if os.name == 'nt': self.skipTest('Windows apply disabled')
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'php.ini'; data=b'[PHP]\nmemory_limit=128M\n[Date]\ndate.timezone=UTC\n'
            p.write_bytes(data); os.chmod(p, 0o640)
            result=defend(str(p), '8.4.26', apply=True, acknowledge=True)
            b=Path(result['backup'])
            self.assertEqual(b.read_bytes(), data)
            self.assertEqual(stat.S_IMODE(b.stat().st_mode), 0o640)
            self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o640)
            self.assertIn('session.upload_progress.enabled = 0\n[Date]',p.read_text())
            self.assertFalse(defend(str(p), '8.4.26', apply=True, acknowledge=True)['changed'])
            self.assertEqual(list(Path(d).glob('*.php2shell-backup-*')).__len__(),1)
    def test_hardlink_refused(self):
        if os.name == 'nt': self.skipTest('Windows apply disabled')
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'php.ini'; p.write_text('[PHP]\nx=1\n')
            os.link(p, Path(d)/'linked.ini')
            with self.assertRaisesRegex(ValueError, 'Hard-linked'):
                defend(str(p), '8.4.26', apply=True, acknowledge=True)
            self.assertEqual(p.read_text(),'[PHP]\nx=1\n')
    def test_xattr_refused_if_supported(self):
        if os.name == 'nt' or not hasattr(os, 'setxattr'): self.skipTest('xattr not available')
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'php.ini'; p.write_text('x=1\n')
            try: os.setxattr(p, 'user.php2shell_test', b'1')
            except OSError: self.skipTest('xattr not enabled on test filesystem')
            with self.assertRaisesRegex(ValueError, 'extended attributes'):
                defend(str(p), '8.4.26', apply=True, acknowledge=True)
            self.assertEqual(p.read_text(), 'x=1\n')
    def test_windows_apply_refused(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'php.ini'; p.write_text('x=1\n')
            with patch('php2shell.defender.platform.system',return_value='Windows'):
                with self.assertRaisesRegex(ValueError,'Windows apply'):
                    defend(str(p), '8.4.26', apply=True, acknowledge=True)
    @unittest.skipIf(os.name == "nt", "Windows automatic apply is intentionally disabled")
    def test_real_php_ini_interpretation_cli(self):
        php=shutil.which('php')
        if not php: self.skipTest('PHP CLI unavailable')
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'php.ini'
            p.write_text('[PHP]\nmemory_limit=128M\n[custom]\nx=1\n')
            defend(str(p), '8.4.26', apply=True, acknowledge=True)
            r=subprocess.run([php,'-c',str(p),'-r','echo ini_get("session.upload_progress.enabled");'],capture_output=True,text=True,timeout=10)
            self.assertEqual(r.returncode,0,r.stderr)
            self.assertEqual(r.stdout.strip(),'0')

if __name__ == '__main__': unittest.main()
