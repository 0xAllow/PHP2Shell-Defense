"""Local executable discovery and advisory-level triage."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import platform
from .core import assess

NAME = re.compile(r'^php(?:-?(?:cgi|fpm))?(?:\d+(?:\.\d+)?)?$')
SEARCH_DIRS = ['/usr/bin', '/usr/local/bin', '/opt/homebrew/bin', '/usr/sbin', '/usr/local/sbin']
WINDOWS_DIRS = [r'C:\php', r'C:\tools\php', r'C:\xampp\php', r'C:\laragon\bin\php', r'C:\Program Files\PHP']


def discover(directories=None):
    discovered = set()
    for d in (directories if directories is not None else (WINDOWS_DIRS if platform.system() == 'Windows' else SEARCH_DIRS)):
        folder = Path(d)
        if not folder.is_dir():
            continue
        try:
            for path in folder.iterdir():
                if NAME.fullmatch(path.stem if platform.system() == 'Windows' and path.suffix.lower() == '.exe' else path.name) and path.is_file() and (platform.system() == 'Windows' or os.access(path, os.X_OK)):
                    discovered.add(str(path.resolve()))
        except PermissionError:
            continue
    path_php = shutil.which('php')
    if path_php:
        discovered.add(str(Path(path_php).resolve()))
    return sorted(discovered)


def inspect(binary, timeout=5):
    try:
        result = subprocess.run([binary, '-v'], capture_output=True, text=True, timeout=timeout, check=False)
        output = (result.stdout + '\n' + result.stderr).strip()
        if result.returncode != 0 or not output.startswith('PHP '):
            return {'binary': binary, 'status': 'inspection_failed', 'detail': output[:250]}
        version = assess(output.splitlines()[0])
        return {'binary': binary, **version}
    except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
        return {'binary': binary, 'status': 'inspection_failed', 'detail': str(exc)}


def main(argv=None):
    parser = argparse.ArgumentParser(description='Non-exploitative local PHP2Shell inventory scanner')
    parser.add_argument('--version', action='append', dest='versions', help='Assess a PHP version without executing PHP; repeatable')
    parser.add_argument('--binary', action='append', dest='binaries', help='Inspect specified PHP executable; repeatable')
    parser.add_argument('--json', action='store_true', help='Output JSON')
    args = parser.parse_args(argv)
    entries = []
    for v in args.versions or []:
        try:
            entries.append({'input': v, **assess(v)})
        except ValueError as exc:
            entries.append({'input': v, 'status': 'invalid_input', 'detail': str(exc)})
    for b in (args.binaries if args.binaries is not None else ([] if args.versions else discover())):
        entries.append(inspect(b))
    result = {'tool': 'PHP2Shell Scanner', 'cves': ['CVE-2026-109618', 'CVE-2026-109619'], 'scope': 'local trusted PHP executable versions only; Windows and Linux best-effort discovery', 'results': entries, 'limitations': ['Version comparison cannot verify vendor backports.', 'CLI PHP may differ from web-served PHP.', 'Container images and embedded runtimes require separate review.']}
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        for item in entries:
            print(f"{item.get('binary', item.get('input'))}: {item['status']} | {item.get('version', item.get('detail', ''))}")
        if not entries:
            print('No PHP executables found; this does not prove no PHP deployment exists.')
        print('Warning: review vendor backports, web runtimes and containers separately.')
    return 2 if any(x['status'] in ('potentially_vulnerable', 'legacy_review_required') for x in entries) else (3 if not entries or any(x['status'] in ('inspection_failed', 'invalid_input', 'unknown_branch') for x in entries) else 0)

if __name__ == '__main__':
    sys.exit(main())
