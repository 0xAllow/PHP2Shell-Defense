"""Cross-platform standard-library host and resource preflight, no mutations."""
import argparse
import json
import os
import platform
import shutil
import sys
import tempfile
from pathlib import Path


def check(path=None, minimum_free_mb=100):
    target = Path(path or tempfile.gettempdir()).resolve()
    results = []
    def add(name, ok, detail):
        results.append({'check': name, 'ok': bool(ok), 'detail': str(detail)})
    add('python_version', sys.version_info >= (3, 9), platform.python_version())
    add('operating_system', sys.platform.startswith(('linux', 'win32')), platform.platform())
    add('directory_exists', target.is_dir(), str(target))
    try:
        free = shutil.disk_usage(target).free // (1024 * 1024)
        add('available_disk', free >= minimum_free_mb, f'{free} MiB available; minimum {minimum_free_mb} MiB')
    except OSError as exc:
        add('available_disk', False, exc)
    add('can_read_directory', os.access(target, os.R_OK), str(target))
    # Only checks the chosen working directory; defender has separate file-specific checks.
    return {'tool': 'PHP2Shell Defense - Preflight', 'author': '0xAllow',
            'platform': sys.platform, 'checks': results,
            'ready_for_local_audit': all(x['ok'] for x in results),
            'note': 'Preflight is not a guarantee of PHP configuration safety or coverage.'}


def main(argv=None):
    p = argparse.ArgumentParser(description='Read-only local resource preflight')
    p.add_argument('--path', help='Directory for free disk assessment')
    p.add_argument('--min-free-mb', type=int, default=100)
    p.add_argument('--json', action='store_true')
    a = p.parse_args(argv)
    if a.min_free_mb < 0:
        p.error('--min-free-mb must be nonnegative')
    result = check(a.path, a.min_free_mb)
    if a.json:
        print(json.dumps(result, indent=2))
    else:
        for item in result['checks']:
            print(('PASS' if item['ok'] else 'FAIL') + ' ' + item['check'] + ': ' + item['detail'])
    return 0 if result['ready_for_local_audit'] else 3


if __name__ == '__main__':
    sys.exit(main())
