"""Read-only local incident triage, not a determination of compromise."""
import argparse
from datetime import datetime, timezone, timedelta
import json
import os
from pathlib import Path
import re
import sys
import subprocess

# Patterns are generic behavioral indicators, not signatures proving PHP2Shell.
ERROR_PATTERNS = (
    ('php_memory_exhaustion', re.compile(r'Allowed memory size of .* exhausted|Out of memory', re.I), 'medium'),
    ('worker_crash', re.compile(r'child .* exited on signal (?:11|6)|segmentation fault|segfault|SIGSEGV|SIGABRT', re.I), 'medium'),
)
HTTP_PATTERN = re.compile(r'"POST [^"\r\n]{1,120} HTTP/[^"\r\n]+"\s+(?:400|413|500|502|503)\b')
SUSPICIOUS_PROCESS_NAMES = {'sh', 'bash', 'dash', 'zsh', 'curl', 'wget', 'nc', 'ncat', 'socat', 'python', 'python3', 'perl', 'ruby'}
PHP_PROCESS_HINTS = ('php-fpm', 'php-cgi', 'apache2', 'httpd', 'lsphp', 'frankenphp')
MAX_LOG_BYTES = 8 * 1024 * 1024
MAX_FILE_BYTES = 512 * 1024
MAX_FILES = 20000
MAX_FINDINGS = 500


def finding(category, severity, location, evidence, note):
    return {'category': category, 'severity': severity, 'location': location,
            'evidence': evidence[:240], 'explanation': note}


def read_tail(path, limit=MAX_LOG_BYTES):
    """Return bounded decoded tail of regular files, rejecting symlinks and devices."""
    import stat
    if Path(path).is_symlink():
        raise ValueError('symlink log paths are refused')
    fd = os.open(str(path), os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError('not a regular file')
        os.lseek(fd, max(0, st.st_size - limit), os.SEEK_SET)
        return os.read(fd, limit).decode('utf-8', errors='replace')
    finally:
        os.close(fd)


def inspect_log(path):
    results = []
    try:
        data = read_tail(path)
    except (OSError, ValueError) as exc:
        return [], f'{path}: {exc}'
    for number, line in enumerate(data.splitlines(), 1):
        for name, regex, severity in ERROR_PATTERNS:
            if regex.search(line):
                results.append(finding(name, severity, f'{path}:tail-line-{number}',
                                       line, 'Correlate with timestamps, access logs and worker telemetry.'))
        if HTTP_PATTERN.search(line):
            results.append(finding('http_post_error', 'low', f'{path}:tail-line-{number}',
                                   line, 'POST error response is nonspecific; correlate with request metadata.'))
        if len(results) >= MAX_FINDINGS:
            break
    return results, None


def inspect_webroot(root, since, max_files=MAX_FILES):
    results, errors = [], []
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        return results, [f'{root}: missing, symlink or not a directory']
    seen = 0
    def onerror(exc):
        errors.append(str(exc))
    for directory, dirs, files in os.walk(root, followlinks=False, onerror=onerror):
        dirs[:] = sorted(d for d in dirs if not (Path(directory) / d).is_symlink())
        for name in sorted(files):
            p = Path(directory) / name
            if p.suffix.lower() not in ('.php', '.phtml', '.phar') or p.is_symlink():
                continue
            seen += 1
            if seen > max_files:
                errors.append(f'{root}: scan cap of {max_files} PHP files reached; coverage incomplete')
                return results, errors
            try:
                st = p.stat()
                if not p.is_file():
                    continue
                if st.st_mtime >= since.timestamp():
                    results.append(finding('recent_php_file', 'low', str(p),
                        datetime.fromtimestamp(st.st_mtime, timezone.utc).isoformat(),
                        'Recent PHP file is not necessarily malicious; compare to approved deployments and backups.'))
            except OSError as exc:
                errors.append(f'{p}: {exc}')
            if len(results) >= MAX_FINDINGS:
                errors.append('finding cap reached; coverage incomplete')
                return results, errors
    return results, errors


def inspect_processes(proc='/proc'):
    """Linux /proc snapshot. Never executes processes or accesses process memory."""
    root = Path(proc)
    results, errors = [], []
    if not root.is_dir():
        return results, ['Linux /proc unavailable; process coverage incomplete']
    table = {}
    for p in root.iterdir():
        if not p.name.isdecimal():
            continue
        try:
            status = (p / 'status').read_text(errors='replace')
            m = re.search(r'^PPid:\s*(\d+)', status, re.M)
            if not m:
                continue
            raw = (p / 'cmdline').read_bytes()[:4096]
            args = [s.decode('utf-8', 'replace') for s in raw.split(b'\0') if s]
            if args:
                table[int(p.name)] = (int(m.group(1)), args)
        except (OSError, ValueError):
            continue  # vanished/inaccessible processes; best effort
    for pid, (ppid, args) in table.items():
        parent = table.get(ppid)
        if not parent:
            continue
        pargs = ' '.join(parent[1]).lower()
        if not any(h in pargs for h in PHP_PROCESS_HINTS):
            continue
        child = Path(args[0]).name.lower()
        if child not in SUSPICIOUS_PROCESS_NAMES:
            continue
        results.append(finding('unexpected_web_child', 'high', f'pid:{pid} ppid:{ppid}',
                               ' '.join(args)[:240],
                               'Investigate process ancestry; web applications sometimes legitimately spawn tools.'))
        if len(results) >= MAX_FINDINGS:
            errors.append('process finding cap reached')
            break
    return results, errors



def inspect_windows_processes(timeout=12):
    """Read-only Windows CIM process snapshot; PowerShell must be installed."""
    exe = __import__('shutil').which('powershell.exe') or __import__('shutil').which('pwsh.exe')
    if not exe:
        return [], ['PowerShell not found; Windows process coverage unavailable']
    script = ('Get-CimInstance Win32_Process | '
              'Select-Object ProcessId,ParentProcessId,Name,CommandLine | '
              'ConvertTo-Json -Compress -Depth 3')
    try:
        completed = subprocess.run([exe, '-NoProfile', '-NonInteractive', '-Command', script],
                                   capture_output=True, text=True, timeout=timeout, check=False)
        if completed.returncode or len(completed.stdout) > 2_000_000:
            return [], ['Windows process query failed or output exceeded limit']
        processes = json.loads(completed.stdout)
        if isinstance(processes, dict):
            processes = [processes]
        table = {int(x['ProcessId']): x for x in processes if x.get('ProcessId') is not None}
        results = []
        for pid, item in table.items():
            parent = table.get(item.get('ParentProcessId'))
            if parent is None:
                continue
            parent_name = (parent.get('Name') or '').lower()
            if not any(h in parent_name for h in ('php', 'httpd', 'apache', 'nginx', 'w3wp', 'iis')):
                continue
            name = Path((item.get('Name') or '').lower()).stem
            if name not in SUSPICIOUS_PROCESS_NAMES and name not in ('cmd', 'powershell', 'pwsh', 'certutil', 'bitsadmin'):
                continue
            results.append(finding('unexpected_web_child', 'high', f'pid:{pid}',
                (item.get('CommandLine') or item.get('Name') or '')[:240],
                'Review process lineage and service context; this is not proof of intrusion.'))
            if len(results) >= MAX_FINDINGS:
                return results, ['process finding cap reached']
        return results, []
    except (OSError, ValueError, subprocess.TimeoutExpired, TypeError, KeyError) as exc:
        return [], [f'Windows process inspection unavailable: {exc}']


def scan(logs, roots, since, processes=True):
    findings, errors, checked = [], [], []
    for path in logs:
        items, error = inspect_log(path)
        findings.extend(items)
        checked.append({'kind': 'log', 'path': str(path)})
        if error:
            errors.append(error)
    for path in roots:
        items, errs = inspect_webroot(path, since)
        findings.extend(items)
        errors.extend(errs)
        checked.append({'kind': 'webroot', 'path': str(path)})
    if processes:
        items, errs = inspect_windows_processes() if os.name == 'nt' else inspect_processes()
        findings.extend(items)
        errors.extend(errs)
        checked.append({'kind': 'processes', 'path': 'Windows CIM' if os.name == 'nt' else '/proc'})
    findings = findings[:MAX_FINDINGS]
    return {
        'tool': 'PHP2Shell Compromise Assessment',
        'author': '0xAllow',
        'scope': 'read-only host triage, no exploit or network scanning',
        'since_utc': since.isoformat(), 'checked': checked,
        'findings': findings, 'errors': errors,
        'assessment': ('REVIEW_REQUIRED' if findings else 'NO_INDICATORS_IN_CHECKED_SOURCES'),
        'compromise_confirmed': False,
        'limitations': [
            'Neither a match nor a clean result establishes whether PHP2Shell exploitation occurred.',
            'Indicators are generic and may be false positives; timestamps must be independently correlated.',
            'Access logs often lack multipart body metadata; malicious requests may have normal status codes.',
            'Limited to supplied paths and accessible host processes; not containers, deleted files, or in-memory-only payloads.',
            'Checks only a bounded tail of each log and bounded PHP file inventory.',
            'No known-good file integrity baseline, EDR, forensic acquisition, cron/account audit, or network telemetry.',
        ],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description='Read-only local compromise triage for PHP2Shell response')
    parser.add_argument('--log', action='append', default=[], help='Explicit local access/error log, repeatable')
    parser.add_argument('--webroot', action='append', default=[], help='Explicit webroot, repeatable')
    parser.add_argument('--since', default='2026-10-17', help='UTC YYYY-MM-DD for recent PHP files (default 2026-10-17)')
    parser.add_argument('--no-processes', action='store_true', help='Skip optional host process inventory')
    parser.add_argument('--json', action='store_true', help='Machine-readable JSON')
    args = parser.parse_args(argv)
    try:
        since = datetime.strptime(args.since, '%Y-%m-%d').replace(tzinfo=timezone.utc)
    except ValueError:
        parser.error('--since must be an ISO date (YYYY-MM-DD)')
    if not args.log and not args.webroot and args.no_processes:
        parser.error('provide --log or --webroot unless process inspection is enabled')
    result = scan(args.log, args.webroot, since, not args.no_processes)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print('Assessment:', result['assessment'], '| findings:', len(result['findings']))
        for item in result['findings']:
            print(f"[{item['severity']}] {item['category']} {item['location']} {item['evidence']}")
        for error in result['errors']:
            print('INCOMPLETE:', error, file=sys.stderr)
        print('No findings does NOT prove the host is uncompromised.')
    return 3 if result['errors'] else (2 if result['findings'] else 0)

if __name__ == '__main__':
    sys.exit(main())
