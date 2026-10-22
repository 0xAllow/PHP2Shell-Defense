"""Careful, opt-in, atomic PHP ini mitigation helper. Not a vulnerability patch."""
import argparse
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import stat
import sys
import platform
import tempfile
from .core import assess

# Only conservative low-disruption mitigations are automated.
SETTINGS = {'session.upload_progress.enabled': '0', 'fatal_error_backtraces': '0'}
INI_LINE = re.compile(r'^(\s*)([;#]?\s*)([A-Za-z_][A-Za-z_.0-9]*)\s*=.*$')


SECTION_LINE = re.compile(r'^\s*\[([^]\r\n]+)\]\s*(?:[;#].*)?$')


def transform(data, settings):
    """Modify only the global / [PHP] scope; never append inside another section.

    Explicitly reject ambiguous settings in other named sections. Preservation of
    mixed scopes is more important than a seemingly successful but inert change.
    """
    lines = data.splitlines(keepends=True)
    newline = '\r\n' if '\r\n' in data else '\n'
    sections = []
    current = None
    php_start = None
    php_end = None
    first_section = len(lines)
    for index, line in enumerate(lines):
        m = SECTION_LINE.match(line.strip('\r\n'))
        if m:
            if first_section == len(lines):
                first_section = index
            if current == 'php' and php_end is None:
                php_end = index
            current = m.group(1).strip().lower()
            if current == 'php':
                if php_start is not None:
                    raise ValueError('Multiple [PHP] sections: manual review required')
                php_start = index
        sections.append(current)
    if php_start is not None and php_end is None:
        php_end = len(lines)
    target_section = 'php' if php_start is not None else None
    found = set()
    output = []
    for index, line in enumerate(lines):
        m = INI_LINE.match(line)
        if m and m.group(3).lower() in settings and not m.group(2).strip():
            name = m.group(3).lower()
            if sections[index] not in (None, 'php'):
                raise ValueError('Mitigation setting exists in a non-global INI section; manual review required')
            # [PHP] values take precedence over earlier global values in this file.
            output.append(f'{name} = {settings[name]}{newline}')
            found.add(name)
        else:
            output.append(line)
    additions = [f'{name} = {value}{newline}' for name, value in settings.items() if name not in found]
    if additions:
        insertion = php_end if php_start is not None else first_section
        if insertion > 0 and not output[insertion - 1].endswith(('\n', '\r')):
            output[insertion - 1] += newline
        output[insertion:insertion] = additions
    return ''.join(output)


def _check_metadata_for_replacement(p, info):
    """Fail closed on file metadata not preserved by atomic replacement."""
    if info.st_nlink != 1:
        raise ValueError('Hard-linked configuration: atomic replace would separate links')
    if hasattr(os, 'listxattr'):
        try:
            attrs = os.listxattr(p, follow_symlinks=False)
        except (OSError, NotImplementedError) as exc:
            raise ValueError('Cannot verify extended attributes / ACLs') from exc
        if attrs:
            raise ValueError('Config has extended attributes, ACLs or security labels; apply refused')
    else:
        raise ValueError('Extended attribute inspection unavailable: apply refused')
    # Refuse SELinux hosts even when this individual file lacks a user-visible label.
    enforce = Path('/sys/fs/selinux/enforce')
    try:
        if enforce.exists() and enforce.read_text().strip() == '1':
            raise ValueError('SELinux enforcing host: context-safe replace not validated')
    except OSError as exc:
        raise ValueError('Cannot inspect SELinux enforcement') from exc


def defend(path, version, apply=False, acknowledge=False):
    assessment = assess(version)
    if assessment['status'] == 'unknown_branch':
        raise ValueError('Unknown PHP branch: no safe version-specific configuration assumed')
    settings = {'session.upload_progress.enabled': '0'}
    if assessment['version'].startswith('8.5.'):
        settings['fatal_error_backtraces'] = '0'
    p = Path(path)
    if p.is_symlink():
        raise ValueError('Symlinks are refused; specify a regular, explicit php.ini file')
    if not p.is_file():
        raise ValueError('Configuration file does not exist or is not regular')
    original_stat = p.stat()
    if platform.system() == 'Windows' and apply:
        raise ValueError('Windows apply intentionally unsupported until ACL-preserving writes are validated; use dry-run and approved manual change control')
    if apply:
        _check_metadata_for_replacement(p, original_stat)
    if apply and (not os.access(p, os.W_OK) or not os.access(p.parent, os.W_OK)):
        raise ValueError('Target and parent directory must be writable')
    mode = original_stat.st_mode
    if not stat.S_ISREG(mode):
        raise ValueError('Not a regular file')
    original = p.read_bytes()
    try:
        decoded = original.decode('utf-8')
    except UnicodeDecodeError as exc:
        raise ValueError('Config must be UTF-8; no changes made') from exc
    updated = transform(decoded, settings).encode('utf-8')
    change = updated != original
    if not apply:
        return {'mode': 'dry-run', 'changed': change, 'settings': settings, 'backup': None, 'note': 'No files modified. Confirm ini scope and verify with web SAPI.'}
    if not acknowledge:
        raise ValueError('--apply requires --acknowledge-incomplete-mitigation')
    if not change:
        return {'mode': 'applied', 'changed': False, 'settings': settings, 'backup': None, 'note': 'Already configured; worker restart may still be necessary.'}
    if p.stat().st_size != len(original) or p.read_bytes() != original:
        raise RuntimeError('Configuration changed since it was read; refusing to overwrite')
    timestamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    backup = p.with_name(p.name + '.php2shell-backup-' + timestamp + '-' + str(os.getpid()))
    # Exclusive backup creation to avoid clobbering previous backups.
    fd = os.open(str(backup), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(original)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(backup, stat.S_IMODE(mode))
        if hasattr(os, 'geteuid') and os.geteuid() == 0:
            os.chown(backup, original_stat.st_uid, original_stat.st_gid)
    except BaseException:
        backup.unlink(missing_ok=True)
        raise
    tempname = None
    try:
        with tempfile.NamedTemporaryFile(mode='wb', dir=p.parent, prefix='.' + p.name + '.php2shell-', delete=False) as tmp:
            tempname = tmp.name
            tmp.write(updated)
            tmp.flush()
            os.fsync(tmp.fileno())
        os.chmod(tempname, stat.S_IMODE(mode))
        if hasattr(os, 'geteuid') and os.geteuid() == 0:
            os.chown(tempname, original_stat.st_uid, original_stat.st_gid)
        if p.is_symlink() or p.read_bytes() != original:
            raise RuntimeError('Configuration changed before atomic replacement; backup retained')
        os.replace(tempname, p)
    finally:
        if tempname and os.path.exists(tempname):
            os.unlink(tempname)
    return {'mode': 'applied', 'changed': True, 'settings': settings, 'backup': str(backup), 'note': 'Temporary mitigation only. Restart relevant PHP workers manually after validating configuration. Patch PHP.'}


def main(argv=None):
    parser = argparse.ArgumentParser(description='Opt-in partial PHP2Shell mitigation with backup; NOT a patch')
    parser.add_argument('--ini', required=True, help='Explicit local php.ini (no symlinks)')
    parser.add_argument('--php-version', required=True, help='Version of matching web-facing PHP runtime')
    parser.add_argument('--apply', action='store_true', help='Write changed config atomically after backup')
    parser.add_argument('--acknowledge-incomplete-mitigation', action='store_true')
    args = parser.parse_args(argv)
    try:
        result = defend(args.ini, args.php_version, args.apply, args.acknowledge_incomplete_mitigation)
        for key, val in result.items():
            print(f'{key}: {val}')
        return 0
    except (OSError, ValueError, RuntimeError) as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        return 1

if __name__ == '__main__':
    sys.exit(main())
