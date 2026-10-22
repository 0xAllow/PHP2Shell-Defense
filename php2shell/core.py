"""Conservative PHP2Shell version assessment (not exploit detection)."""
import re

FIXED = {(8, 2): (8, 2, 35), (8, 3): (8, 3, 36), (8, 4): (8, 4, 27), (8, 5): (8, 5, 12)}
VERSION_RE = re.compile(r'(?<!\d)(\d+)\.(\d+)\.(\d+)(?!\d)')


def parse_version(value):
    match = VERSION_RE.search(value)
    if not match:
        raise ValueError('No PHP major.minor.patch version found')
    return tuple(int(v) for v in match.groups())


def assess(value):
    version = parse_version(value)
    branch = version[:2]
    if branch in FIXED:
        minimum = FIXED[branch]
        return {'version': '.'.join(map(str, version)), 'status': 'patched_upstream' if version >= minimum else 'potentially_vulnerable', 'fixed_version': '.'.join(map(str, minimum)), 'note': 'Version-only assessment. Vendor backports may fix a lower version.'}
    if version < (8, 2, 0):
        return {'version': '.'.join(map(str, version)), 'status': 'legacy_review_required', 'fixed_version': None, 'note': 'No upstream fix for this legacy branch. Verify vendor backports or migrate.'}
    return {'version': '.'.join(map(str, version)), 'status': 'unknown_branch', 'fixed_version': None, 'note': 'No verified threshold for this branch; verify current PHP vendor advisory.'}
