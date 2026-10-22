"""Unified read-only overview; each component has its own module CLI."""
import argparse
import sys
from . import preflight, scanner, compromise, defender


def main(argv=None):
    parser = argparse.ArgumentParser(prog='python -m php2shell', description='PHP2Shell Defense - by 0xAllow')
    parser.add_argument('command', choices=('preflight', 'scanner', 'compromise', 'defender'))
    args, rest = parser.parse_known_args(argv)
    return {'preflight': preflight.main, 'scanner': scanner.main,
            'compromise': compromise.main, 'defender': defender.main}[args.command](rest)


if __name__ == '__main__':
    sys.exit(main())
