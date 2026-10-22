# PHP2Shell Defense - by 0xAllow

**Platforms:** Linux and Windows | **Runtime:** Python 3.9+ (standard library only) | **Release status:** Requires production validation

Defensive local toolkit for assessing PHP installations relevant to CVE-2026-109618 and CVE-2026-109619. It provides a resource preflight, a version scanner, read-only compromise triage, and an opt-in, partial configuration mitigation with backups on supported Linux hosts. It does **not** perform exploit testing, patch PHP, remotely connect, or assert a clean host.

> **The only complete correction is an approved upstream or vendor-patched PHP build.** Upstream fixed releases dated 21 October 2026: PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35. PHP 8.1 and older require vendor confirmation or migration. Version-only comparison may falsely flag vendor-backported packages. See `docs/SECURITY.md`.

## Big Picture

```text
                  LOCAL MACHINE ONLY
                    +------------+
                    |  Preflight | --> supported OS, Python, directory, disk
                    +-----+------+
                          |
              +-----------+------------+
              |                        |
        +-----v------+           +-----v----------------+
        |  Scanner   |           | Compromise Assessment|
        | PHP -v     |           | logs, webroot, process|
        +-----+------+           +-----+----------------+
              |                        |
              +-----------+------------+
                          |
                 MANUAL INVESTIGATION
                          |
                    +-----v-------+
                    |  Defender   |  dry-run by default
                    |  backup     |  Linux opt-in writes only
                    +-----+-------+
                          |
                 Patch PHP / validate SAPI
```

## Quick start: Linux

```bash
python3 -m php2shell preflight --json
python3 -m php2shell scanner --json
python3 -m php2shell scanner --version 8.4.26 --json
python3 -m php2shell compromise --log /var/log/nginx/error.log --webroot /var/www/html --since 2026-10-17 --json
python3 -m php2shell defender --ini /etc/php/8.5/fpm/php.ini --php-version 8.5.11
```

## Quick start: Windows (PowerShell)

```powershell
py -3 -m php2shell preflight --json
py -3 -m php2shell scanner --json
py -3 -m php2shell scanner --binary 'C:\php\php.exe' --json
py -3 -m php2shell compromise --log 'C:\inetpub\logs\LogFiles\W3SVC1\u_ex260102.log' --webroot 'C:\inetpub\wwwroot' --json
py -3 -m php2shell defender --ini 'C:\php\php.ini' --php-version 8.5.11
```

Replace example paths with real ones. Windows process examination uses `Get-CimInstance Win32_Process` via PowerShell when available. If unavailable, errors explicitly report incomplete coverage. IIS log formats vary; the generic HTTP POST matcher does not fully parse W3C IIS records. `php.exe` found on PATH is not proof of the IIS web-facing PHP version. For accurate web runtime evaluation, consult IIS/FastCGI configuration and deployment manifests.

## Components and safety

| Component | Windows | Linux | Mutates host? |
|---|---|---|---|
| `preflight` | Yes | Yes | No |
| `scanner` | Yes | Yes | No (runs trusted local PHP with `-v`) |
| `compromise` | Yes | Yes | No |
| `defender` dry run | Yes | Yes | No |
| `defender --apply` | **Intentionally refused** (NTFS ACL safety) | Limited, opt-in | **Yes** |

### Optional Linux-only partial mitigation

**Always stage and verify first.** The automated change sets `session.upload_progress.enabled=0` and for PHP 8.5 additionally `fatal_error_backtraces=0`. Neither removes the vulnerabilities. These settings can change application functionality and may be overridden. Target the **correct** PHP SAPI configuration. The tool does not verify effective settings, restart workers, or update packages.

```bash
sudo python3 -m php2shell defender --ini /etc/php/8.5/fpm/php.ini --php-version 8.5.11 --apply --acknowledge-incomplete-mitigation
```

The defender refuses symlinks, non-UTF-8 files and unexpected concurrent file edits, creates an exclusive backup next to the original, and atomically replaces the ini on supported Linux. It does **not** preserve every ACL, xattr or SELinux context; use only where metadata policy is understood, and verify before/after. Restore from the recorded backup through your change-management process; restart/reload workers manually after validation.

**Safety and backup is intentionally conservative:** no automatic destructive actions, quarantine, firewall changes, service restarts, patch downloads, or scheduled tasks.

## Compromise Assessment

Supply log paths and webroots explicitly. It checks generic PHP OOM/crash errors, POST failures, recently modified PHP-family files, and suspicious web/PHP child processes. Limits: 8 MiB tail per log, 20,000 PHP files per root, 500 returned findings. Suspicious does **not** mean compromised. A clean report does **not** exclude attacks. On Windows the process inventory requires PowerShell+CIM; if unavailable the assessment reports `errors` and exits `3`. Treat outputs as sensitive. No data leaves the machine.

```bash
python -m php2shell compromise --log /path/to/error.log --webroot /path/to/site --no-processes --json
```

Exit codes: compromise `0` no generic indicators in checked sources, `2` findings, `3` incomplete checks. Scanner `0` no vulnerable upstream versions detected among provided entries, `2` potentially vulnerable version, `3` inconclusive. **These are not guarantees of safety.**

## Test locally

```bash
python -m unittest discover -s tests -v
python -m compileall -q php2shell tests
python -m php2shell preflight --json
```

GitHub Actions runs an OS/Python matrix on Linux and Windows after pushes/PRs. CI execution must be confirmed on the actual repository; a workflow definition by itself is not evidence of success. See `docs/SECURITY.md` for release gates and the `docs/PHP2Shell Defense - by 0xAllow.pdf` for architecture and workflows.

## Official references

- [PHP security announcement](https://www.php.net/archive/2026.php)
- [Canadian Cyber Centre AL26-026](https://www.cyber.gc.ca/en/alerts-advisories/al26-026-critical-vulnerabilities-impacting-php-cve-2026-109618-cve-2026-109619)
- [PHP GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [PHP GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)

## License

MIT, copyright (c) 2026 0xAllow.

## Important distinction: fixing PHP versus reducing exposure

PHP2Shell Defense is not an upstream PHP source-code patch. Its scanner compares local runtime versions with published fixed-version thresholds; the compromise module looks for generic suspicious signals; and the optional Defender action changes selected PHP configuration directives after a backup. None of these actions proves that an exploit is impossible or that a compromised host is clean. For definitive remediation, apply and verify the official patched PHP build or an approved vendor backport.

### Production acceptance

Run the automated suite plus native Windows and Linux CI, validate web-facing PHP SAPIs (IIS/FastCGI, Apache and PHP-FPM), restore backups under production-equivalent ACL/SELinux policy, inspect false positives using realistic logs and obtain an independent security review. **Until those gates are completed, do not run `defender --apply` on production systems.**

## Latest local retest and release status

A Linux retest includes 30 unit/integration tests, including a real installed PHP CLI reading a temporary mitigated `php.ini` and verifying the effective `session.upload_progress.enabled` value. The mitigation scope regression is fixed: settings are inserted before unrelated sections or within `[PHP]`. Ambiguous section overrides fail closed. On Linux, hard links and extended attributes/ACL labels trigger a refusal instead of a potentially metadata-destructive replacement.

This is **not** native Windows, PHP-FPM, IIS or Apache integration certification. The release is intended for review and controlled testing, not unattended production application. The code is not an upstream PHP patch. See `docs/RETEST_REPORT.md`.
