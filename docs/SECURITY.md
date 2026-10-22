# Security and release checklist

**Author:** 0xAllow

## Trust boundaries

1. `scanner --version`: parses caller-provided version strings without PHP execution.
2. `scanner --binary` and default discovery: executes selected local PHP binaries with `-v`. Run only on trusted binaries and hosts.
3. `defender` default: reads selected `php.ini` and computes a proposed change; no writes.
4. `defender --apply`: privileged local config replacement; run only inside change-controlled environments.

No remote scanning, network connections, unauthenticated HTTP test requests, exploit payloads, command injection paths or package-manager invocations are implemented.

## What the mitigation does not cover

- It is **not a code patch** for either CVE.
- Does not enforce no-overrides / effective settings across SAPIs.
- Does not remediate CVE-2026-109618 comprehensively.
- Does not patch vendor images, Docker containers, self-compiled PHP, appliances or end-of-life software.
- Does not inspect intrusion indicators or prove host integrity.
- Does not preserve extended ACLs / SELinux labels in all environments.
- Concurrent writers are not fully synchronized; use a maintenance window.

## Checklist before making repository public

- [ ] Independent security review of all implementation and dependencies.
- [ ] Run automated tests locally and in CI; document commit ID and environment.
- [ ] Manually test Ubuntu/Debian + PHP-FPM, RHEL-like distro + PHP-FPM, and Apache mod_php in disposable VMs.
- [ ] Test SELinux-enforcing deployments and custom ACL/ownership; do not use apply unless validated.
- [ ] Test PHP 8.2 through 8.5 and vendor backported versions; compare package advisory evidence.
- [ ] Confirm effective web-SAPI settings and **restart workers** in a test environment.
- [ ] Confirm that application sessions, uploads and monitoring function after changes.
- [ ] Run static analysis and review race conditions and atomic replacement strategy.
- [ ] Ensure upstream advisory details remain current.
- [ ] Clearly document production acceptance requirements and avoid any certification or 100% safety claim.

## Reporting problems

Avoid posting credentials, sensitive logs, or vulnerable production host details in public GitHub issues. Arrange a private disclosure channel before public release.

## Compromise assessment limitations (experimental)

`python3 -m php2shell.compromise` reports generic investigation leads, not verified PHP2Shell exploitation or a forensic verdict. Anomalous OOM errors, worker crashes, HTTP POST failures, recently modified PHP-family files, and web-worker child processes are NOT proof of exploitation. Attackers may leave none of these artifacts. Verify telemetry against trusted baselines and correlate timestamps across sources before making incident decisions.

The command performs no exploitation, exfiltration, deletion, or remediation. Its optional `/proc` collection is a best-effort process snapshot. Each supplied log is capped at its last 8 MiB; compressed rotations are not decoded. PHP file inventory is bounded to 20,000 per supplied root. Inaccessible files and incomplete coverage are reported where detectable. Protect JSON output as sensitive incident data. Test offline using synthetic logs first.

## Cross-platform production release gate (22 October 2026)

**Production acceptance BLOCKED.** Linux unit tests and simulated Windows-specific code paths are insufficient to prove production operation on Windows. GitHub Actions Windows runners require independent confirmation. The scanner does not inspect IIS handlers/FastCGI deployments, or verify vendor package provenance/backports. The Windows assessor may miss IIS W3C POST errors; the process sampler requires PowerShell CIM and access permissions. Linux apply may not preserve ACL/xattr/SELinux context. On Windows, defender apply is intentionally unavailable to avoid changing NTFS ACLs.

Before claiming production-ready: obtain successful native Windows and Linux CI, manually validate under IIS/FastCGI, Apache/mod_php and PHP-FPM, verify real logs and permission failures, exercise backup/restore in a disposable VM, test ACL/SELinux behavior, verify actual active PHP SAPI versions and patched vendor packages, run third-party security review, and sign release artifacts. No tool can truthfully promise 100% compromise detection.

## Hardening and retest update (22 October 2026)

- INI transformation now places new settings in the global scope or `[PHP]` scope, before unrelated sections. Existing mitigation keys under other named sections, and duplicate `[PHP]` sections, cause a fail-closed error instead of silently editing the wrong scope.
- Linux `--apply` rejects hard-linked files and any detectable extended attributes, including POSIX ACLs/SELinux security labels, and rejects SELinux-enforcing systems. It does not guarantee preservation of unusual metadata or concurrent-write safety across platforms. Explicit human change control remains mandatory.
- New regression suite checks CRLF, idempotence, backup contents, ordinary Unix mode bits, metadata fail-closed behavior, Windows apply refusal and actual local PHP **CLI** interpretation from a temporary INI.
- 30 local automated tests pass on Linux. PHP CLI 8.4.24 was used for an actual configuration-interpretation test. No PHP-FPM, IIS or native Windows test runner was available in this environment.
- **Release decision: NOT VERIFIED FOR PRODUCTION** until native Windows CI, PHP-FPM/IIS/Apache deployment verification, SELinux/ACL behavior on supported hosts, effective web-SAPI settings and independent review are completed.
