# PHP2Shell Defense - by 0xAllow | Retest evidence

Date: 2026-10-22. Host: Linux x86_64, Python 3 (container runtime). Local PHP: PHP 8.4.24 CLI.

## Tested locally

- 30 of 30 Python automated tests passed (`python -m unittest discover -s tests -v`).
- Python compilation passed (`python -m compileall -q php2shell tests`).
- Tests cover INI section insertion, CRLF, repeated transformation, refusal of ambiguous section-scoped settings and duplicate `[PHP]` groups.
- On Linux, sandbox writes verified backup byte-for-byte against original, Unix mode bits, safe second apply, hard-link rejection and xattr rejection (filesystem supports test xattr).
- Real PHP CLI was invoked with a sandbox `php.ini` after mitigation and returned `0` for `ini_get("session.upload_progress.enabled")`.
- Windows `--apply` refusal tested by mock; this **is not** native Windows execution.

## Not tested here / blocking production approval

- Native Windows, Windows IIS/FastCGI behavior, or NTFS ACL restoration.
- Actual PHP-FPM, Apache mod_php and web-SAPI effective values; PHP CLI behavior cannot prove these.
- Real compromised PHP2Shell environments or exploitation detection fidelity.
- RHEL SELinux enforcing and production POSIX ACL edge cases.
- Safe concurrent writers under adversarial timing, independent audit, upstream vendor backport recognition.

## Conclusion

**Not validated for production deployment.** Suitable for further staging and independent code review. The toolkit does not repair either CVE; only a verified patched PHP build remedies the underlying vulnerabilities.
