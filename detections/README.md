# Detection Content | PHP2Shell Defense - by 0xAllow

**Scope:** Windows and Linux, subject to telemetry availability. These rules detect suspicious *post-exploitation behaviors* associated with web-server compromise; **they do not prove exploitation of CVE-2026-109618 or CVE-2026-109619**. Do not use a negative result to conclude a server is clean. Upgrade PHP using approved vendor security fixes.

## Big Picture

`HTTP/PHP request -> unexpected process or file activity -> Elastic / Sentinel alert -> analyst triage`

`Web root -> suspicious PHP source file -> YARA match -> analyst investigation`

These are **detect-only** artifacts. No WAF, IPS, quarantine, deletion or auto-remediation is installed.

## Elastic Security

- `elastic/php2shell_web_process.toml`: ECS `process` event and `process.parent.name` required. EQL process-start detection. The parent names are **not exhaustive** and should be tuned to the deployed PHP engine.
- `elastic/php2shell_php_file_creation.toml`: ECS `file` creation event with path/extension required. For Elastic installations that do not map `file.extension`, normalize the field at ingest.
- Import each TOML using a workflow compatible with Elastic's detection-rule schema or translate the rule query into a Custom EQL rule in Kibana Security. **Do not assume the TOML can be uploaded directly in every Kibana version.** Index patterns are examples; verify that data actually arrives under those names.
- Normal application deployments, scheduled maintenance, PHP framework runners and authorized child processes may cause false positives. Add narrow host/path exclusions after review.

## Microsoft Sentinel / Defender for Endpoint

- `sentinel/php2shell_suspicious_web_child.kql` reads `DeviceProcessEvents`.
- `sentinel/php2shell_webroot_php_creation.kql` reads `DeviceFileEvents`.
- These require corresponding Defender XDR/MDE telemetry connected to the Sentinel workspace. They **do not work by default** with `SecurityEvent` / `Syslog` / `CommonSecurityLog` tables. Create a scheduled analytics rule using the corresponding query, adapt lookback and frequency, and configure alert entity mappings.
- Linux telemetry is possible with MDE on supported Linux distributions; adjust PHP-FPM process names and webroot paths (the initial process rule primarily covers Windows exe names).
- Legitimate deployments trigger file-change alerts. Treat them as change-audit leads.

## YARA

- `yara/php2shell_suspicious_php_webshell.yar` detects suspicious PHP command webshell / encoded evaluation source patterns. It does **not** identify a memory-corruption exploit or scan live PHP process memory.
- Install the official YARA scanner and scan an explicitly authorized web directory, e.g. `yara -r detections/yara/php2shell_suspicious_php_webshell.yar /var/www/html`.
- Never automatically delete matched files. PHP frameworks and administrative tools can contain legitimate command execution patterns. Review every match manually.
- A file that omits these strings, uses obfuscation, or exists only in memory will not match.

## Safe alert triage

1. Identify actual host and application owner; check whether the process / deployment was approved.
2. Correlate process/file event timestamp with web/PHP logs and other EDR observations.
3. If suspicious, preserve logs and volatile evidence, isolate according to incident-response policy, rotate potentially exposed secrets, and deploy approved PHP security patches.
4. Avoid treating these heuristics as conclusive attribution to a particular CVE.

## Validation

- `python -m unittest discover -s tests -v` runs repository tests.
- `python -m unittest tests.test_detection_content -v` validates TOML and static query structure.
- YARA syntax compilation is verified **only if** a `yara` Python module is installed. Validate against your deployed YARA version.
- Production Elastic EQL and Sentinel KQL ingestion/execution must be tested in your own cluster/workspace. Local tests cannot reproduce live schemas, RBAC, ingest pipelines or alert tuning.

## References

- https://www.elastic.co/security-labs/threat-command/php2shell-php-rce-detection
- https://www.cyber.gc.ca/en/alerts-advisories/al26-026-critical-vulnerabilities-impacting-php-cve-2026-109618-cve-2026-109619
- https://techcommunity.microsoft.com/blog/azurenetworksecurityblog/addressing-php2shell-cve-2026-109618-and-cve-2026-109619-upgrade-guidance-and-az/4566623
