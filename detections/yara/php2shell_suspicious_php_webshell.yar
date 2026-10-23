/* PHP2Shell Defense - by 0xAllow
   Suspicious on-disk PHP webshell heuristics. NOT a signature for PHP2Shell RCE
   or for CVE-2026-109618 / CVE-2026-109619 memory corruption itself.
*/
rule PHP2Shell_Suspicious_PHP_Command_Webshell
{
    meta:
        author = "0xAllow"
        description = "PHP script containing request-controlled command execution patterns"
        category = "post_exploitation"
        confidence = "medium"
        reference = "https://www.elastic.co/security-labs/threat-command/php2shell-php-rce-detection"
    strings:
        $php = "<?php" ascii nocase
        $input1 = /\$_(GET|POST|REQUEST|COOKIE)\s*\[/ ascii
        $input2 = /file_get_contents\s*\(\s*["']php:\/\/input["']/ ascii nocase
        $exec1 = /\b(system|shell_exec|passthru|exec|popen|proc_open)\s*\(/ ascii nocase
        $exec2 = /\beval\s*\(/ ascii nocase
    condition:
        filesize < 2MB and $php and 1 of ($input*) and 1 of ($exec*)
}

rule PHP2Shell_Suspicious_PHP_Encoded_Evaluation
{
    meta:
        author = "0xAllow"
        description = "Suspicious PHP request input decoding into dynamic execution"
        category = "post_exploitation"
        confidence = "medium"
    strings:
        $php = "<?php" ascii nocase
        $req = /\$_(GET|POST|REQUEST|COOKIE)\s*\[/ ascii
        $decode = /\b(base64_decode|gzinflate|gzuncompress|str_rot13)\s*\(/ ascii nocase
        $eval = /\beval\s*\(/ ascii nocase
    condition:
        filesize < 2MB and all of them
}
