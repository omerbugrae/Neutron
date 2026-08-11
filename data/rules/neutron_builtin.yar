/*
  Neutron built-in YARA rules.

  This first rule is deliberately harmless. It lets the scanner integration be
  tested with a small text file containing NEUTRON_YARA_SAFE_TEST. Production
  malware rules will be added only after they are sourced, reviewed and tested
  against a clean-file corpus to control false positives.
*/

rule Neutron_Safe_Integration_Test
{
  meta:
    author = "Neutron"
    description = "Neutron YARA motoru güvenli entegrasyon testi"
    severity = "low"
    category = "test"
    reference = "local-safe-test"

  strings:
    $marker = "NEUTRON_YARA_SAFE_TEST" ascii wide fullword

  condition:
    filesize <= 1024 and $marker
}
