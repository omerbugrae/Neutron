rule Proton_Safe_Integration_Test
{
  meta:
    description = "Neutron Proton paket altyapısı için zararsız entegrasyon testi"
    severity = "low"

  strings:
    $marker = "NEUTRON_PROTON_SAFE_TEST" ascii wide fullword

  condition:
    $marker
}
