rule Proton_Ransomware_Recovery_Destruction_Chain
{
  meta:
    description = "Windows kurtarma, olay günlükleri ve önyükleme ayarlarını birlikte hedefleyen komut zinciri"
    severity = "high"
    category = "ransomware-impact"
    confidence = "high"
    author = "Neutron detection engineering"

  strings:
    $shadow = /vssadmin[ \t]+delete[ \t]+shadows/ ascii wide nocase
    $event = /wevtutil[ \t]+cl[ \t]+(System|Security|Application)/ ascii wide nocase
    $boot_1 = /bcdedit[ \t]+\/set[ \t]+recoveryenabled[ \t]+no/ ascii wide nocase
    $boot_2 = /bcdedit[ \t]+\/set[ \t]+bootstatuspolicy[ \t]+ignoreallfailures/ ascii wide nocase

  condition:
    filesize < 5MB and $shadow and $event and 1 of ($boot_*)
}
