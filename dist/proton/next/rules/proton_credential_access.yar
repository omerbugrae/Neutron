/*
  Proton - Kimlik bilgisi erişimi ve Active Directory saldırıları.

  LSASS bellek dökümü, SAM/NTDS çıkarma, DPAPI suistimali, Kerberos bilet
  saldırıları ve kimlik bilgisi damping araçlarının kalıntılarını kapsar.
*/

rule Proton_Mimikatz_Command_Surface
{
  meta:
    description = "Mimikatz komut yüzeyi ve modül adları"
    severity = "critical"
    category = "credential-access"
    confidence = "high"
    author = "Neutron detection engineering"
  strings:
    $mk_1 = "sekurlsa::logonpasswords" ascii wide nocase
    $mk_2 = "sekurlsa::pth" ascii wide nocase
    $mk_3 = "sekurlsa::tickets" ascii wide nocase
    $mk_4 = "lsadump::sam" ascii wide nocase
    $mk_5 = "lsadump::dcsync" ascii wide nocase
    $mk_6 = "lsadump::lsa" ascii wide nocase
    $mk_7 = "kerberos::golden" ascii wide nocase
    $mk_8 = "kerberos::ptt" ascii wide nocase
    $mk_9 = "crypto::capi" ascii wide nocase
    $mk_10 = "privilege::debug" ascii wide nocase
    $mk_11 = "token::elevate" ascii wide nocase
    $banner_1 = "gentilkiwi" ascii wide nocase
    $banner_2 = "mimikatz" ascii wide nocase
    $banner_3 = "Benjamin DELPY" ascii wide nocase
  condition:
    filesize < 30MB and (2 of ($mk_*) or (1 of ($mk_*) and 1 of ($banner_*)) or 2 of ($banner_*))
}

rule Proton_Lsass_Memory_Dump_Techniques
{
  meta:
    description = "LSASS süreç belleğini diske döken teknikler"
    severity = "critical"
    category = "credential-access"
    confidence = "high"
    author = "Neutron detection engineering"
  strings:
    $target_1 = "lsass.exe" ascii wide nocase
    $target_2 = "lsass" ascii wide fullword nocase
    $dump_1 = "MiniDumpWriteDump" ascii wide
    $dump_2 = "comsvcs.dll, MiniDump" ascii wide nocase
    $dump_3 = "MiniDumpW" ascii wide nocase
    $dump_4 = "NtReadVirtualMemory" ascii wide
    $dump_5 = "PssCaptureSnapshot" ascii wide
    $dump_6 = "SilentProcessExit" ascii wide nocase
    $priv_1 = "SeDebugPrivilege" ascii wide
    $priv_2 = "AdjustTokenPrivileges" ascii wide
    $out_1 = ".dmp" ascii wide nocase
    $out_2 = "lsass.dmp" ascii wide nocase
    $out_3 = "MiniDumpWithFullMemory" ascii wide
  condition:
    filesize < 30MB and 1 of ($target_*) and 1 of ($dump_*) and (1 of ($priv_*) or 1 of ($out_*))
}

rule Proton_Sam_Ntds_Registry_Extraction
{
  meta:
    description = "SAM, SYSTEM ve NTDS veritabanı çıkarma"
    severity = "critical"
    category = "credential-access"
    confidence = "high"
    author = "Neutron detection engineering"
  strings:
    $reg_1 = /reg[ \t]+save[ \t]+hklm\\(sam|system|security)/ ascii wide nocase
    $reg_2 = "HKLM\\SAM" ascii wide nocase
    $reg_3 = "HKLM\\SECURITY" ascii wide nocase
    $ntds_1 = "ntds.dit" ascii wide nocase
    $ntds_2 = /ntdsutil[^\r\n]{0,80}ifm/ ascii wide nocase
    $ntds_3 = "IFM Create Full" ascii wide nocase
    $vss_1 = /vssadmin[ \t]+create[ \t]+shadow/ ascii wide nocase
    $vss_2 = "\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy" ascii wide nocase
    $tool_1 = "secretsdump" ascii wide nocase
    $tool_2 = "SharpSecDump" ascii wide nocase
  condition:
    filesize < 30MB and
    (
      2 of ($reg_*) or ($reg_1) or 1 of ($tool_*)
      or ($ntds_1 and 1 of ($ntds_2, $ntds_3, $vss_1, $vss_2))
    )
}

rule Proton_Kerberos_Ticket_Attacks
{
  meta:
    description = "Kerberoasting, AS-REP roasting ve bilet aktarma araçları"
    severity = "high"
    category = "credential-access"
    confidence = "high"
    author = "Neutron detection engineering"
  strings:
    $krb_1 = "kerberoast" ascii wide nocase
    $krb_2 = "asreproast" ascii wide nocase
    $krb_3 = "Invoke-Kerberoast" ascii wide nocase
    $krb_4 = "Rubeus" ascii wide nocase
    $krb_5 = "$krb5tgs$" ascii wide nocase
    $krb_6 = "$krb5asrep$" ascii wide nocase
    $krb_7 = "KerberosRequestorSecurityToken" ascii wide nocase
    $krb_8 = "servicePrincipalName" ascii wide nocase
    $krb_9 = "asktgt" ascii wide nocase
    $krb_10 = "s4u" ascii wide fullword nocase
    $krb_11 = "tgtdeleg" ascii wide nocase
  condition:
    filesize < 30MB and 2 of them
}

rule Proton_Dpapi_Masterkey_Abuse
{
  meta:
    description = "DPAPI ana anahtar ve kimlik bilgisi kasası suistimali"
    severity = "high"
    category = "credential-access"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $dpapi_1 = "CryptUnprotectData" ascii wide
    $dpapi_2 = "\\Microsoft\\Protect\\S-1-5-21" ascii wide nocase
    $dpapi_3 = "masterkey" ascii wide nocase
    $dpapi_4 = "BCryptDeriveKeyPBKDF2" ascii wide
    $vault_1 = "\\Microsoft\\Credentials" ascii wide nocase
    $vault_2 = "\\Microsoft\\Vault" ascii wide nocase
    $vault_3 = "VaultOpenVault" ascii wide
    $vault_4 = "CredEnumerateW" ascii wide
    $tool_1 = "SharpDPAPI" ascii wide nocase
    $tool_2 = "dpapi::masterkey" ascii wide nocase
  condition:
    filesize < 30MB and (1 of ($tool_*) or (2 of ($dpapi_*) and 1 of ($vault_*)) or 3 of ($vault_*))
}

rule Proton_Ntlm_Relay_And_Hash_Capture
{
  meta:
    description = "NTLM aktarma ve karma yakalama araç kalıntıları"
    severity = "high"
    category = "credential-access"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $tool_1 = "ntlmrelayx" ascii wide nocase
    $tool_2 = "Responder" ascii wide fullword nocase
    $tool_3 = "Inveigh" ascii wide nocase
    $tool_4 = "smbrelay" ascii wide nocase
    $proto_1 = "LLMNR" ascii wide nocase
    $proto_2 = "NBT-NS" ascii wide nocase
    $proto_3 = "mDNS" ascii wide nocase
    $proto_4 = "WPAD" ascii wide nocase
    $hash_1 = "NetNTLMv2" ascii wide nocase
    $hash_2 = "NTLMSSP" ascii wide
    $hash_3 = "challenge" ascii wide fullword nocase
  condition:
    filesize < 30MB and ((1 of ($tool_*) and 1 of ($proto_*, $hash_*)) or (2 of ($proto_*) and 2 of ($hash_*)))
}

rule Proton_Credential_Manager_Browser_Vault_Api_Sweep
{
  meta:
    description = "Windows kimlik bilgisi yöneticisi ve tarayıcı kasası API taraması"
    severity = "high"
    category = "credential-access"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $api_1 = "CredEnumerateW" ascii wide
    $api_2 = "CredReadW" ascii wide
    $api_3 = "CredUnPackAuthenticationBuffer" ascii wide
    $api_4 = "VaultEnumerateItems" ascii wide
    $api_5 = "VaultGetItem" ascii wide
    $store_1 = "Local State" ascii wide
    $store_2 = "encrypted_key" ascii wide
    $store_3 = "logins.json" ascii wide
    $crypt = "CryptUnprotectData" ascii wide
  condition:
    uint16(0) == 0x5a4d and filesize < 25MB
    and 2 of ($api_*) and ($crypt or 1 of ($store_*))
}

rule Proton_Domain_Recon_And_Privilege_Path_Discovery
{
  meta:
    description = "Etki alanı keşfi ve ayrıcalık yolu haritalama araçları"
    severity = "medium"
    category = "discovery"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $tool_1 = "SharpHound" ascii wide nocase
    $tool_2 = "BloodHound" ascii wide nocase
    $tool_3 = "PowerView" ascii wide nocase
    $tool_4 = "adrecon" ascii wide nocase
    $tool_5 = "ldapdomaindump" ascii wide nocase
    $func_1 = "Get-NetComputer" ascii wide nocase
    $func_2 = "Get-DomainUser" ascii wide nocase
    $func_3 = "Invoke-ShareFinder" ascii wide nocase
    $func_4 = "Find-LocalAdminAccess" ascii wide nocase
    $func_5 = "Get-NetSession" ascii wide nocase
    $ldap_1 = "(objectCategory=computer)" ascii wide nocase
    $ldap_2 = "(&(objectClass=user)" ascii wide nocase
    $ldap_3 = "distinguishedName" ascii wide
  condition:
    filesize < 40MB and (1 of ($tool_*) or 2 of ($func_*) or (2 of ($ldap_*) and 1 of ($func_*)))
}

rule Proton_Wifi_And_Local_Password_Dump_Commands
{
  meta:
    description = "Kayıtlı kablosuz ağ ve yerel hesap parolalarını dökme komutları"
    severity = "medium"
    category = "credential-access"
    confidence = "high"
    author = "Neutron detection engineering"
  strings:
    $wifi_1 = /netsh[ \t]+wlan[ \t]+show[ \t]+profile/ ascii wide nocase
    $wifi_2 = /key[ \t]*=[ \t]*clear/ ascii wide nocase
    $local_1 = /net[ \t]+user[ \t]+[^\r\n]{0,40}\/add/ ascii wide nocase
    $local_2 = /net[ \t]+localgroup[ \t]+administrators[^\r\n]{0,40}\/add/ ascii wide nocase
    $cred_1 = /cmdkey[ \t]+\/list/ ascii wide nocase
    $cred_2 = "vaultcmd /listcreds" ascii wide nocase
  condition:
    filesize < 5MB and (($wifi_1 and $wifi_2) or ($local_1 and $local_2) or 1 of ($cred_*))
}
