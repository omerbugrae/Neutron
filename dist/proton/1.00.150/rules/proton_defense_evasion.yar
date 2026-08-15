/*
  Proton - Savunma atlatma ve güvenlik bileşeni sabotajı.

  AMSI/ETW yamaları, EDR kanca sökme, savunmasız sürücü suistimali (BYOVD),
  kum havuzu tespiti ve güvenlik hizmetlerini kapatma davranışlarını kapsar.
*/

rule Proton_Amsi_Patch_Bypass
{
  meta:
    description = "AMSI tarama arayüzünü bellek üzerinden devre dışı bırakma"
    severity = "high"
    category = "defense-evasion"
    confidence = "high"
    author = "Neutron detection engineering"
  strings:
    $amsi_1 = "AmsiScanBuffer" ascii wide
    $amsi_2 = "AmsiInitialize" ascii wide
    $amsi_3 = "amsi.dll" ascii wide nocase
    $amsi_4 = "AmsiUtils" ascii wide
    $amsi_5 = "amsiInitFailed" ascii wide
    $patch_1 = "VirtualProtect" ascii wide
    $patch_2 = "NtProtectVirtualMemory" ascii wide
    $patch_3 = "WriteProcessMemory" ascii wide
    $patch_4 = { B8 57 00 07 80 C3 }
    $patch_5 = "SetValue" ascii wide
  condition:
    filesize < 20MB and 2 of ($amsi_*) and 1 of ($patch_*)
}

rule Proton_Etw_Provider_Disable
{
  meta:
    description = "ETW olay sağlayıcısını yamalayarak telemetriyi susturma"
    severity = "high"
    category = "defense-evasion"
    confidence = "high"
    author = "Neutron detection engineering"
  strings:
    $etw_1 = "EtwEventWrite" ascii wide
    $etw_2 = "NtTraceEvent" ascii wide
    $etw_3 = "EtwNotificationRegister" ascii wide
    $etw_4 = "ETW_EVENT_" ascii wide
    $etw_5 = "COMPlus_ETWEnabled" ascii wide
    $patch_1 = "VirtualProtect" ascii wide
    $patch_2 = "NtProtectVirtualMemory" ascii wide
    $patch_3 = { C3 90 90 90 }
  condition:
    filesize < 20MB and 2 of ($etw_*) and 1 of ($patch_*)
}

rule Proton_Ntdll_Unhooking_Fresh_Copy
{
  meta:
    description = "Diskten temiz ntdll kopyası yükleyip kullanıcı modu kancalarını kaldırma"
    severity = "high"
    category = "defense-evasion"
    confidence = "high"
    author = "Neutron detection engineering"
  strings:
    $target_1 = "\\KnownDlls\\ntdll.dll" ascii wide nocase
    $target_2 = "C:\\Windows\\System32\\ntdll.dll" ascii wide nocase
    $target_3 = "\\SystemRoot\\System32\\ntdll.dll" ascii wide nocase
    $target_4 = "ntdll.dll" ascii wide nocase
    $unhook_1 = "NtMapViewOfSection" ascii wide
    $unhook_2 = "NtOpenSection" ascii wide
    $unhook_3 = "CreateFileMapping" ascii wide
    $unhook_4 = ".text" ascii fullword
    $write_1 = "VirtualProtect" ascii wide
    $write_2 = "NtProtectVirtualMemory" ascii wide
    $marker = "unhook" ascii wide nocase
  condition:
    filesize < 20MB and 1 of ($write_*) and
    (
      (uint16(0) == 0x5a4d and 1 of ($target_1, $target_2, $target_3) and 2 of ($unhook_*))
      or ($marker and $target_4 and 1 of ($unhook_*))
    )
}

rule Proton_Vulnerable_Driver_Abuse_Byovd
{
  meta:
    description = "İmzalı fakat savunmasız sürücü yükleyerek çekirdek erişimi (BYOVD)"
    severity = "critical"
    category = "defense-evasion"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $drv_1 = "RTCore64.sys" ascii wide nocase
    $drv_2 = "gdrv.sys" ascii wide nocase
    $drv_3 = "iqvw64e.sys" ascii wide nocase
    $drv_4 = "dbutil_2_3.sys" ascii wide nocase
    $drv_5 = "procexp152.sys" ascii wide nocase
    $drv_6 = "aswArPot.sys" ascii wide nocase
    $drv_7 = "truesight.sys" ascii wide nocase
    $drv_8 = "viragt64.sys" ascii wide nocase
    $load_1 = "NtLoadDriver" ascii wide
    $load_2 = "CreateService" ascii wide
    $load_3 = "SERVICE_KERNEL_DRIVER" ascii wide
    $load_4 = "DeviceIoControl" ascii wide
    $kill_1 = "ZwTerminateProcess" ascii wide
    $kill_2 = "PsLookupProcessByProcessId" ascii wide
    $kill_3 = "ObRegisterCallbacks" ascii wide
  condition:
    filesize < 30MB and 1 of ($drv_*) and (2 of ($load_*) or 1 of ($kill_*))
}

rule Proton_Security_Service_Tamper_Commands
{
  meta:
    description = "Windows Defender ve güvenlik hizmetlerini komutla devre dışı bırakma"
    severity = "high"
    category = "defense-evasion"
    confidence = "high"
    author = "Neutron detection engineering"
  strings:
    $def_1 = /Set-MpPreference[ \t]+-Disable/ ascii wide nocase
    $def_2 = /Add-MpPreference[ \t]+-ExclusionPath/ ascii wide nocase
    $def_3 = "DisableAntiSpyware" ascii wide nocase
    $def_4 = "DisableRealtimeMonitoring" ascii wide nocase
    $def_5 = "DisableBehaviorMonitoring" ascii wide nocase
    $svc_1 = /sc[ \t]+(stop|delete|config)[ \t]+(WinDefend|Sense|WdNisSvc|SecurityHealthService)/ ascii wide nocase
    $svc_2 = /net[ \t]+stop[ \t]+["']?(WinDefend|MsMpSvc|wuauserv)/ ascii wide nocase
    $fw_1 = /netsh[ \t]+advfirewall[ \t]+set[ \t]+allprofiles[ \t]+state[ \t]+off/ ascii wide nocase
    $fw_2 = /netsh[ \t]+firewall[ \t]+set[ \t]+opmode[ \t]+disable/ ascii wide nocase
  condition:
    filesize < 5MB and 2 of them
}

rule Proton_Sandbox_And_Analysis_Environment_Checks
{
  meta:
    description = "Kum havuzu, sanal makine ve analiz aracı tespit kümesi"
    severity = "medium"
    category = "defense-evasion"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $vm_1 = "VBoxService" ascii wide nocase
    $vm_2 = "VBoxTray" ascii wide nocase
    $vm_3 = "vmtoolsd" ascii wide nocase
    $vm_4 = "VMwareService" ascii wide nocase
    $vm_5 = "qemu-ga" ascii wide nocase
    $vm_6 = "SbieDll.dll" ascii wide nocase
    $vm_7 = "cuckoomon" ascii wide nocase
    $tool_1 = "procmon.exe" ascii wide nocase
    $tool_2 = "wireshark.exe" ascii wide nocase
    $tool_3 = "ollydbg.exe" ascii wide nocase
    $tool_4 = "x64dbg.exe" ascii wide nocase
    $tool_5 = "idaq.exe" ascii wide nocase
    $tool_6 = "fiddler.exe" ascii wide nocase
    $api_1 = "IsDebuggerPresent" ascii wide
    $api_2 = "CheckRemoteDebuggerPresent" ascii wide
    $api_3 = "NtQueryInformationProcess" ascii wide
    $api_4 = "GetTickCount" ascii wide
  condition:
    uint16(0) == 0x5a4d and filesize < 25MB
    and 3 of ($vm_*, $tool_*) and 2 of ($api_*)
}

rule Proton_Uac_Bypass_Auto_Elevate_Chain
{
  meta:
    description = "Otomatik yükseltilen bileşenleri kullanarak UAC atlatma"
    severity = "high"
    category = "privilege-escalation"
    confidence = "high"
    author = "Neutron detection engineering"
  strings:
    $hijack_1 = "Software\\Classes\\ms-settings\\shell\\open\\command" ascii wide nocase
    $hijack_2 = "Software\\Classes\\mscfile\\shell\\open\\command" ascii wide nocase
    $hijack_3 = "Software\\Classes\\exefile\\shell\\open\\command" ascii wide nocase
    $hijack_4 = "Software\\Classes\\Folder\\shell\\open\\command" ascii wide nocase
    $binary_1 = "fodhelper.exe" ascii wide nocase
    $binary_2 = "computerdefaults.exe" ascii wide nocase
    $binary_3 = "eventvwr.exe" ascii wide nocase
    $binary_4 = "sdclt.exe" ascii wide nocase
    $binary_5 = "slui.exe" ascii wide nocase
    $binary_6 = "CompMgmtLauncher.exe" ascii wide nocase
    $trigger = "DelegateExecute" ascii wide nocase
  condition:
    filesize < 15MB and ((1 of ($hijack_*) and 1 of ($binary_*)) or ($trigger and 1 of ($hijack_*)))
}

rule Proton_Token_Manipulation_Privilege_Escalation
{
  meta:
    description = "Erişim belirteci çalarak ayrıcalık yükseltme"
    severity = "high"
    category = "privilege-escalation"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $tok_1 = "OpenProcessToken" ascii wide
    $tok_2 = "DuplicateTokenEx" ascii wide
    $tok_3 = "ImpersonateLoggedOnUser" ascii wide
    $tok_4 = "SetTokenInformation" ascii wide
    $tok_5 = "CreateProcessWithTokenW" ascii wide
    $priv_1 = "SeDebugPrivilege" ascii wide
    $priv_2 = "SeImpersonatePrivilege" ascii wide
    $priv_3 = "SeTakeOwnershipPrivilege" ascii wide
    $priv_4 = "AdjustTokenPrivileges" ascii wide
  condition:
    uint16(0) == 0x5a4d and filesize < 20MB and 3 of ($tok_*) and 2 of ($priv_*)
}

rule Proton_Event_Log_And_Forensic_Trace_Removal
{
  meta:
    description = "Olay günlüklerini ve adli izleri silme"
    severity = "high"
    category = "defense-evasion"
    confidence = "high"
    author = "Neutron detection engineering"
  strings:
    $log_1 = /wevtutil[ \t]+cl[ \t]+/ ascii wide nocase
    $log_2 = /Clear-EventLog/ ascii wide nocase
    $log_3 = /Remove-EventLog/ ascii wide nocase
    $log_4 = "ClearEventLogW" ascii wide
    $trace_1 = /fsutil[ \t]+usn[ \t]+deletejournal/ ascii wide nocase
    $trace_2 = /cipher[ \t]+\/w:/ ascii wide nocase
    $trace_3 = "ConsoleHost_history.txt" ascii wide nocase
    $trace_4 = /Set-PSReadlineOption[ \t]+-HistorySaveStyle[ \t]+SaveNothing/ ascii wide nocase
  condition:
    filesize < 5MB and 2 of them
}

rule Proton_Timestomp_And_Attribute_Hiding
{
  meta:
    description = "Dosya zaman damgalarını değiştirip içeriği gizleme"
    severity = "medium"
    category = "defense-evasion"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $time_1 = "SetFileTime" ascii wide
    $time_2 = "NtSetInformationFile" ascii wide
    $time_3 = "timestomp" ascii wide nocase
    $hide_1 = "FILE_ATTRIBUTE_HIDDEN" ascii wide
    $hide_2 = "SetFileAttributes" ascii wide
    $hide_3 = /attrib[ \t]+\+[hs]/ ascii wide nocase
    $stream = "::$DATA" ascii wide
  condition:
    filesize < 20MB and 2 of ($time_*) and (2 of ($hide_*) or $stream)
}

rule Proton_Process_Ppid_Spoofing_And_Blocking_Policy
{
  meta:
    description = "Üst süreç kimliğini taklit etme ve DLL yükleme politikası zorlama"
    severity = "high"
    category = "defense-evasion"
    confidence = "high"
    author = "Neutron detection engineering"
  strings:
    $attr_1 = "InitializeProcThreadAttributeList" ascii wide
    $attr_2 = "UpdateProcThreadAttribute" ascii wide
    $attr_3 = "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS" ascii wide
    $policy_1 = "PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES" ascii wide
    $policy_2 = "SetProcessMitigationPolicy" ascii wide
    $spawn_1 = "CreateProcessW" ascii wide
    $spawn_2 = "CreateProcessA" ascii wide
  condition:
    uint16(0) == 0x5a4d and filesize < 20MB
    and 2 of ($attr_*) and 1 of ($spawn_*) and (1 of ($policy_*) or $attr_3)
}
