rule Proton_Process_Injection_Primitives
{
  meta:
    description = "Bir PE dosyasında süreç enjeksiyonu API kümesi"
    severity = "medium"
    category = "process-injection"
    confidence = "review"
  strings:
    $inject_1 = "VirtualAllocEx" ascii wide
    $inject_2 = "WriteProcessMemory" ascii wide
    $inject_3 = "CreateRemoteThread" ascii wide
    $inject_4 = "QueueUserAPC" ascii wide
    $inject_5 = "NtUnmapViewOfSection" ascii wide
    $inject_6 = "SetThreadContext" ascii wide
    $inject_7 = "ResumeThread" ascii wide
  condition:
    filesize < 25MB and uint16(0) == 0x5a4d and 3 of ($inject_*)
}

rule Proton_Credential_Dump_Primitives
{
  meta:
    description = "Kimlik bilgisi dökümüyle ilişkili API ve hedef kümesi"
    severity = "medium"
    category = "credential-access"
    confidence = "review"
  strings:
    $dump_1 = "lsass.exe" ascii wide nocase
    $dump_2 = "MiniDumpWriteDump" ascii wide
    $dump_3 = "SeDebugPrivilege" ascii wide
    $dump_4 = "comsvcs.dll" ascii wide nocase
    $dump_5 = "OpenProcessToken" ascii wide
  condition:
    filesize < 25MB and uint16(0) == 0x5a4d and 3 of ($dump_*)
}

rule Proton_Encoded_PowerShell_Download_Chain
{
  meta:
    description = "Kodlanmış veya bellek içi PowerShell indirme zinciri"
    severity = "medium"
    category = "script-execution"
    confidence = "review"
  strings:
    $host_1 = "powershell" ascii wide nocase
    $host_2 = "pwsh" ascii wide nocase
    $decode_1 = "FromBase64String" ascii wide nocase
    $decode_2 = "-EncodedCommand" ascii wide nocase
    $decode_3 = " -enc " ascii wide nocase
    $execute_1 = "Invoke-Expression" ascii wide nocase
    $execute_2 = "IEX(" ascii wide nocase
    $download_1 = "DownloadString" ascii wide nocase
    $download_2 = "DownloadFile" ascii wide nocase
    $download_3 = "Net.WebClient" ascii wide nocase
    $download_4 = "Invoke-WebRequest" ascii wide nocase
  condition:
    filesize < 5MB and 1 of ($host_*) and 1 of ($decode_*) and (1 of ($execute_*) or 1 of ($download_*))
}

rule Proton_Windows_Run_Key_Persistence_Chain
{
  meta:
    description = "Komut dosyasında Windows Run anahtarı kalıcılık zinciri"
    severity = "medium"
    category = "persistence"
    confidence = "review"
  strings:
    $run_1 = "CurrentVersion\\Run" ascii wide nocase
    $run_2 = "CurrentVersion\\RunOnce" ascii wide nocase
    $writer_1 = "reg add" ascii wide nocase
    $writer_2 = "Set-ItemProperty" ascii wide nocase
    $writer_3 = "New-ItemProperty" ascii wide nocase
    $launcher_1 = "powershell" ascii wide nocase
    $launcher_2 = "cmd.exe" ascii wide nocase
    $launcher_3 = "wscript.exe" ascii wide nocase
    $launcher_4 = "mshta.exe" ascii wide nocase
  condition:
    filesize < 5MB and 1 of ($run_*) and 1 of ($writer_*) and 1 of ($launcher_*)
}

rule Proton_Recovery_Inhibition_Command_Cluster
{
  meta:
    description = "Windows kurtarma ve gölge kopyalarını devre dışı bırakma komut kümesi"
    severity = "high"
    category = "impact"
    confidence = "high"
  strings:
    $recovery_1 = /vssadmin[ \t]+delete[ \t]+shadows/ ascii wide nocase
    $recovery_2 = /wmic[ \t]+shadowcopy[ \t]+delete/ ascii wide nocase
    $recovery_3 = /wbadmin[ \t]+delete[ \t]+catalog/ ascii wide nocase
    $recovery_4 = /bcdedit[ \t]+\/set/ ascii wide nocase
    $recovery_5 = /recoveryenabled[ \t]+no/ ascii wide nocase
    $recovery_6 = /bootstatuspolicy[ \t]+ignoreallfailures/ ascii wide nocase
    $recovery_7 = /Get-WmiObject[ \t]+Win32_Shadowcopy/ ascii wide nocase
  condition:
    filesize < 5MB and 2 of ($recovery_*)
}
