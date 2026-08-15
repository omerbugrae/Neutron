/*
  Proton - Yükleyici (loader) ve damlalık (dropper) davranışları.

  Bu dosyadaki kurallar tek bir API adına değil, birlikte görüldüğünde anlamlı
  olan API kümelerine bakar. Her kural PE başlığı ve dosya boyutu ile
  sınırlandırılmıştır; amaç temiz dosya korpusunda yanlış pozitifi düşük tutmaktır.
*/

rule Proton_Shellcode_Alloc_Execute_Primitives
{
  meta:
    description = "Bellekte çalıştırılabilir alan ayırıp kod çalıştıran shellcode yükleyici kümesi"
    severity = "medium"
    category = "loader"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $alloc_1 = "VirtualAlloc" ascii wide
    $alloc_2 = "VirtualAllocEx" ascii wide
    $alloc_3 = "NtAllocateVirtualMemory" ascii wide
    $protect_1 = "VirtualProtect" ascii wide
    $protect_2 = "NtProtectVirtualMemory" ascii wide
    $exec_1 = "CreateThread" ascii wide
    $exec_2 = "CreateRemoteThread" ascii wide
    $exec_3 = "NtCreateThreadEx" ascii wide
    $exec_4 = "EnumSystemLocalesA" ascii wide
    $copy_1 = "RtlMoveMemory" ascii wide
    $copy_2 = "WriteProcessMemory" ascii wide
    $copy_3 = "NtWriteVirtualMemory" ascii wide
  condition:
    uint16(0) == 0x5a4d and filesize < 20MB
    and 1 of ($alloc_*) and 1 of ($protect_*) and 1 of ($exec_*) and 1 of ($copy_*)
}

rule Proton_Process_Hollowing_Chain
{
  meta:
    description = "Askıya alınmış süreç oluşturup görüntüsünü değiştiren process hollowing zinciri"
    severity = "high"
    category = "loader"
    confidence = "high"
    author = "Neutron detection engineering"
  strings:
    $unmap_1 = "NtUnmapViewOfSection" ascii wide
    $unmap_2 = "ZwUnmapViewOfSection" ascii wide
    $create = "CreateProcess" ascii wide
    $ctx_1 = "SetThreadContext" ascii wide
    $ctx_2 = "GetThreadContext" ascii wide
    $write = "WriteProcessMemory" ascii wide
    $resume = "ResumeThread" ascii wide
  condition:
    uint16(0) == 0x5a4d and filesize < 20MB
    and 1 of ($unmap_*) and $create and 1 of ($ctx_*) and $write and $resume
}

rule Proton_APC_Queue_Injection_Chain
{
  meta:
    description = "APC kuyruğu üzerinden uzak süreçte kod çalıştırma zinciri"
    severity = "high"
    category = "loader"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $apc_1 = "QueueUserAPC" ascii wide
    $apc_2 = "NtQueueApcThread" ascii wide
    $thread_1 = "OpenThread" ascii wide
    $thread_2 = "Thread32First" ascii wide
    $thread_3 = "NtAlertResumeThread" ascii wide
    $alloc = "VirtualAllocEx" ascii wide
    $write = "WriteProcessMemory" ascii wide
  condition:
    uint16(0) == 0x5a4d and filesize < 20MB
    and 1 of ($apc_*) and 1 of ($thread_*) and $alloc and $write
}

rule Proton_Reflective_DLL_Loader_Artifacts
{
  meta:
    description = "Reflective DLL yükleyici göstergeleri"
    severity = "high"
    category = "loader"
    confidence = "high"
    author = "Neutron detection engineering"
  strings:
    $reflective_1 = "ReflectiveLoader" ascii wide
    $reflective_2 = "_ReflectiveLoader@4" ascii wide
    $reflective_3 = "ReflectiveDLLInjection" ascii wide
    $support_1 = "LoadLibraryA" ascii wide
    $support_2 = "GetProcAddress" ascii wide
    $support_3 = "VirtualAlloc" ascii wide
  condition:
    filesize < 20MB and 1 of ($reflective_*) and 2 of ($support_*)
}

rule Proton_Direct_Syscall_Stub_Loader
{
  meta:
    description = "Kullanıcı modu kancalarını atlamak için doğrudan syscall kullanan yükleyici"
    severity = "high"
    category = "loader"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $nt_1 = "NtAllocateVirtualMemory" ascii wide
    $nt_2 = "NtWriteVirtualMemory" ascii wide
    $nt_3 = "NtProtectVirtualMemory" ascii wide
    $nt_4 = "NtCreateThreadEx" ascii wide
    $nt_5 = "NtOpenProcess" ascii wide
    $nt_6 = "NtResumeThread" ascii wide
    $stub_1 = "SysWhispers" ascii wide
    $stub_2 = "HellsGate" ascii wide
    $stub_3 = "HalosGate" ascii wide
    $stub_4 = "syscall_stub" ascii wide
  condition:
    uint16(0) == 0x5a4d and filesize < 20MB
    and (4 of ($nt_*) or (2 of ($nt_*) and 1 of ($stub_*)))
}

rule Proton_Resource_Embedded_Payload_Dropper
{
  meta:
    description = "Kaynak bölümünden yük çıkarıp çalıştıran damlalık"
    severity = "medium"
    category = "dropper"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $res_1 = "FindResource" ascii wide
    $res_2 = "LoadResource" ascii wide
    $res_3 = "LockResource" ascii wide
    $res_4 = "SizeofResource" ascii wide
    $run_1 = "CreateProcess" ascii wide
    $run_2 = "ShellExecute" ascii wide
    $run_3 = "WinExec" ascii wide
    $write_1 = "WriteFile" ascii wide
    $write_2 = "VirtualProtect" ascii wide
  condition:
    uint16(0) == 0x5a4d and filesize < 20MB
    and 3 of ($res_*) and 1 of ($run_*) and 1 of ($write_*)
}

rule Proton_Temp_Drop_And_Autorun_Dropper
{
  meta:
    description = "Geçici klasöre dosya yazıp başlangıç konumuna kopyalayan damlalık"
    severity = "medium"
    category = "dropper"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $temp_1 = "GetTempPath" ascii wide
    $temp_2 = "\\AppData\\Local\\Temp" ascii wide nocase
    $temp_3 = "%TEMP%" ascii wide nocase
    $startup_1 = "\\Start Menu\\Programs\\Startup" ascii wide nocase
    $startup_2 = "CurrentVersion\\Run" ascii wide nocase
    $startup_3 = "schtasks" ascii wide nocase
    $write_1 = "WriteFile" ascii wide
    $write_2 = "CopyFile" ascii wide
    $write_3 = "MoveFileEx" ascii wide
    $run_1 = "ShellExecute" ascii wide
    $run_2 = "CreateProcess" ascii wide
    $run_3 = "WinExec" ascii wide
  condition:
    uint16(0) == 0x5a4d and filesize < 20MB
    and 1 of ($temp_*) and 1 of ($startup_*) and 1 of ($write_*) and 1 of ($run_*)
}

rule Proton_Thread_Execution_Hijack
{
  meta:
    description = "Var olan iş parçacığının yürütme akışını ele geçiren enjeksiyon"
    severity = "high"
    category = "loader"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $suspend = "SuspendThread" ascii wide
    $get = "GetThreadContext" ascii wide
    $set = "SetThreadContext" ascii wide
    $resume = "ResumeThread" ascii wide
    $alloc = "VirtualAllocEx" ascii wide
    $write = "WriteProcessMemory" ascii wide
  condition:
    uint16(0) == 0x5a4d and filesize < 20MB
    and $suspend and $get and $set and $resume and ($alloc or $write)
}

rule Proton_Embedded_Second_Stage_PE
{
  meta:
    description = "Gövdesinde ikinci bir PE dosyası taşıyan ve kaynak/bellek yürütmesi yapan ikili"
    severity = "medium"
    category = "dropper"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $dos = "This program cannot be run in DOS mode"
    $api_1 = "VirtualAlloc" ascii
    $api_2 = "GetProcAddress" ascii
    $api_3 = "LoadLibraryA" ascii
    $api_4 = "CreateProcess" ascii
    $api_5 = "WriteProcessMemory" ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 20MB and #dos >= 2 and 3 of ($api_*)
}

rule Proton_Section_Mapping_Injection
{
  meta:
    description = "Paylaşılan bölüm eşlemesiyle uzak süreç enjeksiyonu"
    severity = "high"
    category = "loader"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $sec_1 = "NtCreateSection" ascii wide
    $sec_2 = "NtMapViewOfSection" ascii wide
    $sec_3 = "ZwMapViewOfSection" ascii wide
    $sec_4 = "NtUnmapViewOfSection" ascii wide
    $proc_1 = "NtOpenProcess" ascii wide
    $proc_2 = "OpenProcess" ascii wide
    $exec_1 = "RtlCreateUserThread" ascii wide
    $exec_2 = "NtCreateThreadEx" ascii wide
    $exec_3 = "CreateRemoteThread" ascii wide
  condition:
    uint16(0) == 0x5a4d and filesize < 20MB
    and 2 of ($sec_*) and 1 of ($proc_*) and 1 of ($exec_*)
}

rule Proton_Dll_Sideload_Proxy_Stub
{
  meta:
    description = "Meşru DLL adını taklit eden, yükleme sırasında yük çalıştıran vekil kütüphane"
    severity = "medium"
    category = "loader"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $entry_1 = "DllMain" ascii
    $entry_2 = "DllRegisterServer" ascii
    $entry_3 = "DllGetClassObject" ascii
    $chain_1 = "SetDllDirectory" ascii wide
    $chain_2 = "LoadLibraryEx" ascii wide
    $chain_3 = "GetModuleFileName" ascii wide
    $exec_1 = "CreateThread" ascii wide
    $exec_2 = "VirtualProtect" ascii wide
    $exec_3 = "VirtualAlloc" ascii wide
    $decode_1 = "CryptDecrypt" ascii wide
    $decode_2 = "RtlDecompressBuffer" ascii wide
    $decode_3 = "CryptStringToBinary" ascii wide
  condition:
    uint16(0) == 0x5a4d and filesize < 12MB
    and 1 of ($entry_*) and 1 of ($chain_*) and 2 of ($exec_*) and 1 of ($decode_*)
}
