/*
  Proton - Paketleyici, şifreleyici ve koruyucu kalıntıları.

  Paketleme tek başına kötü amaçlı değildir; ticari koruyucular meşru
  yazılımlarda da kullanılır. Bu yüzden kurallar paketleyici izini tek başına
  raporlamaz, ek çalışma zamanı davranışı arar ve severity düşük tutulur.
*/

rule Proton_Modified_Upx_Header_Stub
{
  meta:
    description = "Bölüm adları değiştirilmiş UPX benzeri paketleme"
    severity = "low"
    category = "packer"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $upx_1 = "UPX0" ascii
    $upx_2 = "UPX1" ascii
    $upx_3 = "UPX!" ascii
    $stub = "$Info: This file is packed with the UPX executable packer" ascii
    $runtime_1 = "VirtualAlloc" ascii
    $runtime_2 = "VirtualProtect" ascii
    $runtime_3 = "LoadLibraryA" ascii
    $runtime_4 = "GetProcAddress" ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 20MB
    and (($upx_1 and $upx_2 and not $stub) or ($upx_3 and not $stub))
    and 3 of ($runtime_*)
}

rule Proton_Dotnet_Protector_Obfuscation_Marker
{
  meta:
    description = ".NET koruyucu veya karıştırıcı ile korunmuş derleme"
    severity = "low"
    category = "packer"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $net = "mscoree.dll" ascii
    $prot_1 = "ConfusedByAttribute" ascii wide
    $prot_2 = "SmartAssembly" ascii wide
    $prot_3 = "Babel Obfuscator" ascii wide
    $prot_4 = "Eazfuscator" ascii wide
    $prot_5 = ".NETReactor" ascii wide
    $prot_6 = "DotfuscatorAttribute" ascii wide
    $prot_7 = "Agile.NET" ascii wide
    $runtime_1 = "System.Reflection.Assembly" ascii wide
    $runtime_2 = "GetManifestResourceStream" ascii wide
    $runtime_3 = "Invoke" ascii wide fullword
  condition:
    uint16(0) == 0x5a4d and filesize < 40MB
    and $net and 1 of ($prot_*) and 2 of ($runtime_*)
}

rule Proton_Runtime_Unpacking_Memory_Stub
{
  meta:
    description = "Çalışma anında kendini açıp bellekte çalıştıran koruma katmanı"
    severity = "medium"
    category = "packer"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $alloc_1 = "VirtualAlloc" ascii
    $alloc_2 = "VirtualProtect" ascii
    $alloc_3 = "NtProtectVirtualMemory" ascii
    $resolve_1 = "LoadLibraryA" ascii
    $resolve_2 = "GetProcAddress" ascii
    $resolve_3 = "LdrLoadDll" ascii
    $decode_1 = "RtlDecompressBuffer" ascii
    $decode_2 = "CryptDecrypt" ascii
    $decode_3 = "aPLib" ascii
    $decode_4 = "lzma" ascii nocase
    $antidbg_1 = "IsDebuggerPresent" ascii
    $antidbg_2 = "NtQueryInformationProcess" ascii
    $antidbg_3 = "OutputDebugString" ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 20MB
    and 2 of ($alloc_*) and 2 of ($resolve_*) and 1 of ($decode_*) and 1 of ($antidbg_*)
}

rule Proton_High_Entropy_Resource_Carrier
{
  meta:
    description = "Yüksek entropili gömülü veriyi çözerek çalıştıran taşıyıcı"
    severity = "medium"
    category = "packer"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $res_1 = "FindResourceW" ascii
    $res_2 = "LockResource" ascii
    $res_3 = "SizeofResource" ascii
    $crypt_1 = "CryptCreateHash" ascii
    $crypt_2 = "CryptDeriveKey" ascii
    $crypt_3 = "CryptDecrypt" ascii
    $crypt_4 = "BCryptDecrypt" ascii
    $exec_1 = "VirtualAlloc" ascii
    $exec_2 = "CreateThread" ascii
    $exec_3 = "EnumResourceNamesW" ascii
    $marker = "RCDATA" ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 20MB
    and 2 of ($res_*) and 2 of ($crypt_*) and 2 of ($exec_*) and $marker
}

rule Proton_Overlay_Appended_Payload_Carrier
{
  meta:
    description = "Dosya sonuna eklenmiş yükü okuyup çalıştıran taşıyıcı"
    severity = "medium"
    category = "packer"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $self_1 = "GetModuleFileNameW" ascii
    $self_2 = "GetModuleFileNameA" ascii
    $read_1 = "SetFilePointerEx" ascii
    $read_2 = "ReadFile" ascii
    $read_3 = "GetFileSizeEx" ascii
    $exec_1 = "VirtualAlloc" ascii
    $exec_2 = "CreateProcessW" ascii
    $exec_3 = "WriteProcessMemory" ascii
    $exec_4 = "CreateThread" ascii
    $magic = "This program cannot be run in DOS mode"
  condition:
    uint16(0) == 0x5a4d and filesize < 20MB
    and 1 of ($self_*) and 3 of ($read_*) and 2 of ($exec_*) and #magic >= 2
}
