/*
  Proton - .NET tabanlı yükleyiciler ve bellek içi derleme çalıştırma.

  Yönetilen kod içinde yansıma, P/Invoke ve derleme yükleme birlikte
  kullanıldığında ortaya çıkan yükleyici kalıplarını hedefler.
*/

rule Proton_Dotnet_Reflective_Assembly_Load
{
  meta:
    description = "Bellekten .NET derlemesi yükleyip çalıştıran yansıma zinciri"
    severity = "high"
    category = "loader"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $net = "mscoree.dll" ascii
    $load_1 = "System.Reflection.Assembly" ascii wide
    $load_2 = "Assembly.Load" ascii wide
    $load_3 = "GetManifestResourceStream" ascii wide
    $load_4 = "EntryPoint" ascii wide fullword
    $load_5 = "GetType" ascii wide fullword
    $load_6 = "InvokeMember" ascii wide
    $decode_1 = "FromBase64String" ascii wide
    $decode_2 = "GZipStream" ascii wide
    $decode_3 = "DeflateStream" ascii wide
    $decode_4 = "RijndaelManaged" ascii wide
    $decode_5 = "AesCryptoServiceProvider" ascii wide
  condition:
    uint16(0) == 0x5a4d and filesize < 40MB
    and $net and 3 of ($load_*) and 1 of ($decode_*)
}

rule Proton_Dotnet_PInvoke_Injection_Surface
{
  meta:
    description = ".NET içinden Win32 enjeksiyon API'lerini çağıran yükleyici"
    severity = "critical"
    category = "loader"
    confidence = "high"
    author = "Neutron detection engineering"
  strings:
    $net = "mscoree.dll" ascii
    $pinvoke_1 = "DllImportAttribute" ascii wide
    $pinvoke_2 = "GetDelegateForFunctionPointer" ascii wide
    $pinvoke_3 = "Marshal" ascii wide fullword
    $api_1 = "VirtualAllocEx" ascii wide
    $api_2 = "WriteProcessMemory" ascii wide
    $api_3 = "CreateRemoteThread" ascii wide
    $api_4 = "NtUnmapViewOfSection" ascii wide
    $api_5 = "SetThreadContext" ascii wide
    $api_6 = "VirtualProtect" ascii wide
    $api_7 = "CreateThread" ascii wide
  condition:
    uint16(0) == 0x5a4d and filesize < 40MB
    and $net and 1 of ($pinvoke_*) and 3 of ($api_*)
}

rule Proton_Dotnet_Runpe_Hollowing_Helper
{
  meta:
    description = ".NET RunPE yardımcı sınıfı ve süreç oyma kalıntıları"
    severity = "critical"
    category = "loader"
    confidence = "high"
    author = "Neutron detection engineering"
  strings:
    $net = "mscoree.dll" ascii
    $runpe_1 = "RunPE" ascii wide
    $runpe_2 = "PROCESS_INFORMATION" ascii wide
    $runpe_3 = "STARTUPINFO" ascii wide
    $runpe_4 = "CONTEXT" ascii wide fullword
    $runpe_5 = "ZwUnmapViewOfSection" ascii wide
    $runpe_6 = "ResumeThread" ascii wide
    $runpe_7 = "CREATE_SUSPENDED" ascii wide
    $target_1 = "RegAsm.exe" ascii wide nocase
    $target_2 = "AppLaunch.exe" ascii wide nocase
    $target_3 = "MSBuild.exe" ascii wide nocase
    $target_4 = "InstallUtil.exe" ascii wide nocase
    $target_5 = "aspnet_compiler.exe" ascii wide nocase
  condition:
    uint16(0) == 0x5a4d and filesize < 40MB
    and $net and (3 of ($runpe_*) or (1 of ($target_*) and 2 of ($runpe_*)))
}

rule Proton_Dotnet_Amsi_Etw_Bypass_Managed
{
  meta:
    description = "Yönetilen kod içinde AMSI ve ETW devre dışı bırakma"
    severity = "critical"
    category = "defense-evasion"
    confidence = "high"
    author = "Neutron detection engineering"
  strings:
    $net = "mscoree.dll" ascii
    $amsi_1 = "AmsiScanBuffer" ascii wide
    $amsi_2 = "amsi.dll" ascii wide nocase
    $amsi_3 = "amsiInitFailed" ascii wide
    $etw_1 = "EtwEventWrite" ascii wide
    $etw_2 = "ntdll.dll" ascii wide nocase
    $patch_1 = "VirtualProtect" ascii wide
    $patch_2 = "Marshal.Copy" ascii wide
    $patch_3 = "GetProcAddress" ascii wide
  condition:
    uint16(0) == 0x5a4d and filesize < 40MB
    and $net and (1 of ($amsi_*) or 1 of ($etw_*)) and 2 of ($patch_*)
}

rule Proton_Dotnet_Runtime_Compile_And_Execute
{
  meta:
    description = "Kaynak kodu çalışma anında derleyip çalıştıran .NET yükleyici"
    severity = "high"
    category = "loader"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $net = "mscoree.dll" ascii
    $compile_1 = "CSharpCodeProvider" ascii wide
    $compile_2 = "CompileAssemblyFromSource" ascii wide
    $compile_3 = "CompilerParameters" ascii wide
    $compile_4 = "GenerateInMemory" ascii wide
    $compile_5 = "Microsoft.CSharp" ascii wide
    $exec_1 = "CompiledAssembly" ascii wide
    $exec_2 = "CreateInstance" ascii wide
    $exec_3 = "Invoke" ascii wide fullword
  condition:
    uint16(0) == 0x5a4d and filesize < 40MB
    and $net and 3 of ($compile_*) and 1 of ($exec_*)
}
