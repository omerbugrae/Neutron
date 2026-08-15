/*
  Proton - Betik tabanlı damlalıklar ve sosyal mühendislik zincirleri.

  VBScript, JScript, HTA, toplu iş dosyası ve PowerShell tabanlı ilk aşama
  yükleyicileri hedefler. Betiklerin meşru kullanımı yaygın olduğundan her kural
  gizleme, indirme ve kalıcılık göstergelerini birlikte arar.
*/

rule Proton_Vbscript_Downloader_Chain
{
  meta:
    description = "VBScript ile dosya indirip çalıştıran ilk aşama damlalık"
    severity = "high"
    category = "script-dropper"
    confidence = "high"
    author = "Neutron detection engineering"
  strings:
    $obj_1 = "CreateObject(\"MSXML2.XMLHTTP\")" ascii wide nocase
    $obj_2 = "CreateObject(\"WinHttp.WinHttpRequest.5.1\")" ascii wide nocase
    $obj_3 = "CreateObject(\"ADODB.Stream\")" ascii wide nocase
    $obj_4 = "CreateObject(\"WScript.Shell\")" ascii wide nocase
    $obj_5 = "CreateObject(\"Scripting.FileSystemObject\")" ascii wide nocase
    $net_1 = ".Open \"GET\"" ascii wide nocase
    $net_2 = "responseBody" ascii wide nocase
    $net_3 = "SaveToFile" ascii wide nocase
    $run_1 = ".Run " ascii wide nocase
    $run_2 = ".Exec " ascii wide nocase
    $run_3 = "ShellExecute" ascii wide nocase
  condition:
    filesize < 2MB and 2 of ($obj_*) and 2 of ($net_*) and 1 of ($run_*)
}

rule Proton_Jscript_Obfuscated_Dropper
{
  meta:
    description = "Gizlenmiş JScript damlalığı ve ActiveX yürütme zinciri"
    severity = "high"
    category = "script-dropper"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $activex_1 = "ActiveXObject" ascii wide
    $activex_2 = "WScript.Shell" ascii wide nocase
    $activex_3 = "Scripting.FileSystemObject" ascii wide nocase
    $activex_4 = "MSXML2.XMLHTTP" ascii wide nocase
    $obf_1 = "String.fromCharCode" ascii wide nocase
    $obf_2 = "unescape(" ascii wide nocase
    $obf_3 = "eval(" ascii wide nocase
    $obf_4 = ".charCodeAt(" ascii wide nocase
    $obf_5 = "atob(" ascii wide nocase
    $obf_6 = "[\"split\"]" ascii wide nocase
    $exec_1 = ".Run(" ascii wide nocase
    $exec_2 = ".Exec(" ascii wide nocase
    $exec_3 = "WScript.CreateObject" ascii wide nocase
  condition:
    filesize < 2MB and 2 of ($activex_*) and 2 of ($obf_*) and 1 of ($exec_*)
}

rule Proton_Hta_Application_Loader
{
  meta:
    description = "HTA uygulaması içinde barındırılan yükleyici betiği"
    severity = "high"
    category = "script-dropper"
    confidence = "high"
    author = "Neutron detection engineering"
  strings:
    $hta_1 = "<hta:application" ascii wide nocase
    $hta_2 = "application/hta" ascii wide nocase
    $hta_3 = "windowState=\"minimize\"" ascii wide nocase
    $hta_4 = "showInTaskbar=\"no\"" ascii wide nocase
    $exec_1 = "WScript.Shell" ascii wide nocase
    $exec_2 = "cmd.exe /c" ascii wide nocase
    $exec_3 = "powershell" ascii wide nocase
    $exec_4 = "ActiveXObject" ascii wide nocase
    $exec_5 = "GetObject(\"script:" ascii wide nocase
  condition:
    filesize < 2MB and 1 of ($hta_*) and 2 of ($exec_*)
}

rule Proton_Batch_Obfuscated_Launcher
{
  meta:
    description = "Karakter değiştirme ile gizlenmiş toplu iş dosyası başlatıcısı"
    severity = "medium"
    category = "script-dropper"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $head_1 = "@echo off" ascii wide nocase
    $head_2 = "setlocal enabledelayedexpansion" ascii wide nocase
    $obf_1 = /set[ \t]+[A-Za-z_]{1,12}=[^\r\n]{0,40}%[A-Za-z_]{1,12}:~[0-9]{1,3},[0-9]{1,3}%/ ascii wide nocase
    $obf_2 = /%[A-Za-z_]{1,12}:~[0-9]{1,3},[0-9]{1,3}%/ ascii wide nocase
    $obf_3 = /\^[a-z]\^[a-z]\^[a-z]/ ascii wide nocase
    $launch_1 = "powershell" ascii wide nocase
    $launch_2 = "mshta" ascii wide nocase
    $launch_3 = "wscript" ascii wide nocase
    $launch_4 = "rundll32" ascii wide nocase
    $launch_5 = "certutil" ascii wide nocase
    $hide = /start[ \t]+\/(b|min)/ ascii wide nocase
  condition:
    filesize < 1MB and 1 of ($head_*) and #obf_2 >= 4 and 1 of ($launch_*) and (1 of ($obf_1, $obf_3) or $hide)
}

rule Proton_Powershell_Obfuscation_Heavy
{
  meta:
    description = "Yoğun gizleme kullanan PowerShell yükleyici"
    severity = "high"
    category = "script-dropper"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $obf_1 = /\[char\][ \t]*[0-9]{2,3}[ \t]*\+/ ascii wide nocase
    $obf_2 = /-join[ \t]*\(/ ascii wide nocase
    $obf_3 = /\[Convert\]::FromBase64String/ ascii wide nocase
    $obf_4 = /\[Text\.Encoding\]::(UTF8|Unicode|ASCII)\.GetString/ ascii wide nocase
    $obf_5 = /\[System\.IO\.Compression\.(GZipStream|DeflateStream)\]/ ascii wide nocase
    $obf_6 = /\$\{[a-zA-Z0-9_]{1,20}\}/ ascii wide
    $obf_7 = /['"]\+['"]/ ascii wide
    $exec_1 = "Invoke-Expression" ascii wide nocase
    $exec_2 = /\biex\b/ ascii wide nocase
    $exec_3 = ".Invoke(" ascii wide nocase
    $exec_4 = "Start-Process" ascii wide nocase
    $mem_1 = "System.Reflection.Assembly" ascii wide nocase
    $mem_2 = "GetDelegateForFunctionPointer" ascii wide nocase
    $mem_3 = "VirtualAlloc" ascii wide nocase
  condition:
    filesize < 5MB and 3 of ($obf_*) and (1 of ($exec_*) or 1 of ($mem_*))
}

rule Proton_Powershell_Inmemory_Shellcode_Runner
{
  meta:
    description = "PowerShell içinde Win32 API tanımlayarak shellcode çalıştırma"
    severity = "critical"
    category = "script-dropper"
    confidence = "high"
    author = "Neutron detection engineering"
  strings:
    $api_1 = "VirtualAlloc" ascii wide nocase
    $api_2 = "CreateThread" ascii wide nocase
    $api_3 = "memset" ascii wide nocase
    $api_4 = "WaitForSingleObject" ascii wide nocase
    $api_5 = "VirtualProtect" ascii wide nocase
    $reflect_1 = "System.Reflection.Emit" ascii wide nocase
    $reflect_2 = "DefineDynamicAssembly" ascii wide nocase
    $reflect_3 = "GetDelegateForFunctionPointer" ascii wide nocase
    $reflect_4 = "Add-Type" ascii wide nocase
    $reflect_5 = "DllImport" ascii wide nocase
    $buffer_1 = /\[Byte\[\]\][ \t]*\$/ ascii wide nocase
    $buffer_2 = "0xfc,0x48" ascii wide nocase
    $buffer_3 = "Copy(" ascii wide nocase
  condition:
    filesize < 5MB and 2 of ($api_*) and 2 of ($reflect_*) and 1 of ($buffer_*)
}

rule Proton_ClickFix_Clipboard_Social_Engineering
{
  meta:
    description = "Kullanıcıya panodaki komutu Çalıştır kutusuna yapıştırtan sahte doğrulama sayfası"
    severity = "high"
    category = "social-engineering"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $clip_1 = "navigator.clipboard.writeText" ascii wide nocase
    $clip_2 = "document.execCommand('copy')" ascii wide nocase
    $clip_3 = "document.execCommand(\"copy\")" ascii wide nocase
    $lure_1 = "Press Windows + R" ascii wide nocase
    $lure_2 = "Windows Key + R" ascii wide nocase
    $lure_3 = "Ctrl + V" ascii wide nocase
    $lure_4 = "I'm not a robot" ascii wide nocase
    $lure_5 = "Verify you are human" ascii wide nocase
    $lure_6 = "Robot değilim" ascii wide nocase
    $payload_1 = "powershell" ascii wide nocase
    $payload_2 = "mshta" ascii wide nocase
    $payload_3 = "curl " ascii wide nocase
    $payload_4 = "conhost --headless" ascii wide nocase
  condition:
    filesize < 3MB and 1 of ($clip_*) and 2 of ($lure_*) and 1 of ($payload_*)
}

rule Proton_Wsf_Xml_Script_Container
{
  meta:
    description = "WSF kapsayıcısında gizlenmiş indirici betik"
    severity = "high"
    category = "script-dropper"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $wsf_1 = "<job id=" ascii wide nocase
    $wsf_2 = "<script language=" ascii wide nocase
    $wsf_3 = "</job>" ascii wide nocase
    $net_1 = "XMLHTTP" ascii wide nocase
    $net_2 = "WinHttpRequest" ascii wide nocase
    $net_3 = "ADODB.Stream" ascii wide nocase
    $exec_1 = "WScript.Shell" ascii wide nocase
    $exec_2 = "ShellExecute" ascii wide nocase
    $exec_3 = ".Run(" ascii wide nocase
  condition:
    filesize < 2MB and 2 of ($wsf_*) and 1 of ($net_*) and 1 of ($exec_*)
}

rule Proton_Autoit_Compiled_Script_Loader
{
  meta:
    description = "AutoIt ile derlenmiş, bellek enjeksiyonu yapan yükleyici"
    severity = "high"
    category = "loader"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $autoit_1 = "AutoIt v3" ascii wide
    $autoit_2 = "AU3!EA06" ascii
    $autoit_3 = ">>>AUTOIT NO CMDEXECUTE<<<" ascii
    $inject_1 = "DllStructCreate" ascii wide nocase
    $inject_2 = "DllCallAddress" ascii wide nocase
    $inject_3 = "VirtualAllocEx" ascii wide nocase
    $inject_4 = "WriteProcessMemory" ascii wide nocase
    $inject_5 = "kernel32.dll" ascii wide nocase
  condition:
    filesize < 20MB and 1 of ($autoit_*) and 2 of ($inject_*)
}

rule Proton_Lnk_Shortcut_Command_Launcher
{
  meta:
    description = "Kısayol dosyası içinde gizlenmiş komut satırı yükleyici"
    severity = "high"
    category = "script-dropper"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $magic = { 4C 00 00 00 01 14 02 00 00 00 00 00 C0 00 00 00 00 00 00 46 }
    $cmd_1 = "powershell" ascii wide nocase
    $cmd_2 = "cmd.exe" ascii wide nocase
    $cmd_3 = "mshta" ascii wide nocase
    $cmd_4 = "wscript" ascii wide nocase
    $cmd_5 = "curl" ascii wide nocase
    $bad_1 = "-nop" ascii wide nocase
    $bad_2 = "-w hidden" ascii wide nocase
    $bad_3 = "-enc" ascii wide nocase
    $bad_4 = "FromBase64String" ascii wide nocase
    $bad_5 = "DownloadString" ascii wide nocase
    $bad_6 = "Invoke-Expression" ascii wide nocase
    $bad_7 = "http://" ascii wide nocase
    $bad_8 = "https://" ascii wide nocase
  condition:
    $magic at 0 and filesize < 2MB and 1 of ($cmd_*) and 1 of ($bad_*)
}

rule Proton_Xll_Excel_Addin_Loader
{
  meta:
    description = "Excel XLL eklentisi biçiminde dağıtılan yükleyici"
    severity = "high"
    category = "maldoc"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $xll_1 = "xlAutoOpen" ascii
    $xll_2 = "xlAutoClose" ascii
    $xll_3 = "xlAutoFree" ascii
    $net_1 = "URLDownloadToFile" ascii wide
    $net_2 = "InternetOpenUrl" ascii wide
    $net_3 = "WinHttpOpen" ascii wide
    $exec_1 = "VirtualAlloc" ascii wide
    $exec_2 = "CreateThread" ascii wide
    $exec_3 = "ShellExecute" ascii wide
    $exec_4 = "CreateProcess" ascii wide
  condition:
    uint16(0) == 0x5a4d and filesize < 10MB
    and $xll_1 and 1 of ($xll_2, $xll_3) and (1 of ($net_*) or 2 of ($exec_*))
}
