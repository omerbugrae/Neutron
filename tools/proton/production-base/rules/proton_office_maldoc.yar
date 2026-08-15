/*
  Proton - Office belgesi ve doküman tabanlı saldırı zincirleri.

  OLE makroları, Excel 4.0 (XLM) makroları, RTF nesne yerleştirme, uzak şablon
  enjeksiyonu ve OneNote gömülü yük kalıplarını kapsar. Kurallar belge kapsayıcı
  imzasını da doğrular; düz metin içinde geçen anahtar kelimeler tek başına
  yeterli sayılmaz.
*/

rule Proton_Ole_Macro_Autoexec_Shell
{
  meta:
    description = "Otomatik çalışan VBA makrosu içinde kabuk yürütme"
    severity = "high"
    category = "maldoc"
    confidence = "high"
    author = "Neutron detection engineering"
  strings:
    $ole = { D0 CF 11 E0 A1 B1 1A E1 }
    $auto_1 = "AutoOpen" ascii wide nocase
    $auto_2 = "AutoExec" ascii wide nocase
    $auto_3 = "Document_Open" ascii wide nocase
    $auto_4 = "Workbook_Open" ascii wide nocase
    $auto_5 = "Auto_Open" ascii wide nocase
    $auto_6 = "Document_Close" ascii wide nocase
    $exec_1 = "Shell(" ascii wide nocase
    $exec_2 = "WScript.Shell" ascii wide nocase
    $exec_3 = "CreateObject" ascii wide nocase
    $exec_4 = "Win32_Process" ascii wide nocase
    $exec_5 = "powershell" ascii wide nocase
    $exec_6 = "cmd.exe" ascii wide nocase
  condition:
    $ole at 0 and filesize < 20MB and 1 of ($auto_*) and 2 of ($exec_*)
}

rule Proton_Vba_Payload_Download_And_Write
{
  meta:
    description = "VBA makrosunda indirme ve diske yazma zinciri"
    severity = "high"
    category = "maldoc"
    confidence = "high"
    author = "Neutron detection engineering"
  strings:
    $container_1 = { D0 CF 11 E0 A1 B1 1A E1 }
    $container_2 = { 50 4B 03 04 }
    $vba = "vbaProject.bin" ascii nocase
    $net_1 = "MSXML2.XMLHTTP" ascii wide nocase
    $net_2 = "WinHttp.WinHttpRequest" ascii wide nocase
    $net_3 = "URLDownloadToFile" ascii wide nocase
    $net_4 = "ServerXMLHTTP" ascii wide nocase
    $write_1 = "ADODB.Stream" ascii wide nocase
    $write_2 = "SaveToFile" ascii wide nocase
    $write_3 = "Scripting.FileSystemObject" ascii wide nocase
    $write_4 = "Environ(\"TEMP\")" ascii wide nocase
    $run_1 = "Shell(" ascii wide nocase
    $run_2 = ".Run " ascii wide nocase
    $run_3 = "ShellExecute" ascii wide nocase
  condition:
    filesize < 20MB and ($container_1 at 0 or ($container_2 at 0 and $vba))
    and 1 of ($net_*) and 1 of ($write_*) and 1 of ($run_*)
}

rule Proton_Vba_String_Obfuscation_Chain
{
  meta:
    description = "VBA içinde karakter birleştirme ile gizlenmiş komut üretimi"
    severity = "medium"
    category = "maldoc"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $ole = { D0 CF 11 E0 A1 B1 1A E1 }
    $obf_1 = /Chr\([ \t]*[0-9]{1,3}[ \t]*\)[ \t]*&/ ascii wide nocase
    $obf_2 = "StrReverse(" ascii wide nocase
    $obf_3 = /Mid\([ \t]*[A-Za-z_]{1,20}[ \t]*,[ \t]*[0-9]{1,4}/ ascii wide nocase
    $obf_4 = "Replace(" ascii wide nocase
    $obf_5 = "Asc(" ascii wide nocase
    $exec_1 = "Shell" ascii wide nocase
    $exec_2 = "CreateObject" ascii wide nocase
    $exec_3 = "CallByName" ascii wide nocase
    $exec_4 = "Application.Run" ascii wide nocase
  condition:
    $ole at 0 and filesize < 20MB and (#obf_1 >= 8 or 3 of ($obf_*)) and 1 of ($exec_*)
}

rule Proton_Excel4_Xlm_Macro_Abuse
{
  meta:
    description = "Excel 4.0 makro sayfası ile dış çağrı ve indirme"
    severity = "high"
    category = "maldoc"
    confidence = "high"
    author = "Neutron detection engineering"
  strings:
    $container_1 = { D0 CF 11 E0 A1 B1 1A E1 }
    $container_2 = { 50 4B 03 04 }
    $xlm_1 = "Excel 4.0 Macro" ascii wide nocase
    $xlm_2 = "xlnm._FilterDatabase" ascii wide nocase
    $xlm_3 = "macrosheet" ascii nocase
    $call_1 = "=EXEC(" ascii wide nocase
    $call_2 = "=CALL(" ascii wide nocase
    $call_3 = "=REGISTER(" ascii wide nocase
    $call_4 = "URLDownloadToFileA" ascii wide nocase
    $call_5 = "=FORMULA(" ascii wide nocase
  condition:
    filesize < 20MB and ($container_1 at 0 or $container_2 at 0)
    and 1 of ($xlm_*) and 2 of ($call_*)
}

rule Proton_Rtf_Embedded_Object_Exploit
{
  meta:
    description = "RTF içinde gömülü nesne veya bilinen denklem düzenleyici istismarı"
    severity = "high"
    category = "maldoc"
    confidence = "high"
    author = "Neutron detection engineering"
  strings:
    $rtf = "{\\rt" ascii
    $obj_1 = "\\objdata" ascii nocase
    $obj_2 = "\\objupdate" ascii nocase
    $obj_3 = "\\objocx" ascii nocase
    $obj_4 = "\\objautlink" ascii nocase
    $eq_1 = "Equation.3" ascii nocase
    $eq_2 = "4571756174696f6e2e33" ascii nocase
    $eq_3 = "d0cf11e0a1b11ae1" ascii nocase
    $ole_1 = "OLE2Link" ascii nocase
    $ole_2 = "\\*\\objclass" ascii nocase
  condition:
    $rtf at 0 and filesize < 20MB and 1 of ($obj_*) and 1 of ($eq_*, $ole_*)
}

rule Proton_Remote_Template_Injection
{
  meta:
    description = "Uzak şablon çağrısıyla ikinci aşama makro yükleme"
    severity = "high"
    category = "maldoc"
    confidence = "high"
    author = "Neutron detection engineering"
  strings:
    $zip = { 50 4B 03 04 }
    $rels_1 = "attachedTemplate" ascii nocase
    $rels_2 = "oleObject" ascii nocase
    $rels_3 = "frameset" ascii nocase
    $ext_1 = "TargetMode=\"External\"" ascii nocase
    $remote_1 = "http://" ascii nocase
    $remote_2 = "https://" ascii nocase
    $remote_3 = "\\\\" ascii
    $suspicious = /\.(dotm|dot|docm|rtf|hta)["'\s]/ ascii nocase
  condition:
    $zip at 0 and filesize < 20MB and 1 of ($rels_*) and $ext_1
    and 1 of ($remote_*) and $suspicious
}

rule Proton_OneNote_Embedded_Payload
{
  meta:
    description = "OneNote bölümüne gömülü çalıştırılabilir veya betik yükü"
    severity = "high"
    category = "maldoc"
    confidence = "high"
    author = "Neutron detection engineering"
  strings:
    $onenote = { E4 52 5C 7B 8C D8 A7 4D AE B1 53 78 D0 29 96 D3 }
    $embed_1 = "FileDataStoreObject" ascii wide nocase
    $embed_2 = ".cmd" ascii wide nocase
    $embed_3 = ".bat" ascii wide nocase
    $embed_4 = ".vbs" ascii wide nocase
    $embed_5 = ".hta" ascii wide nocase
    $embed_6 = ".ps1" ascii wide nocase
    $mz = "This program cannot be run in DOS mode"
  condition:
    $onenote at 0 and filesize < 30MB and (2 of ($embed_*) or $mz)
}

rule Proton_Pdf_Javascript_Launch_Action
{
  meta:
    description = "PDF içinde otomatik JavaScript veya harici başlatma eylemi"
    severity = "medium"
    category = "maldoc"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $pdf = "%PDF-"
    $act_1 = "/OpenAction" ascii nocase
    $act_2 = "/AA" ascii
    $js_1 = "/JavaScript" ascii nocase
    $js_2 = "/JS" ascii
    $launch_1 = "/Launch" ascii nocase
    $launch_2 = "/EmbeddedFile" ascii nocase
    $launch_3 = "/URI" ascii
    $bad_1 = "cmd.exe" ascii nocase
    $bad_2 = "powershell" ascii nocase
    $bad_3 = "app.launchURL" ascii nocase
    $bad_4 = "exportDataObject" ascii nocase
    $bad_5 = "unescape(" ascii nocase
  condition:
    $pdf at 0 and filesize < 20MB and 1 of ($act_*)
    and (1 of ($js_*) or 1 of ($launch_*)) and 1 of ($bad_*)
}

rule Proton_Office_Dde_Field_Execution
{
  meta:
    description = "DDE alanı üzerinden harici komut çalıştırma"
    severity = "high"
    category = "maldoc"
    confidence = "high"
    author = "Neutron detection engineering"
  strings:
    $dde_1 = "DDEAUTO" ascii wide nocase
    $dde_2 = "dde " ascii wide nocase
    $cmd_1 = "c:\\\\windows\\\\system32\\\\cmd.exe" ascii wide nocase
    $cmd_2 = "powershell" ascii wide nocase
    $cmd_3 = "mshta" ascii wide nocase
    $cmd_4 = "\\\\..\\\\..\\\\" ascii wide
  condition:
    filesize < 20MB and 1 of ($dde_1, $dde_2) and 1 of ($cmd_*)
}

rule Proton_Iso_Img_Container_Lure
{
  meta:
    description = "E-posta ile dağıtılan disk imajı içinde kısayol ve gizli yük"
    severity = "medium"
    category = "maldoc"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $iso = "CD001"
    $udf = "NSR0"
    $lnk = ".lnk" ascii wide nocase
    $script_1 = ".vbs" ascii wide nocase
    $script_2 = ".js" ascii wide nocase
    $script_3 = ".bat" ascii wide nocase
    $script_4 = ".cmd" ascii wide nocase
    $dll = ".dll" ascii wide nocase
    $mz = "This program cannot be run in DOS mode"
  condition:
    filesize < 60MB and ($iso or $udf) and $lnk and (1 of ($script_*) or ($dll and $mz))
}
