/*
  Proton - Sistemle gelen ikili dosyaların (LOLBin) kötüye kullanımı.

  Kurallar komut satırı kalıplarına bakar. Meşru yönetim betikleri bu ikilileri
  kullanabildiği için her kural indirme, çözme veya uzak yürütme göstergesiyle
  birlikte eşleşme arar.
*/

rule Proton_Certutil_Download_Or_Decode_Abuse
{
  meta:
    description = "certutil ile dosya indirme veya base64 yük çözme"
    severity = "high"
    category = "lolbin"
    confidence = "high"
    author = "Neutron detection engineering"
  strings:
    $url = /certutil(\.exe)?[^\r\n]{0,120}-urlcache/ ascii wide nocase
    $split = /certutil(\.exe)?[^\r\n]{0,120}-split/ ascii wide nocase
    $decode = /certutil(\.exe)?[^\r\n]{0,120}-decode/ ascii wide nocase
    $encodehex = /certutil(\.exe)?[^\r\n]{0,120}-decodehex/ ascii wide nocase
    $http = /https?:\/\// ascii wide nocase
  condition:
    filesize < 5MB and (($url and $http) or ($split and $http) or $decode or $encodehex)
}

rule Proton_Bitsadmin_Transfer_Abuse
{
  meta:
    description = "bitsadmin ile arka planda yük indirme"
    severity = "high"
    category = "lolbin"
    confidence = "high"
    author = "Neutron detection engineering"
  strings:
    $bits = /bitsadmin(\.exe)?[ \t]+\/(transfer|create|addfile)/ ascii wide nocase
    $ps_bits = /Start-BitsTransfer[ \t]+-Source/ ascii wide nocase
    $http = /https?:\/\/[^\s"']{4,}/ ascii wide nocase
  condition:
    filesize < 5MB and ($bits or $ps_bits) and $http
}

rule Proton_Mshta_Remote_Script_Execution
{
  meta:
    description = "mshta ile uzak veya satır içi betik çalıştırma"
    severity = "high"
    category = "lolbin"
    confidence = "high"
    author = "Neutron detection engineering"
  strings:
    $mshta = /mshta(\.exe)?[ \t]+/ ascii wide nocase
    $remote = /mshta(\.exe)?[ \t]+https?:\/\// ascii wide nocase
    $inline_1 = "javascript:" ascii wide nocase
    $inline_2 = "vbscript:" ascii wide nocase
    $inline_3 = "GetObject(\"script:" ascii wide nocase
  condition:
    filesize < 5MB and ($remote or ($mshta and 1 of ($inline_*)))
}

rule Proton_Regsvr32_Scriptlet_Squiblydoo
{
  meta:
    description = "regsvr32 ile uzak scriptlet çalıştırma (Squiblydoo)"
    severity = "high"
    category = "lolbin"
    confidence = "high"
    author = "Neutron detection engineering"
  strings:
    $regsvr = /regsvr32(\.exe)?[^\r\n]{0,80}\/i:/ ascii wide nocase
    $silent = /regsvr32(\.exe)?[^\r\n]{0,80}\/s/ ascii wide nocase
    $scrobj = "scrobj.dll" ascii wide nocase
    $remote = /https?:\/\/[^\s"']{4,}\.(sct|dll|txt)/ ascii wide nocase
  condition:
    filesize < 5MB and (($regsvr and $scrobj) or ($regsvr and $remote) or ($silent and $scrobj and $remote))
}

rule Proton_Rundll32_Suspicious_Entry_Point
{
  meta:
    description = "rundll32 ile şüpheli giriş noktası veya uzak kaynak çağrısı"
    severity = "high"
    category = "lolbin"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $rundll = /rundll32(\.exe)?[ \t]+/ ascii wide nocase
    $js = /rundll32(\.exe)?[^\r\n]{0,40}javascript:/ ascii wide nocase
    $url = /rundll32(\.exe)?[^\r\n]{0,60}url\.dll,[ \t]*(FileProtocolHandler|OpenURL)/ ascii wide nocase
    $comsvcs = /rundll32(\.exe)?[^\r\n]{0,60}comsvcs\.dll,[ \t]*MiniDump/ ascii wide nocase
    $advpack = /rundll32(\.exe)?[^\r\n]{0,60}(advpack|ieadvpack)\.dll,[ \t]*(LaunchINFSection|RegisterOCX)/ ascii wide nocase
    $shell32 = /rundll32(\.exe)?[^\r\n]{0,60}shell32\.dll,[ \t]*ShellExec_RunDLL/ ascii wide nocase
    $tempdll = /rundll32(\.exe)?[^\r\n]{0,120}(%temp%|%appdata%|\\AppData\\)/ ascii wide nocase
  condition:
    filesize < 5MB and $rundll and 1 of ($js, $url, $comsvcs, $advpack, $shell32, $tempdll)
}

rule Proton_Wmic_Remote_Process_And_Xsl_Abuse
{
  meta:
    description = "wmic ile uzak süreç oluşturma veya XSL betiği yürütme"
    severity = "high"
    category = "lolbin"
    confidence = "high"
    author = "Neutron detection engineering"
  strings:
    $create = /wmic(\.exe)?[^\r\n]{0,120}process[ \t]+call[ \t]+create/ ascii wide nocase
    $node = /wmic(\.exe)?[ \t]+\/node:/ ascii wide nocase
    $xsl = /wmic(\.exe)?[^\r\n]{0,120}\/format:[^\s"']{0,200}\.xsl/ ascii wide nocase
    $remotexsl = /\/format:["']?https?:\/\// ascii wide nocase
    $shadow = /wmic(\.exe)?[^\r\n]{0,80}shadowcopy[ \t]+delete/ ascii wide nocase
  condition:
    filesize < 5MB and (($create and $node) or $xsl or $remotexsl or ($create and $shadow))
}

rule Proton_Msbuild_And_Dotnet_Compiler_Abuse
{
  meta:
    description = "MSBuild veya .NET derleyicisi ile bellek içi kod çalıştırma"
    severity = "high"
    category = "lolbin"
    confidence = "high"
    author = "Neutron detection engineering"
  strings:
    $msbuild = "MSBuild.exe" ascii wide nocase
    $inline = "Microsoft.Build.Framework" ascii wide
    $task = "<Task" ascii wide nocase
    $codetask = "CodeTaskFactory" ascii wide nocase
    $usingtask = "UsingTask" ascii wide nocase
    $installutil = /installutil(\.exe)?[^\r\n]{0,80}\/logfile=/ ascii wide nocase
    $csc = /csc(\.exe)?[^\r\n]{0,80}\/target:library/ ascii wide nocase
    $exec = "GetDelegateForFunctionPointer" ascii wide
  condition:
    filesize < 10MB and
    (
      ($codetask and $usingtask and ($msbuild or $inline or $task))
      or $installutil
      or ($csc and $exec)
    )
}

rule Proton_Powershell_Download_Cradle_Variants
{
  meta:
    description = "PowerShell indirme ve bellek içi çalıştırma kalıpları"
    severity = "high"
    category = "script-execution"
    confidence = "high"
    author = "Neutron detection engineering"
  strings:
    $cradle_1 = /IEX[ \t]*\([ \t]*(New-Object|iwr|Invoke-WebRequest)/ ascii wide nocase
    $cradle_2 = /Invoke-Expression[ \t]*\([ \t]*(New-Object|iwr)/ ascii wide nocase
    $cradle_3 = /\.DownloadString\([ \t]*['"]https?:/ ascii wide nocase
    $cradle_4 = /\.DownloadData\([ \t]*['"]https?:/ ascii wide nocase
    $cradle_5 = /Net\.WebClient[^\r\n]{0,80}DownloadFile/ ascii wide nocase
    $cradle_6 = /Invoke-RestMethod[^\r\n]{0,80}\|[ \t]*(iex|Invoke-Expression)/ ascii wide nocase
    $flag_1 = /-(nop|noprofile)\b/ ascii wide nocase
    $flag_2 = /-(w|windowstyle)[ \t]+hidden/ ascii wide nocase
    $flag_3 = /-(ep|executionpolicy)[ \t]+bypass/ ascii wide nocase
  condition:
    filesize < 5MB and (1 of ($cradle_*) and 1 of ($flag_*) or 2 of ($cradle_*))
}

rule Proton_Curl_Certreq_Print_Download_Abuse
{
  meta:
    description = "curl, certreq veya print ikilisiyle dosya indirme ve yazma"
    severity = "medium"
    category = "lolbin"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $curl = /curl(\.exe)?[^\r\n]{0,120}-o[ \t]+[^\s"']{0,120}\.(exe|dll|ps1|bat|scr)/ ascii wide nocase
    $certreq = /certreq(\.exe)?[^\r\n]{0,60}-Post[^\r\n]{0,120}https?:\/\// ascii wide nocase
    $print = /print(\.exe)?[ \t]+\/D:[^\r\n]{0,120}\.(exe|dll)/ ascii wide nocase
    $extrac = /extrac32(\.exe)?[^\r\n]{0,120}\.cab/ ascii wide nocase
    $findstr = /findstr(\.exe)?[^\r\n]{0,60}\/V[^\r\n]{0,120}>[ \t]*[^\s"']{0,80}\.(exe|dll)/ ascii wide nocase
  condition:
    filesize < 5MB and 1 of them
}

rule Proton_Scheduled_Task_And_Service_Remote_Execution
{
  meta:
    description = "schtasks veya sc ile uzak makinede kalıcı yürütme oluşturma"
    severity = "high"
    category = "lolbin"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $sch_remote = /schtasks(\.exe)?[^\r\n]{0,120}\/s[ \t]+\\\\/ ascii wide nocase
    $sch_create = /schtasks(\.exe)?[^\r\n]{0,40}\/create/ ascii wide nocase
    $sch_hidden = /schtasks(\.exe)?[^\r\n]{0,200}(powershell|mshta|wscript|cscript|rundll32)/ ascii wide nocase
    $sc_remote = /sc(\.exe)?[ \t]+\\\\[^\s"']{1,64}[ \t]+create/ ascii wide nocase
    $sc_binpath = /binpath=[ \t]*["']?[^\r\n]{0,120}(cmd\.exe|powershell)/ ascii wide nocase
    $psexec = /psexec(\.exe)?[^\r\n]{0,60}\\\\/ ascii wide nocase
  condition:
    filesize < 5MB and (($sch_create and $sch_hidden) or $sch_remote or $sc_remote or ($sc_binpath and $sch_create) or $psexec)
}

rule Proton_Msiexec_And_Cmstp_Remote_Package
{
  meta:
    description = "msiexec veya cmstp ile uzak paket üzerinden yürütme"
    severity = "high"
    category = "lolbin"
    confidence = "high"
    author = "Neutron detection engineering"
  strings:
    $msi = /msiexec(\.exe)?[^\r\n]{0,80}\/(i|package)[ \t]+["']?https?:\/\// ascii wide nocase
    $msi_quiet = /msiexec(\.exe)?[^\r\n]{0,120}\/q(n|uiet)/ ascii wide nocase
    $cmstp = /cmstp(\.exe)?[^\r\n]{0,60}\/(s|ns)[ \t]+[^\s"']{0,120}\.inf/ ascii wide nocase
    $inf = "RegisterOCXSection" ascii wide nocase
  condition:
    filesize < 5MB and ($msi or ($msi_quiet and $inf) or $cmstp or ($inf and $cmstp))
}

rule Proton_Odbcconf_Verclsid_Xwizard_Proxy_Execution
{
  meta:
    description = "Az bilinen sistem ikilileriyle vekil kod çalıştırma"
    severity = "medium"
    category = "lolbin"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $odbc = /odbcconf(\.exe)?[^\r\n]{0,80}\/a[ \t]*\{[ \t]*REGSVR/ ascii wide nocase
    $verclsid = /verclsid(\.exe)?[^\r\n]{0,80}\/S[ \t]+\/C[ \t]+\{/ ascii wide nocase
    $xwizard = /xwizard(\.exe)?[^\r\n]{0,80}RunWizard/ ascii wide nocase
    $pcalua = /pcalua(\.exe)?[^\r\n]{0,60}-a[ \t]+/ ascii wide nocase
    $forfiles = /forfiles(\.exe)?[^\r\n]{0,120}\/c[ \t]+["']?cmd/ ascii wide nocase
    $conhost = /conhost(\.exe)?[^\r\n]{0,60}--headless/ ascii wide nocase
  condition:
    filesize < 5MB and 1 of them
}
