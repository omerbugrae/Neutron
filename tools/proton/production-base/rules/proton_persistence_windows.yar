/*
  Proton - Windows kalıcılık teknikleri.

  Kayıt defteri, zamanlanmış görev, hizmet, WMI olay aboneliği, COM ele geçirme
  ve oturum açma bileşenleri üzerinden kalıcılık kuran kod kalıpları.
*/

rule Proton_Registry_Autorun_Multi_Location
{
  meta:
    description = "Birden çok otomatik başlatma kayıt defteri konumuna yazma"
    severity = "medium"
    category = "persistence"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $key_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
    $key_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii wide nocase
    $key_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunServices" ascii wide nocase
    $key_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders" ascii wide nocase
    $key_5 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii wide nocase
    $key_6 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run" ascii wide nocase
    $write_1 = "RegSetValueEx" ascii wide
    $write_2 = "RegCreateKeyEx" ascii wide
    $write_3 = "reg add" ascii wide nocase
    $write_4 = "Set-ItemProperty" ascii wide nocase
    $write_5 = "New-ItemProperty" ascii wide nocase
    $target_1 = "%APPDATA%" ascii wide nocase
    $target_2 = "%TEMP%" ascii wide nocase
    $target_3 = "%PROGRAMDATA%" ascii wide nocase
    $target_4 = "powershell" ascii wide nocase
    $target_5 = "rundll32" ascii wide nocase
    $target_6 = "wscript" ascii wide nocase
  condition:
    filesize < 20MB and 2 of ($key_*) and 1 of ($write_*) and 1 of ($target_*)
}

rule Proton_Winlogon_Userinit_Shell_Hijack
{
  meta:
    description = "Winlogon Userinit veya Shell değerini değiştirerek kalıcılık"
    severity = "high"
    category = "persistence"
    confidence = "high"
    author = "Neutron detection engineering"
  strings:
    $key = "Windows NT\\CurrentVersion\\Winlogon" ascii wide nocase
    $value_1 = "Userinit" ascii wide nocase
    $value_2 = "Shell" ascii wide fullword nocase
    $value_3 = "Notify" ascii wide fullword nocase
    $write_1 = "RegSetValueEx" ascii wide
    $write_2 = "reg add" ascii wide nocase
    $write_3 = "Set-ItemProperty" ascii wide nocase
    $chain = "userinit.exe," ascii wide nocase
  condition:
    filesize < 20MB and $key and 1 of ($value_*) and (1 of ($write_*) or $chain)
}

rule Proton_Image_File_Execution_Options_Hijack
{
  meta:
    description = "IFEO veya silent process exit ile hata ayıklayıcı ele geçirme"
    severity = "high"
    category = "persistence"
    confidence = "high"
    author = "Neutron detection engineering"
  strings:
    $ifeo_1 = "Image File Execution Options" ascii wide nocase
    $ifeo_2 = "SilentProcessExit" ascii wide nocase
    $val_1 = "Debugger" ascii wide fullword nocase
    $val_2 = "MonitorProcess" ascii wide nocase
    $val_3 = "GlobalFlag" ascii wide nocase
    $bin_1 = "sethc.exe" ascii wide nocase
    $bin_2 = "utilman.exe" ascii wide nocase
    $bin_3 = "osk.exe" ascii wide nocase
    $bin_4 = "magnify.exe" ascii wide nocase
    $bin_5 = "narrator.exe" ascii wide nocase
    $bin_6 = "cmd.exe" ascii wide nocase
  condition:
    filesize < 20MB and 1 of ($ifeo_*) and 1 of ($val_*) and 1 of ($bin_*)
}

rule Proton_Wmi_Event_Subscription_Persistence
{
  meta:
    description = "WMI kalıcı olay aboneliği ile tetiklenen yük"
    severity = "high"
    category = "persistence"
    confidence = "high"
    author = "Neutron detection engineering"
  strings:
    $ns = "root\\subscription" ascii wide nocase
    $cls_1 = "__EventFilter" ascii wide nocase
    $cls_2 = "CommandLineEventConsumer" ascii wide nocase
    $cls_3 = "ActiveScriptEventConsumer" ascii wide nocase
    $cls_4 = "__FilterToConsumerBinding" ascii wide nocase
    $cls_5 = "__IntervalTimerInstruction" ascii wide nocase
    $query = "SELECT * FROM __InstanceModificationEvent" ascii wide nocase
  condition:
    filesize < 20MB and (2 of ($cls_*) or ($ns and 1 of ($cls_*)) or ($query and 1 of ($cls_*)))
}

rule Proton_Scheduled_Task_Xml_Hidden_Payload
{
  meta:
    description = "Gizli ve yükseltilmiş zamanlanmış görev tanımı"
    severity = "high"
    category = "persistence"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $sch_1 = "Microsoft.Win32.TaskScheduler" ascii wide nocase
    $sch_2 = "Schedule.Service" ascii wide nocase
    $sch_3 = "<Task version=" ascii wide nocase
    $sch_4 = "schtasks" ascii wide nocase
    $hide_1 = "<Hidden>true</Hidden>" ascii wide nocase
    $hide_2 = "HighestAvailable" ascii wide nocase
    $hide_3 = "/rl highest" ascii wide nocase
    $hide_4 = "/ru system" ascii wide nocase
    $trigger_1 = "<LogonTrigger" ascii wide nocase
    $trigger_2 = "<BootTrigger" ascii wide nocase
    $trigger_3 = "/sc onlogon" ascii wide nocase
    $trigger_4 = "/sc onstart" ascii wide nocase
    $trigger_5 = "/sc minute" ascii wide nocase
    $payload_1 = "powershell" ascii wide nocase
    $payload_2 = "mshta" ascii wide nocase
    $payload_3 = "rundll32" ascii wide nocase
    $payload_4 = "wscript" ascii wide nocase
    $payload_5 = "%APPDATA%" ascii wide nocase
  condition:
    filesize < 20MB and 1 of ($sch_*) and 1 of ($hide_*) and 1 of ($trigger_*) and 1 of ($payload_*)
}

rule Proton_Service_Install_Persistence
{
  meta:
    description = "Kalıcılık için otomatik başlayan hizmet oluşturma"
    severity = "medium"
    category = "persistence"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $api_1 = "OpenSCManager" ascii wide
    $api_2 = "CreateService" ascii wide
    $api_3 = "StartService" ascii wide
    $api_4 = "ChangeServiceConfig" ascii wide
    $mode_1 = "SERVICE_AUTO_START" ascii wide
    $mode_2 = "start= auto" ascii wide nocase
    $mode_3 = "SERVICE_WIN32_OWN_PROCESS" ascii wide
    $path_1 = "%APPDATA%" ascii wide nocase
    $path_2 = "%TEMP%" ascii wide nocase
    $path_3 = "\\ProgramData\\" ascii wide nocase
    $path_4 = "cmd.exe /c" ascii wide nocase
    $path_5 = "powershell" ascii wide nocase
  condition:
    uint16(0) == 0x5a4d and filesize < 20MB
    and 3 of ($api_*) and 1 of ($mode_*) and 1 of ($path_*)
}

rule Proton_Com_Object_Hijack_Persistence
{
  meta:
    description = "CLSID InprocServer32 ele geçirmesiyle COM kalıcılığı"
    severity = "high"
    category = "persistence"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $com_1 = "Software\\Classes\\CLSID\\" ascii wide nocase
    $com_2 = "InprocServer32" ascii wide nocase
    $com_3 = "LocalServer32" ascii wide nocase
    $com_4 = "TreatAs" ascii wide nocase
    $model = "ThreadingModel" ascii wide nocase
    $write_1 = "RegSetValueEx" ascii wide
    $write_2 = "reg add" ascii wide nocase
    $write_3 = "New-Item" ascii wide nocase
    $target_1 = "%APPDATA%" ascii wide nocase
    $target_2 = "%TEMP%" ascii wide nocase
    $target_3 = "\\ProgramData\\" ascii wide nocase
  condition:
    filesize < 20MB and $com_1 and 1 of ($com_2, $com_3, $com_4)
    and ($model or 1 of ($write_*)) and 1 of ($target_*)
}

rule Proton_Startup_Folder_Drop_Persistence
{
  meta:
    description = "Başlangıç klasörüne kısayol veya betik bırakma"
    severity = "medium"
    category = "persistence"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $dir_1 = "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" ascii wide nocase
    $dir_2 = "shell:startup" ascii wide nocase
    $dir_3 = "CSIDL_STARTUP" ascii wide nocase
    $dir_4 = "FOLDERID_Startup" ascii wide nocase
    $drop_1 = "CopyFile" ascii wide
    $drop_2 = "WriteFile" ascii wide
    $drop_3 = "IShellLink" ascii wide
    $drop_4 = "CreateShortcut" ascii wide nocase
    $drop_5 = "Copy-Item" ascii wide nocase
    $ext_1 = ".lnk" ascii wide nocase
    $ext_2 = ".vbs" ascii wide nocase
    $ext_3 = ".bat" ascii wide nocase
    $ext_4 = ".exe" ascii wide nocase
    $ext_5 = ".url" ascii wide nocase
  condition:
    filesize < 20MB and 1 of ($dir_*) and 1 of ($drop_*) and 1 of ($ext_*)
}

rule Proton_Netsh_Helper_And_Appinit_Injection
{
  meta:
    description = "AppInit_DLLs veya netsh yardımcı DLL ile sürekli enjeksiyon"
    severity = "high"
    category = "persistence"
    confidence = "high"
    author = "Neutron detection engineering"
  strings:
    $appinit_1 = "AppInit_DLLs" ascii wide nocase
    $appinit_2 = "LoadAppInit_DLLs" ascii wide nocase
    $appcert = "AppCertDlls" ascii wide nocase
    $netsh_1 = /netsh[ \t]+helper[ \t]+add/ ascii wide nocase
    $netsh_2 = "NetShHelper" ascii wide nocase
    $lsa_1 = "Security Packages" ascii wide nocase
    $lsa_2 = "Notification Packages" ascii wide nocase
    $lsa_3 = "Lsa\\OSConfig" ascii wide nocase
  condition:
    filesize < 20MB and
    (2 of ($appinit_*) or ($appcert and 1 of ($appinit_*)) or 1 of ($netsh_*) or 2 of ($lsa_*))
}

rule Proton_Print_Monitor_And_Time_Provider_Persistence
{
  meta:
    description = "Yazıcı izleyici veya zaman sağlayıcı DLL kaydıyla kalıcılık"
    severity = "high"
    category = "persistence"
    confidence = "high"
    author = "Neutron detection engineering"
  strings:
    $mon_1 = "Control\\Print\\Monitors" ascii wide nocase
    $mon_2 = "AddMonitor" ascii wide
    $mon_3 = "MONITOR_INFO_2" ascii wide
    $time_1 = "W32Time\\TimeProviders" ascii wide nocase
    $time_2 = "DllName" ascii wide nocase
    $port_1 = "Control\\Print\\Environments" ascii wide nocase
    $dll = ".dll" ascii wide nocase
  condition:
    filesize < 20MB and $dll and (2 of ($mon_*) or (1 of ($time_*) and $time_2) or ($port_1 and $mon_2))
}

rule Proton_Bits_Job_And_Screensaver_Persistence
{
  meta:
    description = "BITS işi veya ekran koruyucu ayarıyla kalıcılık"
    severity = "medium"
    category = "persistence"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $bits_1 = /bitsadmin[^\r\n]{0,120}\/SetNotifyCmdLine/ ascii wide nocase
    $bits_2 = /bitsadmin[^\r\n]{0,80}\/SetMinRetryDelay/ ascii wide nocase
    $bits_3 = "IBackgroundCopyJob" ascii wide
    $saver_1 = "Control Panel\\Desktop" ascii wide nocase
    $saver_2 = "SCRNSAVE.EXE" ascii wide nocase
    $saver_3 = "ScreenSaveActive" ascii wide nocase
    $payload_1 = ".exe" ascii wide nocase
    $payload_2 = ".scr" ascii wide nocase
    $payload_3 = "cmd.exe" ascii wide nocase
  condition:
    filesize < 20MB and 1 of ($payload_*)
    and (2 of ($bits_*) or ($saver_1 and $saver_2) or ($saver_2 and $saver_3))
}
