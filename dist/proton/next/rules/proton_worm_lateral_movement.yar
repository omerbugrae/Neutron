/*
  Proton - Solucan yayılımı ve yanal hareket.

  Çıkarılabilir sürücü, ağ paylaşımı, uzak hizmet ve WMI üzerinden yayılan kod
  kalıplarını kapsar.
*/

rule Proton_Removable_Drive_Autorun_Worm
{
  meta:
    description = "Çıkarılabilir sürücülere kopyalanarak yayılan solucan"
    severity = "high"
    category = "worm"
    confidence = "high"
    author = "Neutron detection engineering"
  strings:
    $enum_1 = "GetLogicalDriveStrings" ascii wide
    $enum_2 = "GetDriveType" ascii wide
    $enum_3 = "DRIVE_REMOVABLE" ascii wide
    $enum_4 = "RegisterDeviceNotification" ascii wide
    $auto_1 = "autorun.inf" ascii wide nocase
    $auto_2 = "[autorun]" ascii wide nocase
    $auto_3 = "shellexecute=" ascii wide nocase
    $auto_4 = "open=" ascii wide nocase
    $copy_1 = "CopyFileW" ascii wide
    $copy_2 = "CreateFileW" ascii wide
    $hide_1 = "FILE_ATTRIBUTE_HIDDEN" ascii wide
    $hide_2 = "SetFileAttributes" ascii wide
    $lnk = "IShellLink" ascii wide
  condition:
    uint16(0) == 0x5a4d and filesize < 25MB
    and 2 of ($enum_*) and (2 of ($auto_*) or ($lnk and 1 of ($auto_*)))
    and 1 of ($copy_*) and 1 of ($hide_*)
}

rule Proton_Admin_Share_Copy_And_Remote_Exec
{
  meta:
    description = "Yönetici paylaşımına kopyalayıp uzaktan çalıştırarak yayılma"
    severity = "critical"
    category = "lateral-movement"
    confidence = "high"
    author = "Neutron detection engineering"
  strings:
    $share_1 = "\\\\ADMIN$" ascii wide nocase
    $share_2 = "\\\\C$\\Windows" ascii wide nocase
    $share_3 = "\\\\IPC$" ascii wide nocase
    $conn_1 = "WNetAddConnection2" ascii wide
    $conn_2 = "NetUseAdd" ascii wide
    $conn_3 = /net[ \t]+use[ \t]+\\\\/ ascii wide nocase
    $exec_1 = "OpenSCManagerA" ascii wide
    $exec_2 = "OpenSCManagerW" ascii wide
    $exec_3 = "CreateServiceW" ascii wide
    $exec_4 = "StartServiceW" ascii wide
    $exec_5 = /psexec[^\r\n]{0,40}\\\\/ ascii wide nocase
    $exec_6 = /wmic[^\r\n]{0,40}\/node:/ ascii wide nocase
    $copy = "CopyFileW" ascii wide
  condition:
    filesize < 25MB and 1 of ($share_*) and 1 of ($conn_*)
    and (3 of ($exec_1, $exec_2, $exec_3, $exec_4) or $exec_5 or $exec_6)
    and $copy
}

rule Proton_Smb_Vulnerability_Exploit_Spreader
{
  meta:
    description = "SMB protokol istismarıyla yayılan bileşen"
    severity = "critical"
    category = "worm"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $smb_1 = "SMB2_COM_" ascii wide
    $smb_2 = "\\PIPE\\srvsvc" ascii wide nocase
    $smb_3 = "\\PIPE\\browser" ascii wide nocase
    $smb_4 = "NT LM 0.12" ascii
    $exp_1 = "DoublePulsar" ascii wide nocase
    $exp_2 = "EternalBlue" ascii wide nocase
    $exp_3 = "MS17-010" ascii wide nocase
    $exp_4 = "SMB_COM_TRANSACTION2_SECONDARY" ascii wide
    $scan_1 = "445" ascii wide fullword
    $scan_2 = "InetNtoa" ascii wide
    $scan_3 = "connect" ascii fullword
  condition:
    filesize < 25MB and (1 of ($exp_1, $exp_2, $exp_3) or (2 of ($smb_*) and $exp_4))
    and 1 of ($scan_*)
}

rule Proton_Wmi_Remote_Process_Spawn
{
  meta:
    description = "WMI üzerinden uzak makinede süreç başlatma"
    severity = "high"
    category = "lateral-movement"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $wmi_1 = "Win32_Process" ascii wide
    $wmi_2 = "IWbemServices" ascii wide
    $wmi_3 = "ConnectServer" ascii wide
    $wmi_4 = "ExecMethod" ascii wide
    $wmi_5 = "root\\cimv2" ascii wide nocase
    $remote_1 = "\\\\%s\\root" ascii wide
    $remote_2 = "COAUTHIDENTITY" ascii wide
    $remote_3 = "CoSetProxyBlanket" ascii wide
    $cmd_1 = "cmd.exe /c" ascii wide nocase
    $cmd_2 = "powershell" ascii wide nocase
    $cmd_3 = "Create" ascii wide fullword
  condition:
    filesize < 25MB and 3 of ($wmi_*) and 1 of ($remote_*) and 1 of ($cmd_*)
}

rule Proton_Winrm_And_Dcom_Lateral_Execution
{
  meta:
    description = "WinRM veya DCOM nesneleriyle uzaktan kod çalıştırma"
    severity = "high"
    category = "lateral-movement"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $winrm_1 = "Invoke-Command" ascii wide nocase
    $winrm_2 = "New-PSSession" ascii wide nocase
    $winrm_3 = "Enter-PSSession" ascii wide nocase
    $winrm_4 = "wsman" ascii wide nocase
    $dcom_1 = "MMC20.Application" ascii wide nocase
    $dcom_2 = "ShellWindows" ascii wide nocase
    $dcom_3 = "ShellBrowserWindow" ascii wide nocase
    $dcom_4 = "ExecuteShellCommand" ascii wide nocase
    $dcom_5 = "Excel.Application" ascii wide nocase
    $remote_1 = "-ComputerName" ascii wide nocase
    $remote_2 = "CLSCTX_REMOTE_SERVER" ascii wide
    $remote_3 = "CoCreateInstanceEx" ascii wide
    $payload_1 = "cmd.exe" ascii wide nocase
    $payload_2 = "powershell" ascii wide nocase
    $payload_3 = "DDEInitiate" ascii wide nocase
  condition:
    filesize < 25MB and
    (
      (2 of ($winrm_*) and 1 of ($remote_*) and 1 of ($payload_*))
      or (1 of ($dcom_*) and 1 of ($remote_*) and 1 of ($payload_*))
      or (2 of ($dcom_*) and $dcom_4)
    )
}

rule Proton_Credential_Reuse_Spray_Loop
{
  meta:
    description = "Toplanan kimlik bilgileriyle ağda oturum açma denemesi döngüsü"
    severity = "high"
    category = "lateral-movement"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $logon_1 = "LogonUserW" ascii wide
    $logon_2 = "LOGON32_LOGON_NEW_CREDENTIALS" ascii wide
    $logon_3 = "ImpersonateLoggedOnUser" ascii wide
    $logon_4 = "NetUseAdd" ascii wide
    $enum_1 = "NetServerEnum" ascii wide
    $enum_2 = "DsGetDcNameW" ascii wide
    $enum_3 = "NetGroupGetUsers" ascii wide
    $enum_4 = "GetIpNetTable" ascii wide
    $loop_1 = "password_list" ascii wide nocase
    $loop_2 = "userlist" ascii wide nocase
    $loop_3 = "spray" ascii wide nocase
    $loop_4 = "ERROR_LOGON_FAILURE" ascii wide
  condition:
    uint16(0) == 0x5a4d and filesize < 25MB
    and 2 of ($logon_*) and 1 of ($enum_*) and 1 of ($loop_*)
}
