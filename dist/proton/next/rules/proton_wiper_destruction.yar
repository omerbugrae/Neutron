/*
  Proton - Veri imha (wiper) ve sistem bozma davranışları.

  Fidye talebi olmadan geri dönüşü olmayan hasar veren kod kalıplarını hedefler.
*/

rule Proton_Disk_Wiper_Raw_Overwrite
{
  meta:
    description = "Ham disk sektörlerini rastgele veriyle üzerine yazan wiper"
    severity = "critical"
    category = "wiper"
    confidence = "high"
    author = "Neutron detection engineering"
  strings:
    $disk_1 = "\\\\.\\PhysicalDrive" ascii wide nocase
    $disk_2 = "\\\\.\\HarddiskVolume" ascii wide nocase
    $disk_3 = "IOCTL_DISK_DELETE_DRIVE_LAYOUT" ascii wide
    $disk_4 = "FSCTL_LOCK_VOLUME" ascii wide
    $disk_5 = "FSCTL_DISMOUNT_VOLUME" ascii wide
    $wipe_1 = "SetFilePointerEx" ascii wide
    $wipe_2 = "WriteFile" ascii wide
    $wipe_3 = "CryptGenRandom" ascii wide
    $wipe_4 = "BCryptGenRandom" ascii wide
    $wipe_5 = "memset" ascii
    $end_1 = "ExitWindowsEx" ascii wide
    $end_2 = "NtRaiseHardError" ascii wide
    $end_3 = "InitiateSystemShutdownEx" ascii wide
  condition:
    uint16(0) == 0x5a4d and filesize < 20MB
    and 2 of ($disk_*) and 3 of ($wipe_*) and 1 of ($end_*)
}

rule Proton_File_Shredder_Recursive_Overwrite
{
  meta:
    description = "Kullanıcı dosyalarını özyinelemeli olarak üzerine yazıp silen imha kodu"
    severity = "critical"
    category = "wiper"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $walk_1 = "FindFirstFileW" ascii wide
    $walk_2 = "FindNextFileW" ascii wide
    $walk_3 = "SHGetKnownFolderPath" ascii wide
    $walk_4 = "GetLogicalDriveStringsW" ascii wide
    $wipe_1 = "SetEndOfFile" ascii wide
    $wipe_2 = "WriteFile" ascii wide
    $wipe_3 = "DeleteFileW" ascii wide
    $wipe_4 = "SetFilePointerEx" ascii wide
    $rand_1 = "CryptGenRandom" ascii wide
    $rand_2 = "BCryptGenRandom" ascii wide
    $rand_3 = "RtlGenRandom" ascii wide
    $target_1 = "\\Documents" ascii wide
    $target_2 = "\\Desktop" ascii wide
    $target_3 = "\\Pictures" ascii wide
    $target_4 = "\\Users\\" ascii wide
  condition:
    uint16(0) == 0x5a4d and filesize < 20MB
    and 3 of ($walk_*) and 3 of ($wipe_*) and 1 of ($rand_*) and 2 of ($target_*)
}

rule Proton_System_Recovery_Sabotage_Commands
{
  meta:
    description = "Kurtarma ortamını ve önyükleme yapılandırmasını kalıcı bozma"
    severity = "critical"
    category = "wiper"
    confidence = "high"
    author = "Neutron detection engineering"
  strings:
    $cmd_1 = /reagentc[ \t]+\/disable/ ascii wide nocase
    $cmd_2 = /bcdedit[ \t]+\/deletevalue/ ascii wide nocase
    $cmd_3 = /bootrec[ \t]+\/fixmbr/ ascii wide nocase
    $cmd_4 = /format[ \t]+[c-z]:[ \t]+\/(q|fs)/ ascii wide nocase
    $cmd_5 = /diskpart[^\r\n]{0,40}clean[ \t]+all/ ascii wide nocase
    $cmd_6 = /del[ \t]+\/f[ \t]+\/q[ \t]+[c-z]:\\\*/ ascii wide nocase
    $cmd_7 = /Remove-Item[^\r\n]{0,60}-Recurse[^\r\n]{0,40}-Force/ ascii wide nocase
    $cmd_8 = /rd[ \t]+\/s[ \t]+\/q[ \t]+[c-z]:\\/ ascii wide nocase
  condition:
    filesize < 5MB and 2 of them
}

rule Proton_Firmware_And_Driver_Level_Destruction
{
  meta:
    description = "Ürün yazılımı veya sürücü seviyesinde kalıcı hasar girişimi"
    severity = "critical"
    category = "wiper"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $fw_1 = "SetFirmwareEnvironmentVariable" ascii wide
    $fw_2 = "GetFirmwareEnvironmentVariable" ascii wide
    $fw_3 = "NtSetSystemEnvironmentValueEx" ascii wide
    $fw_4 = "EFI_GLOBAL_VARIABLE" ascii wide
    $boot_1 = "BootOrder" ascii wide fullword
    $boot_2 = "\\EFI\\Microsoft\\Boot" ascii wide nocase
    $boot_3 = "bootmgfw.efi" ascii wide nocase
    $priv = "SeSystemEnvironmentPrivilege" ascii wide
  condition:
    uint16(0) == 0x5a4d and filesize < 20MB
    and 2 of ($fw_*) and 1 of ($boot_*) and $priv
}

rule Proton_Logic_Bomb_Time_Trigger_Destruction
{
  meta:
    description = "Belirli tarihte tetiklenen yıkım rutini"
    severity = "high"
    category = "wiper"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $time_1 = "GetSystemTimeAsFileTime" ascii wide
    $time_2 = "GetLocalTime" ascii wide
    $time_3 = "SystemTimeToFileTime" ascii wide
    $destroy_1 = "DeleteFileW" ascii wide
    $destroy_2 = "SHFileOperation" ascii wide
    $destroy_3 = "RemoveDirectoryW" ascii wide
    $destroy_4 = "\\\\.\\PhysicalDrive0" ascii wide nocase
    $sabotage_1 = "vssadmin" ascii wide nocase
    $sabotage_2 = "bcdedit" ascii wide nocase
    $sabotage_3 = "wevtutil" ascii wide nocase
    $sabotage_4 = "ExitWindowsEx" ascii wide
  condition:
    uint16(0) == 0x5a4d and filesize < 20MB
    and 2 of ($time_*) and 2 of ($destroy_*) and 2 of ($sabotage_*)
}
