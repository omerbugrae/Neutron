/*
  Proton - Fidye yazılımı davranış kuralları.

  Toplu şifreleme, fidye notu, gölge kopya yıkımı, ağ paylaşımı taraması ve
  şifreleme sonrası uzantı değiştirme kalıplarını kapsar. Meşru yedekleme ve
  şifreleme araçlarından ayrışmak için her kural en az iki farklı davranış
  ailesinin birlikte görülmesini ister.
*/

rule Proton_Ransom_Note_Language_Template
{
  meta:
    description = "Fidye notu şablonuna özgü ifade ve iletişim kalıpları"
    severity = "critical"
    category = "ransomware"
    confidence = "high"
    author = "Neutron detection engineering"
  strings:
    $note_1 = "your files have been encrypted" ascii wide nocase
    $note_2 = "all your files are encrypted" ascii wide nocase
    $note_3 = "dosyalariniz sifrelendi" ascii wide nocase
    $note_4 = "dosyalarınız şifrelendi" ascii wide nocase
    $note_5 = "your network has been penetrated" ascii wide nocase
    $note_6 = "to decrypt your files you need to buy" ascii wide nocase
    $note_7 = "recover your data" ascii wide nocase
    $pay_1 = "bitcoin" ascii wide nocase
    $pay_2 = "monero" ascii wide nocase
    $pay_3 = "decryption key" ascii wide nocase
    $pay_4 = "decryptor" ascii wide nocase
    $pay_5 = "ransom" ascii wide nocase
    $contact_1 = ".onion" ascii wide nocase
    $contact_2 = "tox id" ascii wide nocase
    $contact_3 = "qtox" ascii wide nocase
    $contact_4 = "session id" ascii wide nocase
    $threat_1 = "do not rename" ascii wide nocase
    $threat_2 = "do not try to decrypt" ascii wide nocase
    $threat_3 = "will be published" ascii wide nocase
    $threat_4 = "leak site" ascii wide nocase
  condition:
    filesize < 5MB and 1 of ($note_*) and 1 of ($pay_*) and 1 of ($contact_*, $threat_*)
}

rule Proton_Mass_Encryption_Crypto_Api_Loop
{
  meta:
    description = "Dosya sistemini gezip toplu şifreleme yapan kripto döngüsü"
    severity = "critical"
    category = "ransomware"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $walk_1 = "FindFirstFileW" ascii wide
    $walk_2 = "FindNextFileW" ascii wide
    $walk_3 = "GetLogicalDriveStrings" ascii wide
    $walk_4 = "SHGetKnownFolderPath" ascii wide
    $crypt_1 = "CryptEncrypt" ascii wide
    $crypt_2 = "BCryptEncrypt" ascii wide
    $crypt_3 = "CryptGenKey" ascii wide
    $crypt_4 = "BCryptGenerateSymmetricKey" ascii wide
    $crypt_5 = "CryptImportKey" ascii wide
    $crypt_6 = "ChaCha20" ascii wide nocase
    $crypt_7 = "Salsa20" ascii wide nocase
    $write_1 = "SetFilePointerEx" ascii wide
    $write_2 = "WriteFile" ascii wide
    $write_3 = "MoveFileExW" ascii wide
    $skip_1 = ".exe" ascii wide nocase
    $skip_2 = ".dll" ascii wide nocase
    $skip_3 = ".sys" ascii wide nocase
    $ext = /\.(locked|encrypted|crypt|enc|payfast|onion|lockbit|akira|blackcat)\b/ ascii wide nocase
  condition:
    uint16(0) == 0x5a4d and filesize < 25MB
    and 2 of ($walk_*) and 2 of ($crypt_*) and 2 of ($write_*)
    and (2 of ($skip_*) or $ext)
}

rule Proton_Shadow_Copy_And_Backup_Destruction
{
  meta:
    description = "Gölge kopya, yedek katalog ve kurtarma noktalarını yok etme"
    severity = "critical"
    category = "ransomware-impact"
    confidence = "high"
    author = "Neutron detection engineering"
  strings:
    $vss_1 = /vssadmin[ \t]+delete[ \t]+shadows/ ascii wide nocase
    $vss_2 = /vssadmin[ \t]+resize[ \t]+shadowstorage/ ascii wide nocase
    $vss_3 = /wmic[ \t]+shadowcopy[ \t]+delete/ ascii wide nocase
    $vss_4 = "Win32_ShadowCopy" ascii wide nocase
    $backup_1 = /wbadmin[ \t]+delete[ \t]+(catalog|systemstatebackup|backup)/ ascii wide nocase
    $backup_2 = /Delete[ \t]+Shadows[ \t]+\/All/ ascii wide nocase
    $restore_1 = /Disable-ComputerRestore/ ascii wide nocase
    $restore_2 = /srclient\.dll/ ascii wide nocase
    $boot_1 = /bcdedit[^\r\n]{0,60}recoveryenabled[ \t]+no/ ascii wide nocase
    $boot_2 = /bcdedit[^\r\n]{0,60}ignoreallfailures/ ascii wide nocase
  condition:
    filesize < 10MB and 2 of them
}

rule Proton_Network_Share_Encryption_Sweep
{
  meta:
    description = "Ağ paylaşımlarını numaralandırıp şifreleme kapsamına alma"
    severity = "critical"
    category = "ransomware"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $enum_1 = "NetShareEnum" ascii wide
    $enum_2 = "WNetEnumResource" ascii wide
    $enum_3 = "WNetAddConnection2" ascii wide
    $enum_4 = "GetLogicalDrives" ascii wide
    $enum_5 = "DRIVE_REMOTE" ascii wide
    $scan_1 = "IcmpSendEcho" ascii wide
    $scan_2 = "GetIpNetTable" ascii wide
    $scan_3 = "arp -a" ascii wide nocase
    $crypt_1 = "CryptEncrypt" ascii wide
    $crypt_2 = "BCryptEncrypt" ascii wide
    $note = /(README|HOW_TO_(DECRYPT|RESTORE)|RESTORE_FILES|DECRYPT_INSTRUCTION)[A-Z_-]{0,20}\.(txt|hta|html)/ ascii wide nocase
  condition:
    uint16(0) == 0x5a4d and filesize < 25MB
    and 3 of ($enum_*) and (1 of ($crypt_*) or $note) and 1 of ($scan_*, $crypt_*)
}

rule Proton_Process_And_Service_Stop_Before_Encryption
{
  meta:
    description = "Şifreleme öncesi veritabanı ve yedekleme hizmetlerini durdurma"
    severity = "high"
    category = "ransomware"
    confidence = "high"
    author = "Neutron detection engineering"
  strings:
    $svc_1 = "sqlserver" ascii wide nocase
    $svc_2 = "MSSQLSERVER" ascii wide nocase
    $svc_3 = "veeam" ascii wide nocase
    $svc_4 = "backupexec" ascii wide nocase
    $svc_5 = "acronis" ascii wide nocase
    $svc_6 = "sophos" ascii wide nocase
    $svc_7 = "MSExchange" ascii wide nocase
    $svc_8 = "QuickBooks" ascii wide nocase
    $svc_9 = "vmms" ascii wide nocase fullword
    $stop_1 = /net[ \t]+stop[ \t]+/ ascii wide nocase
    $stop_2 = /sc[ \t]+(stop|config)[ \t]+/ ascii wide nocase
    $stop_3 = "ControlService" ascii wide
    $stop_4 = /taskkill[ \t]+\/f/ ascii wide nocase
    $stop_5 = "TerminateProcess" ascii wide
  condition:
    filesize < 25MB and 4 of ($svc_*) and 1 of ($stop_*)
}

rule Proton_Wallpaper_And_Desktop_Ransom_Branding
{
  meta:
    description = "Fidye mesajını masaüstü duvar kağıdı olarak ayarlama"
    severity = "high"
    category = "ransomware"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $wall_1 = "SystemParametersInfo" ascii wide
    $wall_2 = "SPI_SETDESKWALLPAPER" ascii wide
    $wall_3 = "Control Panel\\Desktop" ascii wide nocase
    $wall_4 = "WallPaper" ascii wide fullword nocase
    $note_1 = "encrypted" ascii wide nocase
    $note_2 = "decrypt" ascii wide nocase
    $note_3 = "ransom" ascii wide nocase
    $note_4 = "bitcoin" ascii wide nocase
    $img_1 = ".bmp" ascii wide nocase
    $img_2 = ".jpg" ascii wide nocase
    $img_3 = ".png" ascii wide nocase
  condition:
    uint16(0) == 0x5a4d and filesize < 25MB
    and 2 of ($wall_*) and 2 of ($note_*) and 1 of ($img_*)
}

rule Proton_Boot_Locker_Mbr_Overwrite
{
  meta:
    description = "Önyükleme kaydını değiştirerek sistemi kilitleyen fidye bileşeni"
    severity = "critical"
    category = "ransomware-impact"
    confidence = "high"
    author = "Neutron detection engineering"
  strings:
    $disk_1 = "\\\\.\\PhysicalDrive0" ascii wide nocase
    $disk_2 = "\\\\.\\C:" ascii wide nocase
    $disk_3 = "IOCTL_DISK_GET_DRIVE_GEOMETRY" ascii wide
    $write_1 = "DeviceIoControl" ascii wide
    $write_2 = "WriteFile" ascii wide
    $write_3 = "SetFilePointer" ascii wide
    $boot_1 = "Non-System disk" ascii nocase
    $boot_2 = "Operating system not found" ascii nocase
    $boot_3 = "MBR" ascii wide fullword
    $ransom_1 = "encrypted" ascii wide nocase
    $ransom_2 = "decrypt" ascii wide nocase
    $reboot_1 = "ExitWindowsEx" ascii wide
    $reboot_2 = "NtRaiseHardError" ascii wide
    $reboot_3 = "InitiateSystemShutdown" ascii wide
  condition:
    uint16(0) == 0x5a4d and filesize < 20MB
    and 1 of ($disk_*) and 2 of ($write_*) and (1 of ($boot_*) or 1 of ($ransom_*)) and 1 of ($reboot_*)
}

rule Proton_Ransomware_Extension_And_Marker_Set
{
  meta:
    description = "Şifrelenmiş dosya uzantısı ve dosya sonu işaretçisi kullanımı"
    severity = "high"
    category = "ransomware"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $ext_1 = ".locked" ascii wide nocase
    $ext_2 = ".encrypted" ascii wide nocase
    $ext_3 = ".crypted" ascii wide nocase
    $ext_4 = ".enc" ascii wide nocase
    $ext_5 = ".pay" ascii wide nocase
    $ext_6 = ".ryk" ascii wide nocase
    $ext_7 = ".basta" ascii wide nocase
    $marker_1 = "FILE_MARKER" ascii wide nocase
    $marker_2 = "ENCRYPTED_BY" ascii wide nocase
    $marker_3 = "RANSOM_ID" ascii wide nocase
    $marker_4 = "victim_id" ascii wide nocase
    $note = /(README|HOW_TO|RESTORE|DECRYPT)[A-Za-z_-]{0,24}\.(txt|hta|html)/ ascii wide nocase
    $api = "MoveFileExW" ascii wide
  condition:
    uint16(0) == 0x5a4d and filesize < 25MB
    and 2 of ($ext_*) and ($note or 1 of ($marker_*)) and $api
}
