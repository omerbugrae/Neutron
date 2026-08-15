/*
  Proton - Bilgi hırsızı (infostealer) davranışları.

  Tarayıcı kimlik bilgisi depoları, kripto cüzdan dosyaları ve mesajlaşma
  uygulaması oturum belirteçleri birlikte hedeflendiğinde tetiklenir. Tek bir yol
  adı yeterli sayılmaz; meşru yedekleme ve senkronizasyon araçları tek yol adına
  bakan kuralları kolayca tetikler.
*/

rule Proton_Browser_Credential_Store_Harvest
{
  meta:
    description = "Birden çok tarayıcının parola ve çerez veritabanını toplayan kod"
    severity = "high"
    category = "infostealer"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $store_1 = "Login Data" ascii wide
    $store_2 = "Web Data" ascii wide
    $store_3 = "Cookies" ascii wide fullword
    $store_4 = "Local State" ascii wide
    $store_5 = "logins.json" ascii wide
    $store_6 = "key4.db" ascii wide
    $store_7 = "key3.db" ascii wide
    $store_8 = "cookies.sqlite" ascii wide
    $path_1 = "\\Google\\Chrome\\User Data" ascii wide nocase
    $path_2 = "\\Microsoft\\Edge\\User Data" ascii wide nocase
    $path_3 = "\\BraveSoftware\\Brave-Browser" ascii wide nocase
    $path_4 = "\\Mozilla\\Firefox\\Profiles" ascii wide nocase
    $path_5 = "\\Yandex\\YandexBrowser" ascii wide nocase
    $path_6 = "\\Opera Software\\Opera Stable" ascii wide nocase
    $crypt_1 = "CryptUnprotectData" ascii wide
    $crypt_2 = "os_crypt" ascii wide
    $crypt_3 = "encrypted_key" ascii wide
    $crypt_4 = "DPAPI" ascii wide
  condition:
    filesize < 30MB and 3 of ($store_*) and 2 of ($path_*) and 1 of ($crypt_*)
}

rule Proton_Crypto_Wallet_File_Harvest
{
  meta:
    description = "Masaüstü kripto cüzdan dosyalarını toplayan kod"
    severity = "high"
    category = "infostealer"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $wallet_1 = "wallet.dat" ascii wide nocase
    $wallet_2 = "\\Exodus\\exodus.wallet" ascii wide nocase
    $wallet_3 = "\\Electrum\\wallets" ascii wide nocase
    $wallet_4 = "\\Ethereum\\keystore" ascii wide nocase
    $wallet_5 = "\\Atomic\\Local Storage" ascii wide nocase
    $wallet_6 = "\\Coinomi\\Coinomi\\wallets" ascii wide nocase
    $wallet_7 = "\\Guarda\\Local Storage" ascii wide nocase
    $wallet_8 = "\\Binance\\Local Storage" ascii wide nocase
    $ext_1 = "nkbihfbeogaeaoehlefnkodbefgpgknn" ascii wide
    $ext_2 = "ejbalbakoplchlghecdalmeeeajnimhm" ascii wide
    $ext_3 = "fhbohimaelbohpjbbldcngcnapndodjp" ascii wide
    $ext_4 = "ibnejdfjmmkpcnlpebklmnkoeoihofec" ascii wide
    $collect_1 = "CopyFile" ascii wide
    $collect_2 = "FindFirstFile" ascii wide
    $collect_3 = "CreateFileW" ascii wide
    $collect_4 = "ZipArchive" ascii wide
  condition:
    filesize < 30MB and (3 of ($wallet_*) or (1 of ($wallet_*) and 2 of ($ext_*)))
    and 1 of ($collect_*)
}

rule Proton_Messenger_Session_Token_Theft
{
  meta:
    description = "Mesajlaşma uygulamalarının oturum belirteçlerini çalan kod"
    severity = "high"
    category = "infostealer"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $app_1 = "\\discord\\Local Storage\\leveldb" ascii wide nocase
    $app_2 = "\\discordcanary\\Local Storage" ascii wide nocase
    $app_3 = "\\Telegram Desktop\\tdata" ascii wide nocase
    $app_4 = "\\Signal\\sql" ascii wide nocase
    $app_5 = "\\Element\\Local Storage" ascii wide nocase
    $app_6 = "\\Steam\\config\\loginusers.vdf" ascii wide nocase
    $token_1 = "dQw4w9WgXcQ" ascii wide
    $token_2 = "mfa." ascii wide
    $token_3 = "/api/v9/users/@me" ascii wide
    $token_4 = "discord.com/api" ascii wide nocase
    $exfil_1 = "webhook" ascii wide nocase
    $exfil_2 = "api.telegram.org" ascii wide nocase
    $exfil_3 = "InternetOpenUrl" ascii wide
    $exfil_4 = "HttpSendRequest" ascii wide
  condition:
    filesize < 30MB and 2 of ($app_*) and (1 of ($token_*) or 1 of ($exfil_*))
}

rule Proton_Screenshot_And_Clipboard_Collection
{
  meta:
    description = "Ekran görüntüsü ve pano içeriğini periyodik toplayan casus bileşen"
    severity = "medium"
    category = "infostealer"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $screen_1 = "BitBlt" ascii wide
    $screen_2 = "GetDC" ascii wide
    $screen_3 = "CreateCompatibleBitmap" ascii wide
    $screen_4 = "GdiplusStartup" ascii wide
    $clip_1 = "OpenClipboard" ascii wide
    $clip_2 = "GetClipboardData" ascii wide
    $clip_3 = "SetClipboardData" ascii wide
    $exfil_1 = "InternetOpenUrl" ascii wide
    $exfil_2 = "HttpSendRequest" ascii wide
    $exfil_3 = "WinHttpSendRequest" ascii wide
    $exfil_4 = "socket" ascii fullword
  condition:
    uint16(0) == 0x5a4d and filesize < 20MB
    and 2 of ($screen_*) and 2 of ($clip_*) and 1 of ($exfil_*)
}

rule Proton_Keylogger_Hook_Primitives
{
  meta:
    description = "Klavye dinleme kancası ve tuş kaydı biçimlendirme kümesi"
    severity = "high"
    category = "spyware"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $hook_1 = "SetWindowsHookEx" ascii wide
    $hook_2 = "GetAsyncKeyState" ascii wide
    $hook_3 = "GetKeyboardState" ascii wide
    $hook_4 = "RegisterRawInputDevices" ascii wide
    $label_1 = "[BACKSPACE]" ascii wide nocase
    $label_2 = "[ENTER]" ascii wide nocase
    $label_3 = "[CTRL]" ascii wide nocase
    $label_4 = "[TAB]" ascii wide nocase
    $label_5 = "[CAPSLOCK]" ascii wide nocase
    $window = "GetForegroundWindow" ascii wide
  condition:
    filesize < 20MB and 2 of ($hook_*) and (2 of ($label_*) or ($window and 3 of ($hook_*)))
}

rule Proton_System_Profile_Exfiltration_Bundle
{
  meta:
    description = "Sistem envanterini toplayıp tek pakette dışarı gönderen hırsız modülü"
    severity = "medium"
    category = "infostealer"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $profile_1 = "GetComputerName" ascii wide
    $profile_2 = "GetUserName" ascii wide
    $profile_3 = "GetSystemInfo" ascii wide
    $profile_4 = "GlobalMemoryStatusEx" ascii wide
    $profile_5 = "EnumDisplayDevices" ascii wide
    $inventory_1 = "SELECT * FROM Win32_Processor" ascii wide nocase
    $inventory_2 = "SELECT * FROM AntiVirusProduct" ascii wide nocase
    $inventory_3 = "root\\SecurityCenter2" ascii wide nocase
    $inventory_4 = "MachineGuid" ascii wide
    $pack_1 = "ZipArchive" ascii wide
    $pack_2 = "PK\x03\x04"
    $pack_3 = "multipart/form-data" ascii wide nocase
    $send_1 = "WinHttpSendRequest" ascii wide
    $send_2 = "HttpSendRequest" ascii wide
    $send_3 = "InternetWriteFile" ascii wide
  condition:
    uint16(0) == 0x5a4d and filesize < 25MB
    and 3 of ($profile_*) and 1 of ($inventory_*) and 1 of ($pack_*) and 1 of ($send_*)
}

rule Proton_Clipboard_Crypto_Address_Hijacker
{
  meta:
    description = "Panodaki kripto para adresini değiştiren clipper"
    severity = "high"
    category = "clipper"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $clip_1 = "OpenClipboard" ascii wide
    $clip_2 = "SetClipboardData" ascii wide
    $clip_3 = "EmptyClipboard" ascii wide
    $btc = /\b(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,58}\b/ ascii wide
    $eth = /\b0x[a-fA-F0-9]{40}\b/ ascii wide
    $xmr = /\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b/ ascii wide
    $watch = "AddClipboardFormatListener" ascii wide
  condition:
    uint16(0) == 0x5a4d and filesize < 15MB
    and 2 of ($clip_*) and 2 of ($btc, $eth, $xmr, $watch)
}

rule Proton_Ftp_And_Mail_Client_Credential_Harvest
{
  meta:
    description = "FTP ve e-posta istemcilerinin kayıtlı kimlik bilgilerini toplayan kod"
    severity = "high"
    category = "infostealer"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $ftp_1 = "\\FileZilla\\recentservers.xml" ascii wide nocase
    $ftp_2 = "\\FileZilla\\sitemanager.xml" ascii wide nocase
    $ftp_3 = "WinSCP 2" ascii wide
    $ftp_4 = "\\CoreFTP\\sites.idx" ascii wide nocase
    $ftp_5 = "\\FlashFXP\\" ascii wide nocase
    $mail_1 = "\\Thunderbird\\Profiles" ascii wide nocase
    $mail_2 = "Software\\Microsoft\\Office\\16.0\\Outlook\\Profiles" ascii wide nocase
    $mail_3 = "IMAP Password" ascii wide
    $mail_4 = "POP3 Password" ascii wide
    $mail_5 = "\\The Bat!\\" ascii wide nocase
  condition:
    filesize < 30MB and ((2 of ($ftp_*) and 1 of ($mail_*)) or 3 of ($ftp_*) or 3 of ($mail_*))
}

rule Proton_Vpn_And_Remote_Access_Credential_Theft
{
  meta:
    description = "VPN ve uzak masaüstü istemci kimlik bilgilerini toplayan kod"
    severity = "high"
    category = "infostealer"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $vpn_1 = "\\OpenVPN Connect\\profiles" ascii wide nocase
    $vpn_2 = "\\NordVPN\\" ascii wide nocase
    $vpn_3 = "\\ProtonVPN\\" ascii wide nocase
    $vpn_4 = "auth-user-pass" ascii wide
    $rdp_1 = "Default.rdp" ascii wide nocase
    $rdp_2 = "Terminal Server Client\\Servers" ascii wide nocase
    $rdp_3 = "\\AnyDesk\\user.conf" ascii wide nocase
    $rdp_4 = "\\TeamViewer\\" ascii wide nocase
    $creds = "CredEnumerate" ascii wide
    $dpapi = "CryptUnprotectData" ascii wide
  condition:
    filesize < 30MB and 2 of ($vpn_*, $rdp_*) and ($creds or $dpapi)
}

rule Proton_Grabber_Document_Sweep
{
  meta:
    description = "Belge ve anahtar dosyalarını uzantıya göre süpüren toplayıcı"
    severity = "medium"
    category = "infostealer"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $sweep_1 = "*.docx" ascii wide nocase
    $sweep_2 = "*.xlsx" ascii wide nocase
    $sweep_3 = "*.pdf" ascii wide nocase
    $sweep_4 = "*.kdbx" ascii wide nocase
    $sweep_5 = "*.rdp" ascii wide nocase
    $sweep_6 = "*.ovpn" ascii wide nocase
    $sweep_7 = "*.pem" ascii wide nocase
    $sweep_8 = "*.ppk" ascii wide nocase
    $seed_1 = "seed phrase" ascii wide nocase
    $seed_2 = "mnemonic" ascii wide nocase
    $seed_3 = "recovery phrase" ascii wide nocase
    $seed_4 = "private key" ascii wide nocase
    $dir_1 = "\\Desktop" ascii wide
    $dir_2 = "\\Documents" ascii wide
    $dir_3 = "\\Downloads" ascii wide
  condition:
    uint16(0) == 0x5a4d and filesize < 25MB
    and 4 of ($sweep_*) and 1 of ($seed_*) and 2 of ($dir_*)
}
