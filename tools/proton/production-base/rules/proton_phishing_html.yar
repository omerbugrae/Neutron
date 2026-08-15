/*
  Proton - HTML kaçakçılığı ve kimlik avı sayfaları.

  Tarayıcıda yerel olarak dosya üreten HTML kaçakçılığı, sahte oturum açma
  sayfaları ve kimlik bilgisi toplayan formları kapsar. Kurallar meşru web
  uygulamalarından ayrışmak için üretim ve indirme zincirinin tamamını arar.
*/

rule Proton_Html_Smuggling_Blob_Download
{
  meta:
    description = "Sayfa içinde üretilip otomatik indirilen gömülü yük (HTML smuggling)"
    severity = "high"
    category = "phishing"
    confidence = "high"
    author = "Neutron detection engineering"
  strings:
    $blob_1 = "new Blob(" ascii nocase
    $blob_2 = "URL.createObjectURL" ascii nocase
    $blob_3 = "msSaveOrOpenBlob" ascii nocase
    $anchor_1 = "document.createElement('a')" ascii nocase
    $anchor_2 = "document.createElement(\"a\")" ascii nocase
    $anchor_3 = ".download =" ascii nocase
    $anchor_4 = ".click()" ascii nocase
    $decode_1 = "atob(" ascii nocase
    $decode_2 = "fromCharCode" ascii nocase
    $decode_3 = "Uint8Array(" ascii nocase
    $decode_4 = "charCodeAt(" ascii nocase
    $type_1 = "application/octet-stream" ascii nocase
    $type_2 = "application/x-msdownload" ascii nocase
    $type_3 = "application/zip" ascii nocase
    $ext = /\.(exe|dll|iso|img|vbs|js|hta|scr|lnk|zip|7z|rar)["']/ ascii nocase
  condition:
    filesize < 20MB and 1 of ($blob_*) and 2 of ($anchor_*) and 2 of ($decode_*)
    and (1 of ($type_*) or $ext)
}

rule Proton_Data_Uri_Executable_Delivery
{
  meta:
    description = "data: URI ile doğrudan çalıştırılabilir yük teslimi"
    severity = "high"
    category = "phishing"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $uri_1 = "data:application/octet-stream;base64," ascii nocase
    $uri_2 = "data:application/x-msdownload;base64," ascii nocase
    $uri_3 = "data:application/zip;base64," ascii nocase
    $mz_b64_1 = "TVqQAAMAAAAEAAAA" ascii
    $mz_b64_2 = "TVpQAAIAAAAEAA8A" ascii
    $trigger_1 = ".download" ascii nocase
    $trigger_2 = "window.location" ascii nocase
    $trigger_3 = "iframe" ascii nocase
  condition:
    filesize < 20MB and (1 of ($uri_*) or 1 of ($mz_b64_*)) and 1 of ($trigger_*)
}

rule Proton_Credential_Phishing_Form_Kit
{
  meta:
    description = "Toplanan kimlik bilgisini uzak toplayıcıya gönderen sahte oturum sayfası"
    severity = "high"
    category = "phishing"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $form_1 = "type=\"password\"" ascii nocase
    $form_2 = "type='password'" ascii nocase
    $brand_1 = "Microsoft account" ascii nocase
    $brand_2 = "Sign in to your account" ascii nocase
    $brand_3 = "Office 365" ascii nocase
    $brand_4 = "Outlook Web App" ascii nocase
    $brand_5 = "Google Account" ascii nocase
    $brand_6 = "iCloud" ascii nocase
    $kit_1 = "action=\"post.php\"" ascii nocase
    $kit_2 = "action=\"login.php\"" ascii nocase
    $kit_3 = "next.php" ascii nocase
    $kit_4 = "sendmail(" ascii nocase
    $kit_5 = "$message .= \"Email" ascii nocase
    $kit_6 = "antibot" ascii nocase
    $kit_7 = "blocker.php" ascii nocase
    $exfil_1 = "XMLHttpRequest" ascii nocase
    $exfil_2 = "fetch(" ascii nocase
    $exfil_3 = "telegram" ascii nocase
    $exfil_4 = "mail(" ascii nocase
  condition:
    filesize < 5MB and 1 of ($form_*) and 1 of ($brand_*) and 1 of ($kit_*) and 1 of ($exfil_*)
}

rule Proton_Browser_In_The_Browser_Overlay
{
  meta:
    description = "Sahte tarayıcı penceresi çizerek kimlik bilgisi toplayan sayfa"
    severity = "high"
    category = "phishing"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $fake_1 = "browser-in-the-browser" ascii nocase
    $fake_2 = "fake-address-bar" ascii nocase
    $fake_3 = "window-titlebar" ascii nocase
    $fake_4 = "fakeWindow" ascii nocase
    $chrome_1 = "https://login.microsoftonline.com" ascii nocase
    $chrome_2 = "accounts.google.com" ascii nocase
    $ui_1 = "cursor: pointer" ascii nocase
    $ui_2 = "box-shadow" ascii nocase
    $ui_3 = "draggable" ascii nocase
    $form = "type=\"password\"" ascii nocase
  condition:
    filesize < 5MB and 1 of ($fake_*) and 1 of ($chrome_*) and 1 of ($ui_*) and $form
}

rule Proton_Fake_Update_Drive_By_Lure
{
  meta:
    description = "Sahte tarayıcı veya eklenti güncellemesi sunan indirme sayfası"
    severity = "medium"
    category = "phishing"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $lure_1 = "Your browser is out of date" ascii nocase
    $lure_2 = "Critical update required" ascii nocase
    $lure_3 = "Update Chrome" ascii nocase
    $lure_4 = "Flash Player is out of date" ascii nocase
    $lure_5 = "Tarayıcınız güncel değil" ascii nocase
    $lure_6 = "Güncelleme gerekli" ascii nocase
    $drop_1 = ".exe" ascii nocase
    $drop_2 = ".msi" ascii nocase
    $drop_3 = ".dmg" ascii nocase
    $drop_4 = ".zip" ascii nocase
    $auto_1 = "window.onload" ascii nocase
    $auto_2 = "setTimeout(" ascii nocase
    $auto_3 = ".click()" ascii nocase
    $auto_4 = "location.href =" ascii nocase
  condition:
    filesize < 5MB and 1 of ($lure_*) and 1 of ($drop_*) and 2 of ($auto_*)
}

rule Proton_Svg_Embedded_Script_Payload
{
  meta:
    description = "SVG içinde gizlenmiş betik yükü"
    severity = "high"
    category = "phishing"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $svg = "<svg" ascii nocase
    $script_1 = "<script" ascii nocase
    $script_2 = "CDATA[" ascii nocase
    $event_1 = "onload=" ascii nocase
    $event_2 = "onerror=" ascii nocase
    $payload_1 = "atob(" ascii nocase
    $payload_2 = "eval(" ascii nocase
    $payload_3 = "createObjectURL" ascii nocase
    $payload_4 = "window.location" ascii nocase
    $payload_5 = "fromCharCode" ascii nocase
  condition:
    filesize < 5MB and $svg and (1 of ($script_*) or 1 of ($event_*)) and 2 of ($payload_*)
}
