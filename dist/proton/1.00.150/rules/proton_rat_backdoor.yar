/*
  Proton - Uzaktan erişim truva atları ve arka kapılar.

  Kamuya açık RAT ailelerinin yapılandırma anahtarları, komut adları ve
  protokol dizgileri. Aile adı belirtilen kurallar en az iki ayırt edici
  gösterge ister; genel davranış kuralları ayrıca ağ ve yürütme kanıtı arar.
*/

rule Proton_AsyncRat_Family_Artifacts
{
  meta:
    description = "AsyncRAT yapılandırma ve komut kalıntıları"
    severity = "critical"
    category = "rat"
    confidence = "high"
    author = "Neutron detection engineering"
  strings:
    $cfg_1 = "AsyncRAT" ascii wide nocase
    $cfg_2 = "Pastebin" ascii wide nocase
    $cfg_3 = "BDOS" ascii wide fullword
    $cfg_4 = "Anti_Analysis" ascii wide nocase
    $cfg_5 = "MutexName" ascii wide nocase
    $cmd_1 = "sendPlugin" ascii wide nocase
    $cmd_2 = "plugin_" ascii wide nocase
    $cmd_3 = "Packet_Manager" ascii wide nocase
    $cmd_4 = "ClientSocket" ascii wide nocase
    $cert = "AsyncRAT Server" ascii wide nocase
  condition:
    filesize < 30MB and ($cert or (1 of ($cfg_*) and 2 of ($cmd_*)) or (2 of ($cfg_*) and 1 of ($cmd_*)))
}

rule Proton_Quasar_Family_Artifacts
{
  meta:
    description = "Quasar RAT istemci kalıntıları"
    severity = "critical"
    category = "rat"
    confidence = "high"
    author = "Neutron detection engineering"
  strings:
    $q_1 = "Quasar.Common" ascii wide nocase
    $q_2 = "Quasar.Client" ascii wide nocase
    $q_3 = "QuasarRAT" ascii wide nocase
    $msg_1 = "GetKeyloggerLogsResponse" ascii wide
    $msg_2 = "DoShellExecuteResponse" ascii wide
    $msg_3 = "GetPasswordsResponse" ascii wide
    $msg_4 = "DoDownloadFileResponse" ascii wide
    $msg_5 = "GetRemoteDesktop" ascii wide
  condition:
    filesize < 30MB and (1 of ($q_*) or 2 of ($msg_*))
}

rule Proton_Remcos_Family_Artifacts
{
  meta:
    description = "Remcos RAT yapılandırma kalıntıları"
    severity = "critical"
    category = "rat"
    confidence = "high"
    author = "Neutron detection engineering"
  strings:
    $r_1 = "Remcos" ascii wide nocase
    $r_2 = "Breaking-Security.Net" ascii wide nocase
    $r_3 = "remcos_" ascii wide nocase
    $cfg_1 = "SETTINGS" ascii wide fullword
    $cfg_2 = "Watchdog" ascii wide nocase
    $cfg_3 = "keylogger" ascii wide nocase
    $cfg_4 = "licence_code" ascii wide nocase
    $cfg_5 = "screenshot_flag" ascii wide nocase
  condition:
    filesize < 30MB and ((1 of ($r_*) and 1 of ($cfg_*)) or 2 of ($r_*))
}

rule Proton_NjRat_Family_Artifacts
{
  meta:
    description = "njRAT komut protokolü kalıntıları"
    severity = "critical"
    category = "rat"
    confidence = "high"
    author = "Neutron detection engineering"
  strings:
    $n_1 = "njrat" ascii wide nocase
    $n_2 = "njq8" ascii wide nocase
    $cmd_1 = "netsh firewall add allowedprogram" ascii wide nocase
    $cmd_2 = "|'|'|" ascii wide
    $cmd_3 = "inv" ascii wide fullword
    $cmd_4 = "cam" ascii wide fullword
    $cmd_5 = "kl" ascii wide fullword
    $cmd_6 = "OK" ascii wide fullword
    $reg = "SEE_MASK_NOZONECHECKS" ascii wide
  condition:
    filesize < 30MB and ((1 of ($n_*) and 1 of ($cmd_*)) or ($cmd_2 and 3 of ($cmd_*)) or ($cmd_2 and $cmd_1) or ($cmd_2 and $reg))
}

rule Proton_NanoCore_And_DarkComet_Artifacts
{
  meta:
    description = "NanoCore ve DarkComet arka kapı kalıntıları"
    severity = "critical"
    category = "rat"
    confidence = "high"
    author = "Neutron detection engineering"
  strings:
    $nano_1 = "NanoCore" ascii wide nocase
    $nano_2 = "ClientPlugin" ascii wide
    $nano_3 = "IClientNetworkHost" ascii wide
    $nano_4 = "PluginCommand" ascii wide
    $dark_1 = "DarkComet" ascii wide nocase
    $dark_2 = "#BOT#" ascii wide
    $dark_3 = "DCDATA" ascii wide
    $dark_4 = "KEYLOGGER" ascii wide fullword
    $dark_5 = "#KCMDDC" ascii wide
  condition:
    filesize < 30MB and (2 of ($nano_*) or 2 of ($dark_*))
}

rule Proton_VenomRat_And_Xworm_Artifacts
{
  meta:
    description = "VenomRAT ve XWorm türevi ajan kalıntıları"
    severity = "critical"
    category = "rat"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $v_1 = "VenomRAT" ascii wide nocase
    $v_2 = "XWorm" ascii wide nocase
    $v_3 = "XLogger" ascii wide nocase
    $cmd_1 = "PCInfo" ascii wide fullword
    $cmd_2 = "StartDDos" ascii wide nocase
    $cmd_3 = "StopReport" ascii wide nocase
    $cmd_4 = "sendPlugin" ascii wide nocase
    $cmd_5 = "OfflineGet" ascii wide nocase
    $cmd_6 = "RemoveTelegram" ascii wide nocase
  condition:
    filesize < 30MB and (1 of ($v_*) or 3 of ($cmd_*))
}

rule Proton_Hidden_Desktop_And_Remote_Control_Module
{
  meta:
    description = "Gizli masaüstü oturumu ve uzaktan giriş kontrolü modülü"
    severity = "high"
    category = "rat"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $hvnc_1 = "hVNC" ascii wide nocase
    $hvnc_2 = "CreateDesktopW" ascii wide
    $hvnc_3 = "SwitchDesktop" ascii wide
    $hvnc_4 = "SetThreadDesktop" ascii wide
    $input_1 = "SendInput" ascii wide
    $input_2 = "mouse_event" ascii wide
    $input_3 = "keybd_event" ascii wide
    $input_4 = "PostMessageW" ascii wide
    $capture_1 = "BitBlt" ascii wide
    $capture_2 = "PrintWindow" ascii wide
    $net_1 = "WSAStartup" ascii wide
    $net_2 = "WinHttpConnect" ascii wide
  condition:
    uint16(0) == 0x5a4d and filesize < 25MB
    and 2 of ($hvnc_*) and 1 of ($input_*) and 1 of ($capture_*) and 1 of ($net_*)
}

rule Proton_Webcam_And_Microphone_Surveillance
{
  meta:
    description = "İzinsiz kamera ve mikrofon kaydı yapan casus modül"
    severity = "high"
    category = "spyware"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $cam_1 = "capCreateCaptureWindow" ascii wide
    $cam_2 = "avicap32.dll" ascii wide nocase
    $cam_3 = "MediaCapture" ascii wide
    $mic_1 = "waveInOpen" ascii wide
    $mic_2 = "waveInStart" ascii wide
    $mic_3 = "IAudioCaptureClient" ascii wide
    $hide_1 = "SW_HIDE" ascii wide
    $hide_2 = "CREATE_NO_WINDOW" ascii wide
    $exfil_1 = "WinHttpSendRequest" ascii wide
    $exfil_2 = "HttpSendRequest" ascii wide
    $exfil_3 = "send" ascii fullword
  condition:
    uint16(0) == 0x5a4d and filesize < 25MB
    and 1 of ($cam_*) and 1 of ($mic_*) and 1 of ($hide_*) and 1 of ($exfil_*)
}

rule Proton_Reverse_Shell_Socket_Redirect
{
  meta:
    description = "Soket üzerinden komut kabuğu yönlendiren ters kabuk"
    severity = "critical"
    category = "backdoor"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $sock_1 = "WSASocketA" ascii wide
    $sock_2 = "WSASocketW" ascii wide
    $sock_3 = "connect" ascii fullword
    $sock_4 = "WSAConnect" ascii wide
    $redirect_1 = "STARTF_USESTDHANDLES" ascii wide
    $redirect_2 = "hStdInput" ascii wide
    $redirect_3 = "hStdOutput" ascii wide
    $redirect_4 = "CreatePipe" ascii wide
    $shell_1 = "cmd.exe" ascii wide nocase
    $shell_2 = "powershell.exe" ascii wide nocase
    $shell_3 = "/bin/sh" ascii
    $spawn = "CreateProcess" ascii wide
  condition:
    filesize < 25MB and 2 of ($sock_*) and 2 of ($redirect_*) and 1 of ($shell_*) and $spawn
}

rule Proton_Telegram_And_Discord_Bot_C2
{
  meta:
    description = "Telegram veya Discord bot API üzerinden komuta kontrol"
    severity = "high"
    category = "backdoor"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $api_1 = "api.telegram.org/bot" ascii wide nocase
    $api_2 = "discord.com/api/webhooks" ascii wide nocase
    $api_3 = "discordapp.com/api/webhooks" ascii wide nocase
    $method_1 = "/sendMessage" ascii wide nocase
    $method_2 = "/sendDocument" ascii wide nocase
    $method_3 = "/getUpdates" ascii wide nocase
    $exec_1 = "cmd.exe /c" ascii wide nocase
    $exec_2 = "CreateProcess" ascii wide
    $exec_3 = "ShellExecute" ascii wide
    $exec_4 = "subprocess" ascii wide nocase
    $collect_1 = "GetComputerName" ascii wide
    $collect_2 = "screenshot" ascii wide nocase
    $collect_3 = "keylog" ascii wide nocase
  condition:
    filesize < 25MB and 1 of ($api_*) and (1 of ($method_*) or 1 of ($collect_*)) and 1 of ($exec_*)
}
