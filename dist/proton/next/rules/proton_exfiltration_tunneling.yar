/*
  Proton - Veri sızdırma ve gizli tünelleme.

  Bu dosyadaki araçların çoğu meşru kullanım alanına sahiptir. Kurallar bu
  yüzden aracın varlığını değil, otomatik ve gizli kullanımını gösteren
  parametre kombinasyonlarını arar.
*/

rule Proton_Cloud_Sync_Tool_Silent_Exfiltration
{
  meta:
    description = "Bulut senkronizasyon aracıyla sessiz toplu veri aktarımı"
    severity = "high"
    category = "exfiltration"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $tool_1 = "rclone" ascii wide nocase
    $tool_2 = "megacmd" ascii wide nocase
    $tool_3 = "megatools" ascii wide nocase
    $tool_4 = "winscp.com" ascii wide nocase
    $arg_1 = /copy[ \t]+[^\r\n]{0,120}--transfers/ ascii wide nocase
    $arg_2 = "--no-check-certificate" ascii wide nocase
    $arg_3 = "--ignore-existing" ascii wide nocase
    $arg_4 = "--max-age" ascii wide nocase
    $arg_5 = "--multi-thread-streams" ascii wide nocase
    $arg_6 = "-q --no-console" ascii wide nocase
    $target_1 = "\\Documents" ascii wide nocase
    $target_2 = "\\Desktop" ascii wide nocase
    $target_3 = "\\Users\\" ascii wide nocase
    $hide_1 = "SW_HIDE" ascii wide
    $hide_2 = "CREATE_NO_WINDOW" ascii wide
    $hide_3 = "-WindowStyle Hidden" ascii wide nocase
  condition:
    filesize < 40MB and 1 of ($tool_*) and 2 of ($arg_*) and (1 of ($target_*) or 1 of ($hide_*))
}

rule Proton_Reverse_Tunnel_And_Proxy_Client
{
  meta:
    description = "Ağ sınırını aşan ters tünel veya vekil istemci kullanımı"
    severity = "high"
    category = "exfiltration"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $tool_1 = "ngrok" ascii wide nocase
    $tool_2 = "chisel" ascii wide nocase
    $tool_3 = "frpc" ascii wide nocase
    $tool_4 = "gost" ascii wide fullword nocase
    $tool_5 = "plink.exe" ascii wide nocase
    $tool_6 = "socat" ascii wide nocase
    $arg_1 = /-R[ \t]+[0-9]{2,5}:/ ascii wide
    $arg_2 = "--reverse" ascii wide nocase
    $arg_3 = "server_addr" ascii wide nocase
    $arg_4 = "remote_port" ascii wide nocase
    $arg_5 = "socks5" ascii wide nocase
    $arg_6 = /tcp[ \t]+[0-9]{2,5}[ \t]+--region/ ascii wide nocase
    $auto_1 = "SW_HIDE" ascii wide
    $auto_2 = "CreateService" ascii wide
    $auto_3 = "schtasks" ascii wide nocase
    $auto_4 = "CurrentVersion\\Run" ascii wide nocase
  condition:
    filesize < 40MB and 1 of ($tool_*) and 1 of ($arg_*) and 1 of ($auto_*)
}

rule Proton_Dns_Tunneling_Client
{
  meta:
    description = "DNS sorguları içinde veri taşıyan tünel istemcisi"
    severity = "high"
    category = "exfiltration"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $tool_1 = "iodine" ascii wide fullword nocase
    $tool_2 = "dnscat" ascii wide nocase
    $tool_3 = "dns2tcp" ascii wide nocase
    $tool_4 = "dnsteal" ascii wide nocase
    $proto_1 = "DNS_TYPE_TEXT" ascii wide
    $proto_2 = "DNS_TYPE_NULL" ascii wide
    $proto_3 = "DnsQuery" ascii wide
    $proto_4 = "TXT record" ascii wide nocase
    $encode_1 = "base32" ascii wide nocase
    $encode_2 = "base64" ascii wide nocase
    $encode_3 = "hex encode" ascii wide nocase
    $chunk_1 = "chunk" ascii wide fullword nocase
    $chunk_2 = "sequence" ascii wide fullword nocase
    $chunk_3 = "max_label" ascii wide nocase
  condition:
    filesize < 30MB and
    (1 of ($tool_*) or (2 of ($proto_*) and 1 of ($encode_*) and 1 of ($chunk_*)))
}

rule Proton_Icmp_Covert_Channel
{
  meta:
    description = "ICMP paketlerinde veri taşıyan gizli kanal"
    severity = "high"
    category = "exfiltration"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $icmp_1 = "IcmpCreateFile" ascii wide
    $icmp_2 = "IcmpSendEcho2" ascii wide
    $icmp_3 = "ICMP_ECHO_REPLY" ascii wide
    $icmp_4 = "IPPROTO_ICMP" ascii wide
    $raw_1 = "SOCK_RAW" ascii wide
    $raw_2 = "WSAIoctl" ascii wide
    $payload_1 = "RequestData" ascii wide
    $payload_2 = "RequestSize" ascii wide
    $exec_1 = "CreateProcess" ascii wide
    $exec_2 = "cmd.exe" ascii wide nocase
  condition:
    uint16(0) == 0x5a4d and filesize < 25MB
    and 2 of ($icmp_*) and (1 of ($raw_*) or 2 of ($payload_*)) and 1 of ($exec_*)
}

rule Proton_Archive_Stage_And_Upload_Chain
{
  meta:
    description = "Toplanan veriyi parola korumalı arşive alıp yükleyen zincir"
    severity = "high"
    category = "exfiltration"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $arch_1 = /7z(a)?(\.exe)?[^\r\n]{0,80}-p[^\s"']{4,}/ ascii wide nocase
    $arch_2 = /rar(\.exe)?[ \t]+a[^\r\n]{0,80}-hp/ ascii wide nocase
    $arch_3 = "Compress-Archive" ascii wide nocase
    $arch_4 = "ZipFile.CreateFromDirectory" ascii wide
    $split = /-v[0-9]{2,5}m/ ascii wide nocase
    $up_1 = "curl -F" ascii wide nocase
    $up_2 = "Invoke-RestMethod" ascii wide nocase
    $up_3 = "InternetWriteFile" ascii wide
    $up_4 = "WinHttpWriteData" ascii wide
    $up_5 = "multipart/form-data" ascii wide nocase
    $up_6 = "transfer.sh" ascii wide nocase
    $up_7 = "anonfiles" ascii wide nocase
    $up_8 = "gofile.io" ascii wide nocase
  condition:
    filesize < 30MB and 1 of ($arch_*) and 1 of ($up_*) and ($split or 2 of ($up_*))
}

rule Proton_Tor_Hidden_Service_Client_Bundle
{
  meta:
    description = "Tor üzerinden anonim kanal kuran gömülü istemci"
    severity = "medium"
    category = "exfiltration"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $tor_1 = "tor.exe" ascii wide nocase
    $tor_2 = "torrc" ascii wide nocase
    $tor_3 = "SOCKSPort" ascii wide nocase
    $tor_4 = "HiddenServiceDir" ascii wide nocase
    $tor_5 = "127.0.0.1:9050" ascii wide
    $tor_6 = "127.0.0.1:9150" ascii wide
    $onion = /[a-z2-7]{56}\.onion/ ascii wide nocase
    $auto_1 = "SW_HIDE" ascii wide
    $auto_2 = "CREATE_NO_WINDOW" ascii wide
    $auto_3 = "CreateService" ascii wide
  condition:
    filesize < 40MB and ((2 of ($tor_*) and 1 of ($auto_*)) or ($onion and 1 of ($tor_*)))
}
