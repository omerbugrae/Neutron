/*
  Proton - Komuta kontrol (C2) çerçevesi kalıntıları.

  Kurallar kamuya açık kırmızı takım çerçevelerinin varsayılan artefaktlarını
  hedefler. Bu araçların yetkili sızma testlerinde de kullanıldığı unutulmamalı;
  bu yüzden severity değerleri "high" ile sınırlı tutulmuş, açıklamalarda
  çerçeve adı belirtilmiştir.
*/

rule Proton_CobaltStrike_Beacon_Config_Artifacts
{
  meta:
    description = "Cobalt Strike beacon yapılandırma ve komut dizgi kümesi"
    severity = "high"
    category = "c2-framework"
    confidence = "high"
    author = "Neutron detection engineering"
  strings:
    $beacon_1 = "beacon.dll" ascii wide nocase
    $beacon_2 = "beacon.x64.dll" ascii wide nocase
    $beacon_3 = "ReflectiveLoader" ascii
    $cmd_1 = "%s as %s\\%s: %d" ascii
    $cmd_2 = "could not run command (w/ token) because of its length of %d bytes!" ascii
    $cmd_3 = "could not upload file: %d" ascii
    $cmd_4 = "Could not open service control manager on %s: %d" ascii
    $cmd_5 = "beacon_command_register" ascii
    $pipe_1 = "\\\\.\\pipe\\msagent_" ascii wide
    $pipe_2 = "\\\\.\\pipe\\postex_" ascii wide
    $pipe_3 = "\\\\.\\pipe\\status_" ascii wide
    $ua = "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)" ascii
  condition:
    filesize < 20MB and (2 of ($cmd_*) or 1 of ($pipe_*) or (1 of ($beacon_*) and 1 of ($cmd_*, $ua)))
}

rule Proton_Meterpreter_Stager_Artifacts
{
  meta:
    description = "Metasploit Meterpreter yükleyici ve uzantı kalıntıları"
    severity = "high"
    category = "c2-framework"
    confidence = "high"
    author = "Neutron detection engineering"
  strings:
    $ext_1 = "metsrv.dll" ascii wide nocase
    $ext_2 = "ext_server_stdapi" ascii nocase
    $ext_3 = "ext_server_priv" ascii nocase
    $ext_4 = "ext_server_espia" ascii nocase
    $ext_5 = "ext_server_kiwi" ascii nocase
    $core_1 = "core_channel_open" ascii
    $core_2 = "core_migrate" ascii
    $core_3 = "stdapi_sys_process_execute" ascii
    $core_4 = "stdapi_fs_file_download" ascii
    $core_5 = "priv_passwd_get_sam_hashes" ascii
  condition:
    filesize < 20MB and 2 of ($ext_*, $core_*)
}

rule Proton_Sliver_Implant_Artifacts
{
  meta:
    description = "Sliver C2 implant yapısı ve protokol dizgileri"
    severity = "high"
    category = "c2-framework"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $sliver_1 = "sliverpb" ascii
    $sliver_2 = "github.com/bishopfox/sliver" ascii
    $sliver_3 = "sliver/implant/sliverpb" ascii
    $rpc_1 = "InvokeExecuteAssemblyReq" ascii
    $rpc_2 = "SpawnDllReq" ascii
    $rpc_3 = "ImpersonateReq" ascii
    $rpc_4 = "MsfRemoteReq" ascii
  condition:
    filesize < 60MB and (1 of ($sliver_*) or 2 of ($rpc_*))
}

rule Proton_Havoc_Demon_Artifacts
{
  meta:
    description = "Havoc C2 Demon ajanı kalıntıları"
    severity = "high"
    category = "c2-framework"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $demon_1 = "DemonMain" ascii
    $demon_2 = "havoc" ascii fullword nocase
    $demon_3 = "Demon.x64.exe" ascii wide nocase
    $task_1 = "DEMON_COMMAND_" ascii
    $task_2 = "CALLBACK_OUTPUT" ascii
    $task_3 = "KaynLdr" ascii
    $task_4 = "DemonConfig" ascii
  condition:
    filesize < 20MB and 2 of ($demon_*, $task_*)
}

rule Proton_BruteRatel_Badger_Artifacts
{
  meta:
    description = "Brute Ratel C4 badger kalıntıları"
    severity = "high"
    category = "c2-framework"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $br_1 = "badger_" ascii
    $br_2 = "bruteratel" ascii nocase
    $br_3 = "BadgerDispatch" ascii
    $br_4 = "brc4" ascii fullword nocase
    $br_5 = "b4dg3r" ascii nocase
  condition:
    filesize < 20MB and 2 of them
}

rule Proton_Mythic_Agent_Artifacts
{
  meta:
    description = "Mythic C2 ajan (Apollo/Athena/Merlin) kalıntıları"
    severity = "high"
    category = "c2-framework"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $mythic_1 = "mythic_payloadtype_container" ascii
    $mythic_2 = "get_tasking" ascii fullword
    $mythic_3 = "post_response" ascii fullword
    $agent_1 = "Apollo.Tasks" ascii
    $agent_2 = "Athena.Commands" ascii
    $agent_3 = "merlin/pkg/agent" ascii
    $agent_4 = "checkin_uuid" ascii
  condition:
    filesize < 60MB and ((2 of ($mythic_*) and 1 of ($agent_*)) or 2 of ($agent_*))
}

rule Proton_Generic_Http_Beacon_Loop
{
  meta:
    description = "Sabit aralıklı HTTP yoklama ve komut yürütme döngüsü taşıyan ajan"
    severity = "medium"
    category = "c2-framework"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $beacon_1 = "sleep_interval" ascii wide nocase
    $beacon_2 = "beacon_interval" ascii wide nocase
    $beacon_3 = "checkin_interval" ascii wide nocase
    $beacon_4 = "jitter" ascii wide fullword nocase
    $task_1 = "cmd.exe /c" ascii wide nocase
    $task_2 = "task_id" ascii wide nocase
    $task_3 = "command_output" ascii wide nocase
    $task_4 = "agent_id" ascii wide nocase
    $net_1 = "WinHttpSendRequest" ascii wide
    $net_2 = "HttpSendRequest" ascii wide
    $net_3 = "InternetOpenUrl" ascii wide
  condition:
    uint16(0) == 0x5a4d and filesize < 20MB
    and 2 of ($beacon_*) and 2 of ($task_*) and 1 of ($net_*)
}

rule Proton_Dns_Beacon_Channel
{
  meta:
    description = "DNS TXT kayıtları üzerinden komut alan gizli kanal"
    severity = "high"
    category = "c2-framework"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $dns_1 = "DnsQuery_A" ascii wide
    $dns_2 = "DnsQuery_W" ascii wide
    $dns_3 = "DNS_TYPE_TEXT" ascii wide
    $dns_4 = "DnsRecordListFree" ascii wide
    $encode_1 = "CryptBinaryToString" ascii wide
    $encode_2 = "base32" ascii wide nocase
    $encode_3 = "base64_encode" ascii wide nocase
    $exec_1 = "CreateProcess" ascii wide
    $exec_2 = "WinExec" ascii wide
    $exec_3 = "ShellExecute" ascii wide
  condition:
    uint16(0) == 0x5a4d and filesize < 20MB
    and 2 of ($dns_*) and 1 of ($encode_*) and 1 of ($exec_*)
}

rule Proton_Named_Pipe_Peer_To_Peer_C2
{
  meta:
    description = "Adlandırılmış boru üzerinden eşler arası C2 yönlendirmesi"
    severity = "high"
    category = "c2-framework"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $pipe_1 = "CreateNamedPipe" ascii wide
    $pipe_2 = "ConnectNamedPipe" ascii wide
    $pipe_3 = "\\\\.\\pipe\\" ascii wide
    $token = "ImpersonateNamedPipeClient" ascii wide
    $exec_1 = "CreateProcessAsUser" ascii wide
    $exec_2 = "CreateProcessWithToken" ascii wide
    $exec_3 = "DuplicateTokenEx" ascii wide
  condition:
    uint16(0) == 0x5a4d and filesize < 20MB
    and 2 of ($pipe_*) and $token and 1 of ($exec_*)
}
