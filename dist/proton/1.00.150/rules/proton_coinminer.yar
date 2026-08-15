/*
  Proton - İzinsiz kripto para madenciliği.

  Kullanıcı onayı olmadan kurulan madenci ikilileri, havuz yapılandırmaları ve
  tarayıcı içi madencilik betiklerini kapsar. Meşru madencilik yazılımı da bu
  dizgileri taşıyabileceğinden severity değerleri ölçülü tutulmuştur.
*/

rule Proton_Xmrig_Miner_Artifacts
{
  meta:
    description = "XMRig madenci ikilisi ve yapılandırma anahtarları"
    severity = "high"
    category = "coinminer"
    confidence = "high"
    author = "Neutron detection engineering"
  strings:
    $name_1 = "xmrig" ascii wide nocase
    $name_2 = "XMRig " ascii wide
    $cfg_1 = "\"donate-level\"" ascii wide nocase
    $cfg_2 = "\"rig-id\"" ascii wide nocase
    $cfg_3 = "\"max-cpu-usage\"" ascii wide nocase
    $cfg_4 = "\"randomx\"" ascii wide nocase
    $cfg_5 = "\"huge-pages\"" ascii wide nocase
    $algo_1 = "rx/0" ascii wide
    $algo_2 = "cn/r" ascii wide
    $algo_3 = "argon2/chukwa" ascii wide nocase
  condition:
    filesize < 40MB and ((1 of ($name_*) and 1 of ($cfg_*, $algo_*)) or 3 of ($cfg_*))
}

rule Proton_Mining_Pool_Stratum_Configuration
{
  meta:
    description = "Stratum madencilik havuzu bağlantı yapılandırması"
    severity = "medium"
    category = "coinminer"
    confidence = "high"
    author = "Neutron detection engineering"
  strings:
    $stratum_1 = "stratum+tcp://" ascii wide nocase
    $stratum_2 = "stratum+ssl://" ascii wide nocase
    $stratum_3 = "stratum1+tcp://" ascii wide nocase
    $method_1 = "\"method\":\"login\"" ascii wide nocase
    $method_2 = "mining.subscribe" ascii wide nocase
    $method_3 = "mining.authorize" ascii wide nocase
    $method_4 = "\"job_id\"" ascii wide nocase
    $method_5 = "\"blob\"" ascii wide nocase
    $flag_1 = "--donate-level" ascii wide nocase
    $flag_2 = "-o stratum" ascii wide nocase
    $flag_3 = "--cpu-priority" ascii wide nocase
    $flag_4 = "--coin=" ascii wide nocase
  condition:
    filesize < 40MB and (1 of ($stratum_*) or 2 of ($method_*)) and 1 of ($method_*, $flag_*)
}

rule Proton_Stealth_Miner_Host_Preparation
{
  meta:
    description = "Madenciyi gizleyip sistem kaynaklarını ayarlayan yükleyici"
    severity = "high"
    category = "coinminer"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $miner_1 = "stratum" ascii wide nocase
    $miner_2 = "xmrig" ascii wide nocase
    $miner_3 = "nicehash" ascii wide nocase
    $miner_4 = "randomx" ascii wide nocase
    $hide_1 = "SW_HIDE" ascii wide
    $hide_2 = "CREATE_NO_WINDOW" ascii wide
    $hide_3 = /attrib[ \t]+\+[hs]/ ascii wide nocase
    $hide_4 = "SetPriorityClass" ascii wide
    $evade_1 = "taskmgr" ascii wide nocase
    $evade_2 = "procexp" ascii wide nocase
    $evade_3 = "Add-MpPreference" ascii wide nocase
    $evade_4 = "SeLockMemoryPrivilege" ascii wide
    $persist_1 = "CurrentVersion\\Run" ascii wide nocase
    $persist_2 = "schtasks" ascii wide nocase
    $persist_3 = "CreateService" ascii wide
  condition:
    filesize < 40MB and 1 of ($miner_*) and 1 of ($hide_*) and 1 of ($evade_*) and 1 of ($persist_*)
}

rule Proton_Browser_Cryptojacking_Script
{
  meta:
    description = "Tarayıcı içinde çalışan izinsiz madencilik betiği"
    severity = "medium"
    category = "coinminer"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $lib_1 = "CoinHive" ascii wide nocase
    $lib_2 = "CryptoLoot" ascii wide nocase
    $lib_3 = "deepMiner" ascii wide nocase
    $lib_4 = "webminerpool" ascii wide nocase
    $lib_5 = "coinimp" ascii wide nocase
    $api_1 = "new Miner(" ascii wide nocase
    $api_2 = ".start(" ascii wide nocase
    $api_3 = "setNumThreads" ascii wide nocase
    $api_4 = "setThrottle" ascii wide nocase
    $wasm_1 = "WebAssembly.instantiate" ascii wide nocase
    $wasm_2 = "cryptonight" ascii wide nocase
    $ws = "new WebSocket(" ascii wide nocase
  condition:
    filesize < 5MB and
    (
      1 of ($lib_*)
      or ($wasm_2 and ($ws or 1 of ($wasm_*)))
      or (2 of ($api_*) and $wasm_1 and $ws)
    )
}

rule Proton_Gpu_Miner_Bundle_Silent_Install
{
  meta:
    description = "Sessiz kurulan GPU madenci paketi"
    severity = "medium"
    category = "coinminer"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $miner_1 = "phoenixminer" ascii wide nocase
    $miner_2 = "lolminer" ascii wide nocase
    $miner_3 = "t-rex" ascii wide nocase
    $miner_4 = "gminer" ascii wide nocase
    $miner_5 = "nbminer" ascii wide nocase
    $miner_6 = "teamredminer" ascii wide nocase
    $arg_1 = "-pool " ascii wide nocase
    $arg_2 = "-wal " ascii wide nocase
    $arg_3 = "--algo " ascii wide nocase
    $arg_4 = "-epsw" ascii wide nocase
    $silent_1 = "/S" ascii wide fullword
    $silent_2 = "SW_HIDE" ascii wide
    $silent_3 = "CREATE_NO_WINDOW" ascii wide
  condition:
    filesize < 60MB and 1 of ($miner_*) and 1 of ($arg_*) and 1 of ($silent_*)
}
