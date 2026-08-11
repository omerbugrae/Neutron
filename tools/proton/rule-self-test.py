#!/usr/bin/env python3
"""Compile Proton YARA sources and verify conservative match thresholds."""

from pathlib import Path

import yara


RULE_DIRECTORY = Path(__file__).resolve().parent / "examples" / "rules"


def matched_names(rules: yara.Rules, sample: bytes) -> set[str]:
    return {match.rule for match in rules.match(data=sample)}


def words(*parts: bytes) -> bytes:
    """Build command-like fixtures at runtime, never in the invoking shell command line."""
    return b" ".join(parts)


def main() -> None:
    paths = {path.stem: str(path) for path in sorted(RULE_DIRECTORY.glob("*.yar"))}
    rules = yara.compile(filepaths=paths)
    positive_cases = {
        "injection": (
            b"MZ" + (b"X" * 40) + b"VirtualAllocEx WriteProcessMemory CreateRemoteThread",
            "Proton_Process_Injection_Primitives",
        ),
        "credential": (
            b"MZ" + (b"X" * 40) + b"lsass.exe MiniDumpWriteDump SeDebugPrivilege",
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
    }
    for label, (sample, expected) in positive_cases.items():
        matches = matched_names(rules, sample)
        assert expected in matches, f"{label}: expected {expected}, received {matches}"

    negative_samples = (
        b"ordinary application configuration and documentation",
        b"MZ VirtualAllocEx only",
        b"powershell Write-Output hello",
        b"reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        b"vssadmin list shadows",
    )
    advanced_names = {expected for _sample, expected in positive_cases.values()}
    for sample in negative_samples:
        matches = matched_names(rules, sample)
        assert not matches.intersection(advanced_names), f"negative sample matched: {matches}"

    print(
        f"Advanced YARA tests: OK "
        f"({len(positive_cases)} positive, {len(negative_samples)} negative)"
    )


if __name__ == "__main__":
    main()
