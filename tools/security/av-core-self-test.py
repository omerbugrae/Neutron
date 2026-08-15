#!/usr/bin/env python3
"""Isolated AV-core regression tests; never changes Windows security state."""

from __future__ import annotations

import hashlib
import os
import shutil
import sys
import tempfile
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "src"))


def main() -> int:
    test_root = Path(tempfile.mkdtemp(prefix="neutron-av-core-"))
    previous_data = os.environ.get("NEUTRON_DATA_DIR")
    previous_temp = os.environ.get("TEMP")
    os.environ["NEUTRON_DATA_DIR"] = str(test_root / "data")
    os.environ["TEMP"] = str(test_root)
    try:
        import engine

        settings = engine.read_app_settings()
        assert settings["signature_auto_update_enabled"] is True
        assert settings["signature_update_interval_hours"] == 6
        assert engine.write_app_setting("signature_update_interval_hours", 99)["signature_update_interval_hours"] == 24

        fake_thumbprint = "A" * 40
        engine.trust_publisher(fake_thumbprint, "CN=Neutron isolated test")
        assert fake_thumbprint in engine.trusted_publisher_thumbprints()

        lolbin = test_root / "mshta.exe"
        lolbin.write_bytes(b"isolated harmless fixture")
        behavior = engine.suspicious_process_finding(
            lolbin,
            command_line='"mshta.exe" https://example.invalid/test.hta',
            parent_path=r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
        )
        assert behavior is not None
        assert (behavior.risk_score or 0) >= 60
        assert "Davranış riski" in behavior.reason

        ordinary = test_root / "ordinary.exe"
        ordinary.write_bytes(b"ordinary isolated fixture")
        assert engine.suspicious_process_finding(ordinary, command_line=str(ordinary)) is None

        # Self-process suppression is path-anchored: this checked-out Neutron
        # tree is trusted, an identically named executable elsewhere is not.
        assert engine.is_neutron_owned_process_path(PROJECT_ROOT / "src" / "engine.py")
        assert not engine.is_neutron_owned_process_path(test_root / "Neutron.exe")
        fake_processes = {
            100: str(PROJECT_ROOT / "Neutron.exe"),
            101: str(Path(os.environ.get("SystemRoot", r"C:\\Windows")) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"),
        }
        assert engine.is_neutron_process_or_descendant(101, fake_processes, {101: 100})
        assert not engine.is_neutron_process_or_descendant(101, fake_processes, {101: 999})
        previous_internal = os.environ.get("NEUTRON_INTERNAL_PATHS")
        os.environ["NEUTRON_INTERNAL_PATHS"] = str(PROJECT_ROOT)
        try:
            assert engine.is_path_excluded(PROJECT_ROOT / "Neutron.exe", engine.load_exclusion_set())
            assert not engine.is_path_excluded(test_root / "Neutron.exe", engine.load_exclusion_set())
        finally:
            if previous_internal is None:
                os.environ.pop("NEUTRON_INTERNAL_PATHS", None)
            else:
                os.environ["NEUTRON_INTERNAL_PATHS"] = previous_internal

        native_fixture = PROJECT_ROOT / "runtime" / "service" / "x64" / "NeutronServiceHost.exe"
        if native_fixture.is_file():
            pe_analysis = engine.analyze_pe(native_fixture, native_fixture.stat().st_size)
            assert pe_analysis is not None
            assert pe_analysis.image_kind == "EXE"
            assert pe_analysis.risk_score < 85

        sample = test_root / "incident-safe-test.bin"
        sample.write_bytes(b"NEUTRON_INCIDENT_REVERSIBLE_SAFE_TEST")
        digest = hashlib.sha256(sample.read_bytes()).hexdigest()
        event_id = engine.save_protection_event(
            "isolated-test",
            engine.Finding(
                path=str(sample), kind="signature", severity="high",
                reason="İzole ve zararsız olay müdahalesi öz testi", sha256=digest, risk_score=100,
            ),
        )
        assert engine.remediate_protection_event(event_id) == 0
        assert not sample.exists()
        with engine.open_database() as connection:
            event = connection.execute(
                "SELECT disposition, incident_id FROM protection_events WHERE id=?", (event_id,)
            ).fetchone()
            assert event[0] == "remediated" and event[1]
            incident_id = int(event[1])
            action_types = {row[0] for row in connection.execute(
                "SELECT action_type FROM response_actions WHERE incident_id=?", (incident_id,)
            ).fetchall()}
            assert "quarantine" in action_types
        firewall_detail = '{"rule_name":"Neutron-Incident-%d-Outbound","target_path":%s}' % (
            incident_id, __import__("json").dumps(str(sample)),
        )
        assert engine.record_incident_firewall_action(incident_id, firewall_detail) == 0
        with engine.open_database() as connection:
            firewall_action_id = int(connection.execute(
                "SELECT id FROM response_actions WHERE incident_id=? AND action_type='firewall-block'",
                (incident_id,),
            ).fetchone()[0])
        assert engine.finalize_incident_external_rollback(firewall_action_id) == 0
        assert engine.rollback_response_incident(incident_id) == 0
        assert sample.read_bytes() == b"NEUTRON_INCIDENT_REVERSIBLE_SAFE_TEST"
        with engine.open_database() as connection:
            assert connection.execute("SELECT state FROM response_incidents WHERE id=?", (incident_id,)).fetchone()[0] == "rolled-back"

        assert engine.terminate_process_tree_for_image(str(test_root / "not-running.exe")) == []
        print("AV çekirdek öz testi başarılı (yalnız geçici klasör; sistem koruması değiştirilmedi).")
        return 0
    finally:
        if previous_data is None:
            os.environ.pop("NEUTRON_DATA_DIR", None)
        else:
            os.environ["NEUTRON_DATA_DIR"] = previous_data
        if previous_temp is None:
            os.environ.pop("TEMP", None)
        else:
            os.environ["TEMP"] = previous_temp
        shutil.rmtree(test_root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
