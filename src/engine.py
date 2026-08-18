#!/usr/bin/env python3
"""Neutron'un salt-okunur hızlı tarama motoru.

Bu ilk sürüm bir antivirüs iddiasında bulunmaz. Kullanıcının profil ve geçici dosya
klasörlerinde sınırlı bir tarama yapar; dosya silmez, taşımaz,
karantinaya almaz veya ağ üzerinden veri göndermez. Electron ile standart
çıktıdaki JSON Lines olayları üzerinden konuşur.
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import hashlib
import json
import math
import os
import queue
import re
import secrets
import shutil
import socket
import sqlite3
import stat as stat_module
import struct
import subprocess
import sys
import threading
import time
from urllib.parse import urlsplit
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any
from datetime import datetime, timedelta, timezone

from ml_pe import (
    FEATURE_SCHEMA_VERSION,
    build_feature_vector,
    merge_ensemble_predictions,
    model_cache_token,
    predict_ember2024,
    predict_ensemble,
)

for _stream in (sys.stdout, sys.stderr):
    if _stream is not None and hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8", errors="backslashreplace")

try:
    import winreg
except ImportError:
    winreg = None

try:
    import yara
except ImportError:
    yara = None

try:
    import pefile
except ImportError:
    pefile = None

try:
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer
except ImportError:
    FileSystemEventHandler = None
    Observer = None


MAX_FILES = 1_500


def resolved_max_files(setting_value: Any) -> int:
    """scan_max_files stores 0 to mean "sınırsız" (unlimited) -- iter_files'
    loop condition (`yielded < max_files`) needs an actual large int, not
    0, or it would stop immediately."""
    value = int(setting_value)
    return sys.maxsize if value == 0 else value
MAX_FULL_SCAN_FILES = 1_000_000
MAX_DEPTH = 8
MAX_HASH_BYTES = 25 * 1024 * 1024
MAX_CONTENT_BYTES = 1 * 1024 * 1024
MAX_YARA_BYTES = 25 * 1024 * 1024
MAX_PE_BYTES = 64 * 1024 * 1024
MAX_PE_SECTIONS = 96
MAX_PE_IMPORTS = 4096
MAX_ARCHIVE_INPUT_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_MEMBER_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_TOTAL_BYTES = 128 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 512
MAX_ARCHIVE_DEPTH = 3
MAX_ARCHIVE_COMPRESSION_RATIO = 250
MAX_ARCHIVE_FINDINGS = 50
MAX_PROTON_PAYLOAD_BYTES = 64 * 1024 * 1024
MAX_PROTON_SIGNATURES = 1_000_000
MAX_PROTON_RULES = 256
MAX_PROTON_WEB_INDICATORS = 500_000
MAX_PROTON_RULE_BYTES = 2 * 1024 * 1024
MAX_PROTON_TOTAL_RULE_BYTES = 16 * 1024 * 1024
MAX_ANALYSIS_CACHE_ENTRIES = 25_000
ANALYSIS_CACHE_RETENTION_DAYS = 30
# Bump whenever the analysis pipeline can reach a different verdict on the same
# bytes, or already-scanned files keep their old cached result and silently skip
# the new logic. v3: model-led detection (ML_AUTONOMOUS_*) can now raise a file
# to the auto-quarantine bar on its own.
ANALYSIS_CACHE_REVISION = "static-analysis-v5-docs-lnk-motw"
PROGRESS_INTERVAL = 25
WATCH_INTERVAL_SECONDS = 5.0
BEHAVIOR_INTERVAL_SECONDS = 3.0
NETWORK_INTERVAL_SECONDS = 10.0
WATCH_DEBOUNCE_SECONDS = 0.9
WATCH_SETTLE_SECONDS = 0.65
SIGNATURE_DATABASE_NAME = "Proton"
NEUTRON_ENGINE_VERSION = "0.3.0"
BUILTIN_SIGNATURE_VERSION = "1.00.001"
PROTON_VERSION_PATTERN = re.compile(r"^\d+\.\d{2}\.\d{3}$")
PROTON_SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")
PROTON_RULE_NAME_PATTERN = re.compile(r"^[A-Za-z0-9._-]+\.yar$")
EXCLUSION_EXTENSION_PATTERN = re.compile(r"^\.[a-z0-9][a-z0-9_+-]{0,15}$")
DEFAULT_APP_SETTINGS: dict[str, Any] = {
    "start_with_windows": False,
    "protection_enabled": True,
    "behavior_protection_enabled": True,
    "web_protection_enabled": True,
    "amsi_protection_enabled": False,
    "watchdog_protection_enabled": False,
    "wsc_registration_enabled": False,
    "network_protection_enabled": False,
    "service_mode_enabled": False,
    "memory_scan_enabled": False,
    "usb_protection_enabled": True,
    "ransomware_protection_enabled": True,
    "cloud_lookup_enabled": False,
    "ml_assisted_detection_enabled": True,
    "malwarebazaar_api_key": "",
    "virustotal_api_key": "",
    "notifications_enabled": True,
    "watch_paths": [],
    "scan_max_files": MAX_FILES,
    "scheduled_scan_enabled": True,
    "scheduled_scan_last_run_at": 0,
    "signature_auto_update_enabled": True,
    "signature_update_interval_hours": 6,
    "signature_update_last_check_at": 0,
    "signature_update_last_success_at": 0,
    "signature_update_last_error": "",
}

# EICAR, antivirüs ürünlerini güvenli şekilde denemek için kullanılan zararsız
# standart test dizgesidir. Bu motor yalnızca bu test imzasını kesin bulgu sayar.
EICAR_MARKER = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
# A Neutron-only benign fixture for validating the full quarantine workflow on
# machines where another antivirus locks the industry-standard EICAR file first.
NEUTRON_QUARANTINE_TEST_MARKER = b"NEUTRON_QUARANTINE_SAFE_TEST_V1"
EXECUTABLE_EXTENSIONS = {
    ".bat", ".cmd", ".com", ".dll", ".exe", ".hta", ".jar", ".js", ".jse",
    ".lnk", ".msi", ".ps1", ".psm1", ".scr", ".vbe", ".vbs", ".wsf",
}
DOCUMENT_EXTENSIONS = {".doc", ".docx", ".pdf", ".png", ".jpg", ".jpeg", ".txt", ".xlsx", ".zip"}
ARCHIVE_EXTENSIONS = {".zip", ".7z", ".rar"}
RISK_WORDS = {"keygen", "crack", "ransom", "payload", "trojan"}
SKIP_DIRECTORIES = {
    "$recycle.bin", "appdata", "node_modules", "system volume information",
    "venv", "windows", ".git", "neutronsecret", "neutronprotonrelease",
    "neutronprotoncandidate", "neutronlicensesecret",
}


@dataclass
class Finding:
    path: str
    kind: str
    severity: str
    reason: str
    sha256: str | None = None
    risk_score: int | None = None
    container_path: str | None = None
    publisher_subject: str | None = None
    publisher_thumbprint: str | None = None
    ml_shadow_score: int | None = None
    ml_model_version: str | None = None
    ml_shadow_details: dict[str, Any] | None = None


@dataclass(frozen=True)
class ExclusionSet:
    folders: tuple[str, ...]
    extensions: frozenset[str]
    hashes: frozenset[str]


@dataclass(frozen=True)
class PEAnalysis:
    architecture: str
    image_kind: str
    entry_point: int
    section_count: int
    import_count: int
    signature_status: str
    publisher_subject: str | None
    publisher_thumbprint: str | None
    risk_score: int
    reasons: tuple[str, ...]
    ml_shadow_score: int | None
    ml_model_version: str | None
    ml_features: dict[str, float] | None
    ml_shadow_details: dict[str, Any] | None


@dataclass
class AnalysisCacheEntry:
    file_size: int
    modified_ns: int
    changed_ns: int
    findings_json: str
    analyzed_at: str


@dataclass
class AnalysisCacheSession:
    engine_revision: str
    proton_version: str
    yara_fingerprint: str
    entries: dict[str, AnalysisCacheEntry] = field(default_factory=dict)
    pending: dict[str, AnalysisCacheEntry] = field(default_factory=dict)
    hits: int = 0
    misses: int = 0
    stores: int = 0


@dataclass
class ArchiveBudget:
    members: int = 0
    expanded_bytes: int = 0
    findings: int = 0


def data_directory() -> Path:
    """Electron'ın verdiği klasörü, yoksa proje içindeki data klasörünü kullanır."""
    configured = os.environ.get("NEUTRON_DATA_DIR")
    if configured:
        return Path(configured)
    return Path(__file__).resolve().parent.parent / "data"


def bundled_data_directory() -> Path | None:
    configured = os.environ.get("NEUTRON_BUNDLED_DATA_DIR")
    return Path(configured) if configured else None


def database_path() -> Path:
    return data_directory() / "neutron.db"


@contextmanager
def open_database() -> Iterator[sqlite3.Connection]:
    directory = data_directory()
    directory.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(database_path())
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA journal_mode = WAL")
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS scan_runs (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          completed_at TEXT NOT NULL,
          mode TEXT NOT NULL,
          target_labels TEXT NOT NULL,
          scanned_files INTEGER NOT NULL,
          confirmed_count INTEGER NOT NULL,
          review_count INTEGER NOT NULL,
          elapsed_ms INTEGER NOT NULL,
          limited INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS scan_findings (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          scan_run_id INTEGER NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
          file_path TEXT NOT NULL,
          kind TEXT NOT NULL,
          severity TEXT NOT NULL,
          reason TEXT NOT NULL,
          sha256 TEXT
        );

        CREATE INDEX IF NOT EXISTS scan_runs_completed_at_idx
          ON scan_runs(completed_at DESC);
        CREATE INDEX IF NOT EXISTS scan_findings_scan_run_id_idx
          ON scan_findings(scan_run_id);

        CREATE TABLE IF NOT EXISTS quarantine_items (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          original_path TEXT NOT NULL,
          stored_path TEXT NOT NULL UNIQUE,
          file_name TEXT NOT NULL,
          sha256 TEXT,
          reason TEXT NOT NULL,
          quarantined_at TEXT NOT NULL,
          state TEXT NOT NULL DEFAULT 'active',
          restored_at TEXT,
          deleted_at TEXT
        );

        CREATE INDEX IF NOT EXISTS quarantine_items_state_idx
          ON quarantine_items(state, quarantined_at DESC);

        CREATE TABLE IF NOT EXISTS protection_events (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          occurred_at TEXT NOT NULL,
          event_kind TEXT NOT NULL,
          file_path TEXT NOT NULL,
          finding_kind TEXT,
          severity TEXT,
          reason TEXT,
          sha256 TEXT,
          disposition TEXT NOT NULL DEFAULT 'pending',
          disposition_at TEXT,
          quarantine_item_id INTEGER
        );

        CREATE INDEX IF NOT EXISTS protection_events_occurred_at_idx
          ON protection_events(occurred_at DESC);

        CREATE TABLE IF NOT EXISTS signatures (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          sha256 TEXT NOT NULL UNIQUE,
          file_size INTEGER NOT NULL,
          name TEXT NOT NULL,
          severity TEXT NOT NULL,
          source TEXT NOT NULL,
          enabled INTEGER NOT NULL DEFAULT 1,
          added_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS signatures_size_idx
          ON signatures(file_size, enabled);

        CREATE TABLE IF NOT EXISTS signature_metadata (
          key TEXT PRIMARY KEY,
          value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS proton_yara_rules (
          name TEXT PRIMARY KEY,
          sha256 TEXT NOT NULL,
          source_text TEXT NOT NULL,
          installed_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS proton_provenance (
          id INTEGER PRIMARY KEY CHECK(id = 1),
          source_name TEXT NOT NULL,
          source_url TEXT NOT NULL,
          collected_at TEXT NOT NULL,
          license TEXT NOT NULL,
          review_policy TEXT NOT NULL,
          installed_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS proton_web_indicators (
          indicator_type TEXT NOT NULL CHECK(indicator_type IN ('domain', 'url')),
          value TEXT NOT NULL,
          name TEXT NOT NULL,
          severity TEXT NOT NULL,
          installed_at TEXT NOT NULL,
          PRIMARY KEY(indicator_type, value)
        );

        CREATE TABLE IF NOT EXISTS proton_snapshots (
          version TEXT PRIMARY KEY,
          payload_json TEXT NOT NULL,
          installed_at TEXT NOT NULL,
          last_activated_at TEXT NOT NULL,
          active INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS proton_update_history (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          occurred_at TEXT NOT NULL,
          action TEXT NOT NULL CHECK(action IN ('install', 'rollback')),
          version TEXT NOT NULL,
          status TEXT NOT NULL CHECK(status IN ('success', 'failed')),
          detail TEXT
        );

        CREATE INDEX IF NOT EXISTS proton_update_history_time_idx
          ON proton_update_history(occurred_at DESC);

        CREATE TABLE IF NOT EXISTS app_settings (
          key TEXT PRIMARY KEY,
          value_json TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS exclusions (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          kind TEXT NOT NULL CHECK(kind IN ('folder', 'extension', 'hash')),
          value TEXT NOT NULL,
          normalized_value TEXT NOT NULL,
          label TEXT,
          enabled INTEGER NOT NULL DEFAULT 1,
          created_at TEXT NOT NULL,
          UNIQUE(kind, normalized_value)
        );

        CREATE TABLE IF NOT EXISTS exclusion_events (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          occurred_at TEXT NOT NULL,
          action TEXT NOT NULL CHECK(action IN ('added', 'removed')),
          exclusion_kind TEXT NOT NULL,
          exclusion_value TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS exclusions_enabled_idx
          ON exclusions(enabled, kind);

        CREATE INDEX IF NOT EXISTS exclusion_events_occurred_idx
          ON exclusion_events(occurred_at DESC);

        CREATE TABLE IF NOT EXISTS trusted_publishers (
          thumbprint TEXT PRIMARY KEY,
          subject TEXT NOT NULL,
          created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS analysis_cache (
          path_key TEXT PRIMARY KEY,
          file_path TEXT NOT NULL,
          file_size INTEGER NOT NULL,
          modified_ns INTEGER NOT NULL,
          changed_ns INTEGER NOT NULL,
          engine_revision TEXT NOT NULL,
          proton_version TEXT NOT NULL,
          yara_fingerprint TEXT NOT NULL,
          findings_json TEXT NOT NULL,
          analyzed_at TEXT NOT NULL,
          last_used_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS analysis_cache_context_idx
          ON analysis_cache(engine_revision, proton_version, yara_fingerprint, last_used_at DESC);

        CREATE TABLE IF NOT EXISTS analysis_cache_metrics (
          id INTEGER PRIMARY KEY CHECK(id = 1),
          hits INTEGER NOT NULL DEFAULT 0,
          misses INTEGER NOT NULL DEFAULT 0,
          stores INTEGER NOT NULL DEFAULT 0,
          updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS ml_shadow_observations (
          sha256 TEXT PRIMARY KEY,
          model_version TEXT NOT NULL,
          feature_schema_version INTEGER NOT NULL,
          ml_score INTEGER NOT NULL,
          heuristic_score INTEGER NOT NULL,
          signature_status TEXT NOT NULL,
          features_json TEXT NOT NULL,
          model_scores_json TEXT,
          disagreement INTEGER,
          independent_families INTEGER,
          independent_categories INTEGER,
          first_seen_at TEXT NOT NULL,
          last_seen_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS ml_shadow_observations_seen_idx
          ON ml_shadow_observations(last_seen_at DESC);

        -- Every automatic (no-human-in-the-loop) quarantine, with the kind of
        -- evidence that drove it. Exists to answer one question quickly: is
        -- Neutron removing files at a rate that a real infection explains?
        CREATE TABLE IF NOT EXISTS auto_quarantine_log (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          occurred_at TEXT NOT NULL,
          file_path TEXT NOT NULL,
          driver TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS auto_quarantine_log_time_idx
          ON auto_quarantine_log(occurred_at DESC);

        CREATE TABLE IF NOT EXISTS cloud_reputation_cache (
          sha256 TEXT PRIMARY KEY,
          verdict TEXT NOT NULL,
          source TEXT NOT NULL,
          reason TEXT,
          checked_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS network_ip_indicators (
          value TEXT PRIMARY KEY,
          name TEXT,
          severity TEXT NOT NULL,
          installed_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS firewall_rules (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          program_path TEXT NOT NULL,
          program_name TEXT NOT NULL,
          action TEXT NOT NULL,
          direction TEXT NOT NULL,
          rule_name TEXT NOT NULL UNIQUE,
          enabled INTEGER NOT NULL DEFAULT 1,
          created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS startup_item_backups (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          source TEXT NOT NULL,
          hive TEXT,
          key_path TEXT NOT NULL,
          view INTEGER NOT NULL DEFAULT 0,
          value_name TEXT NOT NULL,
          original_path TEXT NOT NULL,
          stored_path TEXT,
          state TEXT NOT NULL DEFAULT 'disabled',
          disabled_at TEXT NOT NULL,
          restored_at TEXT
        );

        CREATE TABLE IF NOT EXISTS response_incidents (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          protection_event_id INTEGER,
          created_at TEXT NOT NULL,
          state TEXT NOT NULL DEFAULT 'active',
          summary TEXT NOT NULL,
          rolled_back_at TEXT
        );

        CREATE TABLE IF NOT EXISTS response_actions (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          incident_id INTEGER NOT NULL REFERENCES response_incidents(id) ON DELETE CASCADE,
          action_type TEXT NOT NULL,
          target TEXT NOT NULL,
          before_json TEXT,
          after_json TEXT,
          reversible INTEGER NOT NULL DEFAULT 0,
          state TEXT NOT NULL DEFAULT 'applied',
          created_at TEXT NOT NULL,
          reverted_at TEXT
        );

        CREATE INDEX IF NOT EXISTS response_actions_incident_idx ON response_actions(incident_id, id);
        """
    )
    protection_columns = {
        str(row[1]) for row in connection.execute("PRAGMA table_info(protection_events)").fetchall()
    }
    if "disposition" not in protection_columns:
        connection.execute(
            "ALTER TABLE protection_events ADD COLUMN disposition TEXT NOT NULL DEFAULT 'pending'"
        )
        connection.execute(
            "UPDATE protection_events SET disposition = 'ignored' WHERE disposition = 'pending'"
        )
    if "disposition_at" not in protection_columns:
        connection.execute("ALTER TABLE protection_events ADD COLUMN disposition_at TEXT")
        connection.execute(
            "UPDATE protection_events SET disposition_at = occurred_at WHERE disposition = 'ignored'"
        )
    if "quarantine_item_id" not in protection_columns:
        connection.execute("ALTER TABLE protection_events ADD COLUMN quarantine_item_id INTEGER")
    if "risk_score" not in protection_columns:
        connection.execute("ALTER TABLE protection_events ADD COLUMN risk_score INTEGER")
    if "publisher_subject" not in protection_columns:
        connection.execute("ALTER TABLE protection_events ADD COLUMN publisher_subject TEXT")
    if "publisher_thumbprint" not in protection_columns:
        connection.execute("ALTER TABLE protection_events ADD COLUMN publisher_thumbprint TEXT")
    if "incident_id" not in protection_columns:
        connection.execute("ALTER TABLE protection_events ADD COLUMN incident_id INTEGER")
    quarantine_columns = {
        str(row[1]) for row in connection.execute("PRAGMA table_info(quarantine_items)").fetchall()
    }
    if "incident_id" not in quarantine_columns:
        connection.execute("ALTER TABLE quarantine_items ADD COLUMN incident_id INTEGER")
    # Neutralised-at-rest quarantine (see quarantine_file). Rows written by
    # older builds keep payload_version NULL and are restored as plain files.
    if "payload_version" not in quarantine_columns:
        connection.execute("ALTER TABLE quarantine_items ADD COLUMN payload_version INTEGER")
    if "payload_key" not in quarantine_columns:
        connection.execute("ALTER TABLE quarantine_items ADD COLUMN payload_key TEXT")
    if "stored_sha256" not in quarantine_columns:
        connection.execute("ALTER TABLE quarantine_items ADD COLUMN stored_sha256 TEXT")
    ml_observation_columns = {
        str(row[1]) for row in connection.execute("PRAGMA table_info(ml_shadow_observations)").fetchall()
    }
    if "model_scores_json" not in ml_observation_columns:
        connection.execute("ALTER TABLE ml_shadow_observations ADD COLUMN model_scores_json TEXT")
    if "disagreement" not in ml_observation_columns:
        connection.execute("ALTER TABLE ml_shadow_observations ADD COLUMN disagreement INTEGER")
    if "independent_families" not in ml_observation_columns:
        connection.execute("ALTER TABLE ml_shadow_observations ADD COLUMN independent_families INTEGER")
    if "independent_categories" not in ml_observation_columns:
        connection.execute("ALTER TABLE ml_shadow_observations ADD COLUMN independent_categories INTEGER")
    eicar_sha256 = hashlib.sha256(EICAR_MARKER).hexdigest()
    updated_at = datetime.now(timezone.utc).isoformat()
    connection.execute(
        """
        INSERT OR IGNORE INTO signatures (
          sha256, file_size, name, severity, source, enabled, added_at
        ) VALUES (?, ?, ?, ?, ?, 1, ?)
        """,
        (
            eicar_sha256,
            len(EICAR_MARKER),
            "EICAR güvenli antivirüs test imzası",
            "high",
            "builtin",
            updated_at,
        ),
    )
    connection.execute(
        "INSERT OR IGNORE INTO signature_metadata (key, value) VALUES ('version', ?)",
        (BUILTIN_SIGNATURE_VERSION,),
    )
    connection.execute(
        "UPDATE signature_metadata SET value = ? WHERE key = 'version' AND value LIKE 'builtin-%'",
        (BUILTIN_SIGNATURE_VERSION,),
    )
    connection.execute(
        """
        INSERT INTO signature_metadata (key, value) VALUES ('database_name', ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value
        """,
        (SIGNATURE_DATABASE_NAME,),
    )
    connection.execute(
        "INSERT OR IGNORE INTO signature_metadata (key, value) VALUES ('updated_at', ?)",
        (updated_at,),
    )
    connection.executemany(
        "INSERT OR IGNORE INTO app_settings (key, value_json, updated_at) VALUES (?, ?, ?)",
        [
            (key, json.dumps(value, ensure_ascii=False), updated_at)
            for key, value in DEFAULT_APP_SETTINGS.items()
        ],
    )
    connection.execute(
        """
        INSERT OR IGNORE INTO analysis_cache_metrics (id, hits, misses, stores, updated_at)
        VALUES (1, 0, 0, 0, ?)
        """,
        (updated_at,),
    )
    connection.commit()
    try:
        yield connection
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    finally:
        connection.close()


def load_signatures() -> dict[int, dict[str, dict[str, Any]]]:
    """Load enabled hashes once so individual files never open SQLite."""
    index: dict[int, dict[str, dict[str, Any]]] = {}
    with open_database() as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """
            SELECT sha256, file_size, name, severity, source
            FROM signatures
            WHERE enabled = 1
            """
        ).fetchall()
    for row in rows:
        size_bucket = index.setdefault(int(row["file_size"]), {})
        size_bucket[str(row["sha256"])] = dict(row)
    return index


def signature_status_payload() -> dict[str, Any]:
    with open_database() as connection:
        connection.row_factory = sqlite3.Row
        count = int(connection.execute(
            "SELECT COUNT(*) FROM signatures WHERE enabled = 1"
        ).fetchone()[0])
        web_count = int(connection.execute("SELECT COUNT(*) FROM proton_web_indicators").fetchone()[0])
        metadata = dict(connection.execute(
            "SELECT key, value FROM signature_metadata"
        ).fetchall())
        provenance = connection.execute(
            "SELECT source_name, source_url, collected_at, license, review_policy FROM proton_provenance WHERE id = 1"
        ).fetchone()
        rollback_versions = [str(row[0]) for row in connection.execute(
            "SELECT version FROM proton_snapshots WHERE active = 0 ORDER BY last_activated_at DESC LIMIT 4"
        ).fetchall()]
        update_history = [dict(row) for row in connection.execute(
            "SELECT occurred_at, action, version, status, detail FROM proton_update_history ORDER BY id DESC LIMIT 10"
        ).fetchall()]
    return {
        "database_name": metadata.get("database_name", SIGNATURE_DATABASE_NAME),
        "version": metadata.get("version", BUILTIN_SIGNATURE_VERSION),
        "updated_at": metadata.get("updated_at"),
        "signature_count": count,
        "web_indicator_count": web_count,
        "source": metadata.get("source", "builtin"),
        "network_used": metadata.get("source") == "github-release",
        "provenance": dict(provenance) if provenance else None,
        "rollback_versions": rollback_versions,
        "update_history": update_history,
    }


def normalize_app_setting(key: str, value: Any) -> Any:
    if key not in DEFAULT_APP_SETTINGS:
        raise ValueError("Bilinmeyen ayar")
    if key in {
        "start_with_windows", "protection_enabled", "behavior_protection_enabled", "web_protection_enabled",
        "amsi_protection_enabled", "watchdog_protection_enabled", "wsc_registration_enabled",
        "network_protection_enabled", "service_mode_enabled", "memory_scan_enabled", "usb_protection_enabled",
        "ransomware_protection_enabled",
        "cloud_lookup_enabled", "notifications_enabled", "scheduled_scan_enabled",
        "signature_auto_update_enabled", "ml_assisted_detection_enabled",
    }:
        if not isinstance(value, bool):
            raise ValueError("Ayar true veya false olmalı")
        return value
    if key in {"scheduled_scan_last_run_at", "signature_update_last_check_at", "signature_update_last_success_at"}:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError("Zaman damgası sayı olmalı")
        return int(value)
    if key == "signature_update_interval_hours":
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError("Güncelleme aralığı tam sayı olmalı")
        return max(1, min(value, 24))
    if key == "signature_update_last_error":
        if not isinstance(value, str):
            raise ValueError("Güncelleme hatası metin olmalı")
        return value.strip()[:500]
    if key in {"malwarebazaar_api_key", "virustotal_api_key"}:
        if not isinstance(value, str):
            raise ValueError("API anahtarı metin olmalı")
        cleaned = value.strip()
        if len(cleaned) > 128:
            raise ValueError("API anahtarı çok uzun")
        return cleaned
    if key == "scan_max_files":
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError("Tarama sınırı sayı olmalı")
        if value == 0:  # 0 == "sınırsız", see resolved_max_files()
            return 0
        return max(250, min(value, 10_000))
    if key == "watch_paths":
        if not isinstance(value, list):
            raise ValueError("İzleme konumları liste olmalı")
        normalized: list[str] = []
        for raw_path in value[:8]:
            if not isinstance(raw_path, str) or not raw_path.strip():
                continue
            try:
                resolved = Path(raw_path).expanduser().resolve(strict=True)
            except (OSError, RuntimeError):
                continue
            if resolved.is_dir() and str(resolved) not in normalized:
                normalized.append(str(resolved))
        return normalized
    raise ValueError("Desteklenmeyen ayar")


def read_app_settings() -> dict[str, Any]:
    settings = dict(DEFAULT_APP_SETTINGS)
    with open_database() as connection:
        rows = connection.execute("SELECT key, value_json FROM app_settings").fetchall()
    for key, raw_value in rows:
        if key not in DEFAULT_APP_SETTINGS:
            continue
        try:
            settings[key] = normalize_app_setting(key, json.loads(raw_value))
        except (ValueError, TypeError, json.JSONDecodeError):
            settings[key] = DEFAULT_APP_SETTINGS[key]
    return settings


# The PE analyser consults this once per scanned file, and read_app_settings()
# is an uncached SELECT -- reading it per file would put thousands of database
# round trips inside the scan loop. Cached until a setting is written.
_ML_ASSIST_CACHE: dict[str, bool] = {}


def ml_assisted_detection_enabled() -> bool:
    if "value" not in _ML_ASSIST_CACHE:
        try:
            _ML_ASSIST_CACHE["value"] = bool(
                read_app_settings().get("ml_assisted_detection_enabled", True))
        except (OSError, sqlite3.Error):
            _ML_ASSIST_CACHE["value"] = True
    return _ML_ASSIST_CACHE["value"]


def write_app_setting(key: str, value: Any) -> dict[str, Any]:
    _ML_ASSIST_CACHE.pop("value", None)
    normalized = normalize_app_setting(key, value)
    with open_database() as connection:
        connection.execute(
            """
            INSERT INTO app_settings (key, value_json, updated_at) VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET
              value_json = excluded.value_json,
              updated_at = excluded.updated_at
            """,
            (key, json.dumps(normalized, ensure_ascii=False), datetime.now(timezone.utc).isoformat()),
        )
    return read_app_settings()


def canonical_path(path: Path) -> str:
    return os.path.normcase(os.path.normpath(str(path.resolve())))


def path_is_within(path_value: str, folder_value: str) -> bool:
    try:
        return os.path.commonpath([path_value, folder_value]) == folder_value
    except ValueError:
        return False


def protected_exclusion_roots() -> tuple[str, ...]:
    roots: list[str] = []
    for variable in ("SystemRoot", "WINDIR", "ProgramFiles", "ProgramFiles(x86)", "ProgramData"):
        raw_value = os.environ.get(variable)
        if not raw_value:
            continue
        try:
            value = canonical_path(Path(raw_value))
        except (OSError, RuntimeError):
            continue
        if value not in roots:
            roots.append(value)
    return tuple(roots)


def protected_system_quarantine_roots() -> tuple[str, ...]:
    """Narrower than protected_exclusion_roots(): folders that must never be
    touched by an *automatic* quarantine decision (no human in the loop),
    because a wrong match here can break Windows itself. Manual,
    user-confirmed quarantine from the UI is deliberately not gated by this
    -- real malware does sometimes hide in these folders, and that action is
    reversible and explicit."""
    system_root = os.environ.get("SystemRoot") or os.environ.get("WINDIR")
    if not system_root:
        return ()
    roots: list[str] = []
    base = Path(system_root)
    for sub in ("System32", "SysWOW64", "WinSxS", "servicing", "assembly", "Boot"):
        try:
            roots.append(canonical_path(base / sub))
        except (OSError, RuntimeError):
            continue
    return tuple(roots)


def is_protected_system_path(path: Path) -> bool:
    try:
        normalized = canonical_path(path)
    except (OSError, RuntimeError):
        return False
    return any(path_is_within(normalized, root) for root in protected_system_quarantine_roots())


@lru_cache(maxsize=1)
def neutron_own_roots() -> tuple[str, ...]:
    """Neutron's own installation and working directories.

    An antivirus that quarantines its own engine disables itself, and the
    result is not obvious to the user: protection silently stops. The models
    make this a live risk rather than a theoretical one -- a packed, unsigned
    PyInstaller bundle full of scanning code looks, structurally, a great deal
    like the malware they were trained on, and this build is not signed.

    Covered: the frozen engine binary's own folder, the Electron app folder
    above it, the data directory (database, quarantine store) and the bundled
    data directory. Development checkouts resolve to the repository root.
    """
    roots: list[str] = []

    def add(candidate: Path | None) -> None:
        if candidate is None:
            return
        try:
            value = canonical_path(candidate)
        except (OSError, RuntimeError):
            return
        if value and value not in roots:
            roots.append(value)

    try:
        executable = Path(sys.executable).resolve()
    except (OSError, RuntimeError):
        executable = None
    if executable is not None:
        add(executable.parent)
        # A packaged build lives in resources/engine under the app root; the
        # app's own Neutron.exe and Electron runtime sit further up. Walking a
        # bounded number of parents covers both layouts without ever reaching
        # a drive root (guarded below).
        for parent in list(executable.parents)[:6]:
            if parent == parent.anchor or parent.parent == parent:
                break
            if (parent / "Neutron.exe").exists() or (parent / "resources").is_dir():
                add(parent)

    add(Path(__file__).resolve().parent)
    add(Path(__file__).resolve().parent.parent)
    add(data_directory())
    add(bundled_data_directory())

    # A root that resolved to a drive root or the user profile would silently
    # exempt the whole machine from automatic action -- drop those.
    try:
        home = canonical_path(Path.home())
    except (OSError, RuntimeError):
        home = ""
    safe: list[str] = []
    for root in roots:
        try:
            anchor = canonical_path(Path(Path(root).anchor))
        except (OSError, RuntimeError):
            anchor = ""
        if root and root != anchor and root != home:
            safe.append(root)
    return tuple(safe)


def is_neutron_own_path(path: Path) -> bool:
    try:
        normalized = canonical_path(path)
    except (OSError, RuntimeError):
        return False
    return any(path_is_within(normalized, root) for root in neutron_own_roots())


def is_auto_quarantine_forbidden(path: Path) -> bool:
    """Single gate for every automatic (no-human-in-the-loop) removal.

    Manual, user-confirmed quarantine from the UI is deliberately NOT gated by
    this: real malware does hide in system folders, and a manual action is
    explicit and reversible."""
    return is_protected_system_path(path) or is_neutron_own_path(path)


def normalize_exclusion(kind: str, raw_value: str) -> tuple[str, str]:
    if kind == "folder":
        try:
            folder = Path(raw_value).expanduser().resolve(strict=True)
        except (OSError, RuntimeError):
            raise ValueError("Seçilen istisna klasörü kullanılamıyor") from None
        if not folder.is_dir():
            raise ValueError("İstisna konumu bir klasör değil")
        normalized = canonical_path(folder)
        anchor = canonical_path(Path(folder.anchor))
        home = canonical_path(Path.home())
        if normalized in {anchor, home}:
            raise ValueError("Sürücü veya kullanıcı kökünün tamamı istisna bırakılamaz")
        if any(path_is_within(normalized, protected) for protected in protected_exclusion_roots()):
            raise ValueError("Windows ve program sistem klasörleri istisna bırakılamaz")
        return str(folder), normalized
    if kind == "extension":
        extension = raw_value.strip().casefold()
        if extension.startswith("*"):
            extension = extension[1:]
        if not extension.startswith("."):
            extension = f".{extension}"
        if not EXCLUSION_EXTENSION_PATTERN.fullmatch(extension):
            raise ValueError("Dosya uzantısı .ext biçiminde olmalı")
        return extension, extension
    if kind == "hash":
        digest = raw_value.strip().casefold()
        if not PROTON_SHA256_PATTERN.fullmatch(digest):
            raise ValueError("Güvenilir dosya hash değeri geçersiz")
        return digest, digest
    raise ValueError("Desteklenmeyen istisna türü")


def load_exclusion_set() -> ExclusionSet:
    with open_database() as connection:
        rows = connection.execute(
            "SELECT kind, normalized_value FROM exclusions WHERE enabled = 1"
        ).fetchall()
    folders = [str(value) for kind, value in rows if kind == "folder"]
    for raw_path in os.environ.get("NEUTRON_INTERNAL_PATHS", "").split(os.pathsep):
        if not raw_path.strip():
            continue
        try:
            normalized = canonical_path(Path(raw_path))
        except (OSError, RuntimeError):
            continue
        if normalized not in folders:
            folders.append(normalized)
    extensions = frozenset(str(value) for kind, value in rows if kind == "extension")
    hashes = frozenset(str(value) for kind, value in rows if kind == "hash")
    return ExclusionSet(folders=tuple(folders), extensions=extensions, hashes=hashes)


def is_path_excluded(
    path: Path,
    exclusions: ExclusionSet,
    include_extension: bool = True,
) -> bool:
    if include_extension and path.suffix.casefold() in exclusions.extensions:
        return True
    try:
        normalized = canonical_path(path)
    except (OSError, RuntimeError):
        normalized = os.path.normcase(os.path.normpath(str(path.absolute())))
    return any(path_is_within(normalized, folder) for folder in exclusions.folders)


def exclusions_payload() -> dict[str, Any]:
    with open_database() as connection:
        connection.row_factory = sqlite3.Row
        items = [dict(row) for row in connection.execute(
            """
            SELECT id, kind, value, label, created_at
            FROM exclusions
            WHERE enabled = 1
            ORDER BY kind, created_at, id
            """
        ).fetchall()]
        history = [dict(row) for row in connection.execute(
            """
            SELECT occurred_at, action, exclusion_kind, exclusion_value
            FROM exclusion_events
            ORDER BY occurred_at DESC, id DESC
            LIMIT 20
            """
        ).fetchall()]
    return {"items": items, "history": history}


def trusted_publisher_thumbprints() -> frozenset[str]:
    with open_database() as connection:
        rows = connection.execute("SELECT thumbprint FROM trusted_publishers").fetchall()
    return frozenset(str(row[0]).upper() for row in rows)


def trust_publisher(thumbprint: str, subject: str) -> None:
    normalized = re.sub(r"[^A-Fa-f0-9]", "", str(thumbprint)).upper()
    if len(normalized) not in {40, 64}:
        raise ValueError("Yayıncı sertifika parmak izi geçersiz")
    cleaned_subject = str(subject or "Bilinmeyen yayıncı").strip()[:500]
    with open_database() as connection:
        connection.execute(
            "INSERT INTO trusted_publishers (thumbprint, subject, created_at) VALUES (?, ?, ?) "
            "ON CONFLICT(thumbprint) DO UPDATE SET subject=excluded.subject",
            (normalized, cleaned_subject, datetime.now(timezone.utc).isoformat()),
        )
        connection.execute("DELETE FROM analysis_cache")


def add_exclusion(kind: str, raw_value: str, label: str | None = None) -> dict[str, Any]:
    value, normalized = normalize_exclusion(kind, raw_value)
    safe_label = label.strip()[:160] if isinstance(label, str) and label.strip() else None
    now = datetime.now(timezone.utc).isoformat()
    try:
        with open_database() as connection:
            connection.execute(
                """
                INSERT INTO exclusions (kind, value, normalized_value, label, enabled, created_at)
                VALUES (?, ?, ?, ?, 1, ?)
                """,
                (kind, value, normalized, safe_label, now),
            )
            connection.execute(
                """
                INSERT INTO exclusion_events (
                  occurred_at, action, exclusion_kind, exclusion_value
                ) VALUES (?, 'added', ?, ?)
                """,
                (now, kind, value),
            )
    except sqlite3.IntegrityError:
        raise ValueError("Bu istisna zaten kayıtlı") from None
    return exclusions_payload()


def remove_exclusion(item_id: int) -> dict[str, Any]:
    with open_database() as connection:
        row = connection.execute(
            "SELECT kind, value FROM exclusions WHERE id = ? AND enabled = 1",
            (item_id,),
        ).fetchone()
        if row is None:
            raise ValueError("İstisna kaydı bulunamadı")
        now = datetime.now(timezone.utc).isoformat()
        connection.execute("DELETE FROM exclusions WHERE id = ?", (item_id,))
        connection.execute(
            """
            INSERT INTO exclusion_events (
              occurred_at, action, exclusion_kind, exclusion_value
            ) VALUES (?, 'removed', ?, ?)
            """,
            (now, str(row[0]), str(row[1])),
        )
    return exclusions_payload()


def rules_directories() -> tuple[Path, ...]:
    candidates = [data_directory() / "rules"]
    bundled = bundled_data_directory()
    if bundled is not None:
        candidates.append(bundled / "rules")
    unique: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        key = os.path.normcase(str(candidate.resolve(strict=False)))
        if key not in seen:
            seen.add(key)
            unique.append(candidate)
    return tuple(unique)


def yara_sources(proton_override: list[dict[str, str]] | None = None) -> dict[str, str]:
    sources: dict[str, str] = {}
    rule_index = 0
    for directory in rules_directories():
        for rule_path in sorted(directory.glob("*.yar")):
            try:
                if rule_path.stat().st_size > MAX_PROTON_RULE_BYTES:
                    continue
                sources[f"builtin_{rule_index}_{rule_path.stem}"] = rule_path.read_text(encoding="utf-8")
                rule_index += 1
            except (OSError, UnicodeError):
                continue

    if proton_override is None:
        try:
            with open_database() as connection:
                rows = connection.execute(
                    "SELECT name, source_text FROM proton_yara_rules ORDER BY name"
                ).fetchall()
            proton_rules = [{"name": str(name), "content": str(content)} for name, content in rows]
        except (OSError, sqlite3.Error):
            proton_rules = []
    else:
        proton_rules = proton_override

    for index, rule in enumerate(proton_rules):
        sources[f"proton_{index}_{Path(rule['name']).stem}"] = rule["content"]
    return sources


def yara_rule_fingerprint(sources: dict[str, str]) -> str:
    digest = hashlib.sha256()
    for namespace, source in sorted(sources.items()):
        digest.update(namespace.encode("utf-8"))
        digest.update(b"\0")
        digest.update(source.encode("utf-8"))
        digest.update(b"\0")
    return digest.hexdigest() if sources else "none"


def load_yara_rules(proton_override: list[dict[str, str]] | None = None) -> tuple[Any | None, dict[str, Any]]:
    sources = yara_sources(proton_override)
    fingerprint = yara_rule_fingerprint(sources)
    if yara is None:
        return None, {
            "available": False,
            "version": None,
            "rule_files": len(sources),
            "fingerprint": f"unavailable:{fingerprint}",
            "message": "yara-python kurulu değil.",
        }

    if not sources:
        return None, {
            "available": True,
            "version": yara.__version__,
            "rule_files": 0,
            "fingerprint": fingerprint,
            "message": "YARA kural dosyası bulunamadı.",
        }

    try:
        compiled = yara.compile(sources=sources)
    except yara.Error as error:
        return None, {
            "available": True,
            "version": yara.__version__,
            "rule_files": len(sources),
            "fingerprint": f"invalid:{fingerprint}",
            "message": f"YARA kuralları derlenemedi: {error}",
        }
    return compiled, {
        "available": True,
        "version": yara.__version__,
        "rule_files": len(sources),
        "fingerprint": fingerprint,
        "message": "YARA kuralları hazır.",
    }


def analysis_cache_path_key(path: Path) -> str:
    try:
        resolved = path.resolve(strict=False)
    except (OSError, RuntimeError):
        resolved = path.absolute()
    return os.path.normcase(str(resolved))


def open_analysis_cache_session(yara_fingerprint: str) -> AnalysisCacheSession:
    try:
        proton_version = str(signature_status_payload().get("version") or BUILTIN_SIGNATURE_VERSION)
    except (OSError, sqlite3.Error):
        proton_version = BUILTIN_SIGNATURE_VERSION
    engine_revision = (
        f"{ANALYSIS_CACHE_REVISION}:"
        f"ml-{model_cache_token(data_directory() / 'ml')}:"
        f"ember-{model_cache_token(data_directory() / 'ml' / 'ember2024')}"
    )
    session = AnalysisCacheSession(
        engine_revision=engine_revision,
        proton_version=proton_version,
        yara_fingerprint=yara_fingerprint,
    )
    cutoff = (datetime.now(timezone.utc) - timedelta(days=ANALYSIS_CACHE_RETENTION_DAYS)).isoformat()
    try:
        with open_database() as connection:
            connection.execute(
                """
                DELETE FROM analysis_cache
                WHERE engine_revision != ? OR proton_version != ? OR yara_fingerprint != ?
                   OR last_used_at < ?
                """,
                (engine_revision, proton_version, yara_fingerprint, cutoff),
            )
            rows = connection.execute(
                """
                SELECT path_key, file_size, modified_ns, changed_ns, findings_json, analyzed_at
                FROM analysis_cache
                WHERE engine_revision = ? AND proton_version = ? AND yara_fingerprint = ?
                ORDER BY last_used_at DESC
                LIMIT ?
                """,
                (engine_revision, proton_version, yara_fingerprint, MAX_ANALYSIS_CACHE_ENTRIES),
            ).fetchall()
        for row in rows:
            session.entries[str(row[0])] = AnalysisCacheEntry(
                file_size=int(row[1]), modified_ns=int(row[2]), changed_ns=int(row[3]),
                findings_json=str(row[4]), analyzed_at=str(row[5]),
            )
    except (OSError, sqlite3.Error, ValueError):
        session.entries.clear()
    return session


def deserialize_cached_findings(raw: str) -> list[Finding] | None:
    try:
        items = json.loads(raw)
        if not isinstance(items, list) or len(items) > 100:
            return None
        findings: list[Finding] = []
        for item in items:
            if not isinstance(item, dict):
                return None
            findings.append(Finding(
                path=str(item["path"]), kind=str(item["kind"]), severity=str(item["severity"]),
                reason=str(item["reason"]), sha256=item.get("sha256"), risk_score=item.get("risk_score"),
                container_path=item.get("container_path"), publisher_subject=item.get("publisher_subject"),
                publisher_thumbprint=item.get("publisher_thumbprint"),
                ml_shadow_score=item.get("ml_shadow_score"), ml_model_version=item.get("ml_model_version"),
                ml_shadow_details=item.get("ml_shadow_details"),
            ))
        return findings
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return None


def inspect_file_cached(
    path: Path,
    signatures: dict[int, dict[str, dict[str, Any]]],
    yara_rules: Any | None,
    exclusions: ExclusionSet,
    session: AnalysisCacheSession,
    cloud_lookup: bool = False,
    malwarebazaar_api_key: str = "",
    virustotal_api_key: str = "",
) -> list[Finding]:
    if is_path_excluded(path, exclusions):
        return []
    try:
        stat = path.stat()
    except (OSError, PermissionError):
        return []
    path_key = analysis_cache_path_key(path)
    entry = session.entries.get(path_key)
    if entry and (
        entry.file_size == stat.st_size
        and entry.modified_ns == stat.st_mtime_ns
        and entry.changed_ns == stat.st_ctime_ns
    ):
        cached = deserialize_cached_findings(entry.findings_json)
        if cached is not None:
            session.hits += 1
            session.pending[path_key] = entry
            if exclusions.hashes:
                cached = [finding for finding in cached if finding.sha256 not in exclusions.hashes]
            return cached

    session.misses += 1
    findings = inspect_file(
        path, signatures, yara_rules, exclusions, cloud_lookup, malwarebazaar_api_key, virustotal_api_key,
    )
    try:
        final_stat = path.stat()
    except (OSError, PermissionError):
        return findings
    if (
        final_stat.st_size != stat.st_size
        or final_stat.st_mtime_ns != stat.st_mtime_ns
        or final_stat.st_ctime_ns != stat.st_ctime_ns
    ):
        # Tarama sırasında değişen bir dosyanın kısmi sonucu güvenilir bir cache girdisi değildir.
        return findings
    analyzed_at = datetime.now(timezone.utc).isoformat()
    new_entry = AnalysisCacheEntry(
        file_size=int(final_stat.st_size), modified_ns=int(final_stat.st_mtime_ns),
        changed_ns=int(final_stat.st_ctime_ns),
        findings_json=json.dumps([asdict(finding) for finding in findings], ensure_ascii=False),
        analyzed_at=analyzed_at,
    )
    session.entries[path_key] = new_entry
    session.pending[path_key] = new_entry
    session.stores += 1
    return findings


def flush_analysis_cache(session: AnalysisCacheSession) -> None:
    if not session.pending and not (session.hits or session.misses or session.stores):
        return
    now = datetime.now(timezone.utc).isoformat()
    try:
        with open_database() as connection:
            connection.executemany(
                """
                INSERT INTO analysis_cache (
                  path_key, file_path, file_size, modified_ns, changed_ns, engine_revision,
                  proton_version, yara_fingerprint, findings_json, analyzed_at, last_used_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(path_key) DO UPDATE SET
                  file_path=excluded.file_path, file_size=excluded.file_size,
                  modified_ns=excluded.modified_ns, changed_ns=excluded.changed_ns,
                  engine_revision=excluded.engine_revision, proton_version=excluded.proton_version,
                  yara_fingerprint=excluded.yara_fingerprint, findings_json=excluded.findings_json,
                  analyzed_at=excluded.analyzed_at, last_used_at=excluded.last_used_at
                """,
                [
                    (key, key, entry.file_size, entry.modified_ns, entry.changed_ns,
                     session.engine_revision, session.proton_version, session.yara_fingerprint,
                     entry.findings_json, entry.analyzed_at, now)
                    for key, entry in session.pending.items()
                ],
            )
            connection.execute(
                """
                UPDATE analysis_cache_metrics
                SET hits = hits + ?, misses = misses + ?, stores = stores + ?, updated_at = ?
                WHERE id = 1
                """,
                (session.hits, session.misses, session.stores, now),
            )
            connection.execute(
                """
                DELETE FROM analysis_cache WHERE path_key IN (
                  SELECT path_key FROM analysis_cache ORDER BY last_used_at DESC LIMIT -1 OFFSET ?
                )
                """,
                (MAX_ANALYSIS_CACHE_ENTRIES,),
            )
    except (OSError, sqlite3.Error):
        return
    session.pending.clear()
    session.hits = session.misses = session.stores = 0


def analysis_cache_status_payload() -> dict[str, Any]:
    proton_version = str(signature_status_payload().get("version") or BUILTIN_SIGNATURE_VERSION)
    engine_revision = (
        f"{ANALYSIS_CACHE_REVISION}:"
        f"ml-{model_cache_token(data_directory() / 'ml')}:"
        f"ember-{model_cache_token(data_directory() / 'ml' / 'ember2024')}"
    )
    yara_fingerprint = yara_rule_fingerprint(yara_sources())
    if yara is None:
        yara_fingerprint = f"unavailable:{yara_fingerprint}"
    with open_database() as connection:
        entries, result_bytes = connection.execute(
            """
            SELECT COUNT(*), COALESCE(SUM(LENGTH(findings_json)), 0)
            FROM analysis_cache
            WHERE engine_revision = ? AND proton_version = ? AND yara_fingerprint = ?
            """,
            (engine_revision, proton_version, yara_fingerprint),
        ).fetchone()
        hits, misses, stores, updated_at = connection.execute(
            "SELECT hits, misses, stores, updated_at FROM analysis_cache_metrics WHERE id = 1"
        ).fetchone()
    attempts = int(hits) + int(misses)
    return {
        "entries": int(entries), "result_bytes": int(result_bytes), "hits": int(hits),
        "misses": int(misses), "stores": int(stores),
        "hit_rate": round((int(hits) / attempts) * 100, 1) if attempts else 0.0,
        "engine_revision": engine_revision, "updated_at": updated_at,
    }


def analysis_cache_status() -> int:
    try:
        emit("cache-status", **analysis_cache_status_payload())
        return 0
    except (OSError, sqlite3.Error, TypeError):
        emit("error", code="CACHE_STATUS_UNAVAILABLE", message="Tarama önbelleği okunamadı.")
        return 2


def clear_analysis_cache() -> int:
    try:
        now = datetime.now(timezone.utc).isoformat()
        with open_database() as connection:
            connection.execute("DELETE FROM analysis_cache")
            connection.execute(
                "UPDATE analysis_cache_metrics SET hits=0, misses=0, stores=0, updated_at=? WHERE id=1",
                (now,),
            )
        emit("cache-cleared", **analysis_cache_status_payload())
        return 0
    except (OSError, sqlite3.Error, TypeError):
        emit("error", code="CACHE_CLEAR_FAILED", message="Tarama önbelleği temizlenemedi.")
        return 2


def record_ml_shadow_observation(sha256: str | None, analysis: PEAnalysis | None) -> None:
    """Keep bounded, path-free local evidence for offline model evaluation."""
    if (
        not sha256 or analysis is None or analysis.ml_shadow_score is None
        or not analysis.ml_model_version or analysis.ml_features is None
    ):
        return
    now = datetime.now(timezone.utc).isoformat()
    with open_database() as connection:
        connection.execute(
            """
            INSERT INTO ml_shadow_observations (
              sha256, model_version, feature_schema_version, ml_score,
              heuristic_score, signature_status, features_json, model_scores_json,
              disagreement, independent_families, independent_categories,
              first_seen_at, last_seen_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(sha256) DO UPDATE SET
              model_version=excluded.model_version,
              feature_schema_version=excluded.feature_schema_version,
              ml_score=excluded.ml_score,
              heuristic_score=excluded.heuristic_score,
              signature_status=excluded.signature_status,
              features_json=excluded.features_json,
              model_scores_json=excluded.model_scores_json,
              disagreement=excluded.disagreement,
              independent_families=excluded.independent_families,
              independent_categories=excluded.independent_categories,
              last_seen_at=excluded.last_seen_at
            """,
            (
                sha256, analysis.ml_model_version, FEATURE_SCHEMA_VERSION,
                analysis.ml_shadow_score, analysis.risk_score, analysis.signature_status,
                json.dumps(analysis.ml_features, ensure_ascii=True, separators=(",", ":")),
                json.dumps(analysis.ml_shadow_details, ensure_ascii=True, separators=(",", ":")),
                int((analysis.ml_shadow_details or {}).get("disagreement") or 0),
                int((analysis.ml_shadow_details or {}).get("independent_families") or 0),
                int((analysis.ml_shadow_details or {}).get("independent_categories") or 0),
                now, now,
            ),
        )
        connection.execute(
            """DELETE FROM ml_shadow_observations WHERE sha256 IN (
                 SELECT sha256 FROM ml_shadow_observations
                 ORDER BY last_seen_at DESC LIMIT -1 OFFSET 10000
               )"""
        )


# Candidate cut-offs for turning shadow mode into real decisions. Nothing in
# the product uses these yet -- they exist so the report can answer "if we had
# acted at this score, what would we have done to this machine's files?"
ML_CANDIDATE_THRESHOLDS = (50, 70, 80, 90, 95)


def ml_shadow_report(limit: int = 25) -> int:
    """Reads back what shadow mode has been quietly recording.

    Shadow mode exists to produce evidence before the models are allowed to
    act, but nothing could read that evidence until now, so the models were
    scoring into a table nobody looked at.

    The observations are path-free by design (privacy), so this cannot show
    which file was scored. What it can show is the honest false-positive
    proxy: a file carrying a valid Windows Authenticode signature that the
    models score highly is almost certainly something legitimate that would
    have been quarantined. That ratio is the number that decides whether a
    threshold is safe to enable.
    """
    with open_database() as connection:
        total = int(connection.execute(
            "SELECT COUNT(*) FROM ml_shadow_observations").fetchone()[0] or 0)
        if not total:
            emit(
                "ml-shadow-report", total=0, thresholds=[], histogram=[], samples=[],
                model_versions=[], first_seen_at=None, last_seen_at=None,
                message="Henüz gölge gözlem kaydedilmedi. Modeller yalnız PE dosyaları "
                        "tarandığında puan üretir; bir tarama çalıştırıp tekrar bak.",
            )
            return 0

        first_seen, last_seen = connection.execute(
            "SELECT MIN(first_seen_at), MAX(last_seen_at) FROM ml_shadow_observations").fetchone()
        model_versions = [
            {"version": str(row[0]), "count": int(row[1])}
            for row in connection.execute(
                """SELECT model_version, COUNT(*) FROM ml_shadow_observations
                   GROUP BY model_version ORDER BY COUNT(*) DESC""")
        ]

        trusted_total = int(connection.execute(
            "SELECT COUNT(*) FROM ml_shadow_observations WHERE signature_status = 'trusted'"
        ).fetchone()[0] or 0)

        thresholds = []
        for threshold in ML_CANDIDATE_THRESHOLDS:
            flagged, trusted_flagged = connection.execute(
                """SELECT COUNT(*),
                          SUM(CASE WHEN signature_status = 'trusted' THEN 1 ELSE 0 END)
                   FROM ml_shadow_observations WHERE ml_score >= ?""",
                (threshold,),
            ).fetchone()
            flagged = int(flagged or 0)
            trusted_flagged = int(trusted_flagged or 0)
            thresholds.append({
                "threshold": threshold,
                "flagged": flagged,
                "flagged_ratio": round(flagged / total * 100, 2),
                # Signed-and-flagged: the closest thing to a measured false
                # positive that path-free observations can give.
                "trusted_flagged": trusted_flagged,
                "trusted_flagged_ratio": round(trusted_flagged / flagged * 100, 2) if flagged else 0.0,
            })

        histogram = [
            {"bucket": int(row[0]) * 10, "count": int(row[1])}
            for row in connection.execute(
                """SELECT MIN(ml_score / 10, 9) AS bucket, COUNT(*)
                   FROM ml_shadow_observations GROUP BY bucket ORDER BY bucket""")
        ]

        # The highest scorers are what a reviewer actually needs to eyeball.
        samples = [
            {
                "sha256": str(row[0]),
                "ml_score": int(row[1]),
                "heuristic_score": int(row[2]),
                "signature_status": str(row[3]),
                "disagreement": int(row[4] or 0),
                "last_seen_at": str(row[5]),
            }
            for row in connection.execute(
                """SELECT sha256, ml_score, heuristic_score, signature_status,
                          disagreement, last_seen_at
                   FROM ml_shadow_observations
                   ORDER BY ml_score DESC, last_seen_at DESC LIMIT ?""",
                (max(1, min(int(limit), 200)),),
            )
        ]

    emit(
        "ml-shadow-report",
        total=total,
        trusted_total=trusted_total,
        first_seen_at=first_seen,
        last_seen_at=last_seen,
        model_versions=model_versions,
        thresholds=thresholds,
        histogram=histogram,
        samples=samples,
    )
    return 0


def save_scan_history(
    *,
    completed_at: str,
    mode: str,
    targets: list[Path],
    scanned: int,
    confirmed_count: int,
    review_count: int,
    elapsed_ms: int,
    limited: bool,
    findings: list[Finding],
) -> int:
    """Tarama özetini ve en fazla 25 bulguyu tek bir yerel işlemde kaydeder."""
    with open_database() as connection:
        cursor = connection.execute(
            """
            INSERT INTO scan_runs (
              completed_at, mode, target_labels, scanned_files, confirmed_count,
              review_count, elapsed_ms, limited
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                completed_at,
                mode,
                json.dumps([target.name for target in targets], ensure_ascii=False),
                scanned,
                confirmed_count,
                review_count,
                elapsed_ms,
                int(limited),
            ),
        )
        scan_run_id = int(cursor.lastrowid)
        connection.executemany(
            """
            INSERT INTO scan_findings (
              scan_run_id, file_path, kind, severity, reason, sha256
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    scan_run_id,
                    finding.path,
                    finding.kind,
                    finding.severity,
                    finding.reason,
                    finding.sha256,
                )
                for finding in findings[:25]
            ],
        )
    return scan_run_id


def read_scan_history(limit: int) -> list[dict[str, Any]]:
    if not database_path().is_file():
        return []
    with open_database() as connection:
        rows = connection.execute(
            """
            SELECT id, completed_at, mode, target_labels, scanned_files,
                   confirmed_count, review_count, elapsed_ms, limited
            FROM scan_runs
            ORDER BY id DESC
            LIMIT ?
            """,
            (max(1, min(limit, 25)),),
        ).fetchall()
    return [
        {
            "id": row[0],
            "completed_at": row[1],
            "mode": row[2],
            "targets": json.loads(row[3]),
            "scanned": row[4],
            "confirmed_count": row[5],
            "review_count": row[6],
            "elapsed_ms": row[7],
            "limited": bool(row[8]),
        }
        for row in rows
    ]


def current_user_sid() -> str | None:
    """SID string of the account this process runs as, or None."""
    if os.name != "nt":
        return None
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    TOKEN_QUERY = 0x0008
    TOKEN_USER_CLASS = 1

    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(token)
    ):
        return None
    try:
        size = wintypes.DWORD(0)
        advapi32.GetTokenInformation(token, TOKEN_USER_CLASS, None, 0, ctypes.byref(size))
        if not size.value:
            return None
        buffer = ctypes.create_string_buffer(size.value)
        if not advapi32.GetTokenInformation(
            token, TOKEN_USER_CLASS, buffer, size, ctypes.byref(size)
        ):
            return None
        # TOKEN_USER starts with SID_AND_ATTRIBUTES, whose first member is the
        # PSID -- read it directly rather than redeclaring the whole struct.
        sid_pointer = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0]
        advapi32.ConvertSidToStringSidW.argtypes = [
            ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR),
        ]
        advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
        text = wintypes.LPWSTR()
        if not advapi32.ConvertSidToStringSidW(sid_pointer, ctypes.byref(text)):
            return None
        try:
            return str(text.value) if text.value else None
        finally:
            kernel32.LocalFree(text)
    finally:
        kernel32.CloseHandle(token)


# Quarantine store access control (plan.md item 6).
#
# The store inherited whatever the parent data directory allowed. On a shared
# machine that can mean other user accounts, and it always means a permissive
# ACL set anywhere above us silently widens access to the malware corpus and
# to the per-item keys' plaintext targets.
#
# The DACL below is protected (inheritance disabled) and lists only SYSTEM,
# the local Administrators group, and the account Neutron runs as.
#
# What this does NOT do, stated plainly because the same limit is documented
# for self-protection: Windows ACLs are per-account, so this is no defence
# against malware already running as the same user -- that process has the
# owner's rights by definition. It keeps *other* users and other unprivileged
# processes out, and stops an over-broad inherited ACL from applying. That is
# the honest scope.
#
# Service-mode note: as LocalSystem the store lives under %ProgramData% and
# the account SID resolves to SYSTEM, so the resulting DACL is SYSTEM plus
# Administrators. That is intended there -- the service owns that store and
# the desktop app keeps its own under %APPDATA% -- but it does mean a
# non-admin user cannot reach the machine-wide store directly.
QUARANTINE_DACL_TEMPLATE = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"


def harden_quarantine_directory(directory: Path) -> None:
    """Apply a protected DACL to the store. Best effort by design: a failure
    here must never stop a detection from being quarantined, since an
    inherited-ACL store is still far better than leaving malware in place."""
    if os.name != "nt":
        return
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    SE_FILE_OBJECT = 1
    DACL_SECURITY_INFORMATION = 0x00000004
    PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000

    # Hard requirement, not a nicety: the DACL is protected, so it replaces
    # inherited access outright. Applying one that does not name the account
    # this process runs as would lock Neutron out of its own quarantine store
    # -- no restore, no listing, no cleanup. If the SID cannot be resolved the
    # correct move is to leave the inherited ACL alone.
    sid = current_user_sid()
    if not sid:
        return
    sddl = f"{QUARANTINE_DACL_TEMPLATE}(A;OICI;FA;;;{sid})"

    convert = advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.restype = wintypes.BOOL
    convert.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.DWORD),
    ]
    descriptor = ctypes.c_void_p()
    descriptor_size = wintypes.DWORD(0)
    if not convert(sddl, 1, ctypes.byref(descriptor), ctypes.byref(descriptor_size)):
        return
    try:
        dacl_present = wintypes.BOOL()
        dacl_defaulted = wintypes.BOOL()
        dacl = ctypes.c_void_p()
        advapi32.GetSecurityDescriptorDacl.argtypes = [
            ctypes.c_void_p, ctypes.POINTER(wintypes.BOOL),
            ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.BOOL),
        ]
        advapi32.GetSecurityDescriptorDacl.restype = wintypes.BOOL
        if not advapi32.GetSecurityDescriptorDacl(
            descriptor, ctypes.byref(dacl_present), ctypes.byref(dacl),
            ctypes.byref(dacl_defaulted),
        ) or not dacl_present.value:
            return
        advapi32.SetNamedSecurityInfoW.argtypes = [
            wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD,
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
        ]
        advapi32.SetNamedSecurityInfoW.restype = wintypes.DWORD
        advapi32.SetNamedSecurityInfoW(
            str(directory), SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None, None, dacl, None,
        )
    finally:
        kernel32.LocalFree(descriptor)


_quarantine_directory_hardened = False


def quarantine_directory() -> Path:
    global _quarantine_directory_hardened
    directory = data_directory() / "quarantine"
    existed = directory.is_dir()
    directory.mkdir(parents=True, exist_ok=True)
    # Applied once per process, and always on first creation. Re-running it on
    # every call would mean a SetNamedSecurityInfoW round trip per quarantined
    # file for no benefit -- the DACL is protected, so nothing re-widens it.
    if not _quarantine_directory_hardened or not existed:
        harden_quarantine_directory(directory)
        _quarantine_directory_hardened = True
    return directory.resolve()


def path_is_inside(candidate: Path, parent: Path) -> bool:
    try:
        candidate.resolve().relative_to(parent.resolve())
        return True
    except (OSError, ValueError):
        return False


# Quarantine store hardening (plan.md item 6).
#
# Until now a quarantined executable sat in the store byte-for-byte intact and
# still runnable: one double-click, one script walking the folder, one backup
# job restoring it, and the malware Neutron "removed" is live again. Another
# scanner walking the profile would also flag the store and, in the worst
# case, act on it -- deleting the only copy of a file the user may want back.
#
# Files are therefore transformed on the way in and back on the way out.
#
# Be precise about what this is: the key is stored in the same database as the
# record, so this is NOT confidentiality against someone who already has the
# machine. It is neutralisation -- the stored blob is not a runnable PE, does
# not match malware signatures, and cannot be executed by accident. That is
# what the store actually needs, and claiming more would be dishonest.
QUARANTINE_PAYLOAD_VERSION = 1
QUARANTINE_PAYLOAD_CHUNK = 1024 * 1024


def quarantine_stream_transform(reader: Any, destination: Path, key: bytes) -> tuple[str, str]:
    """Streams an already-open reader -> destination through the keystream,
    returning the (plain, transformed) SHA-256 digests. Streamed rather than
    read whole so a large quarantined file cannot exhaust memory.

    Takes an open reader rather than a path so the caller can guarantee the
    bytes hashed here came from the exact file that was inspected -- see
    opened_for_quarantine()."""
    plain = hashlib.sha256()
    stored = hashlib.sha256()
    key_length = len(key)
    offset = 0
    with destination.open("wb") as writer:
        while True:
            chunk = reader.read(QUARANTINE_PAYLOAD_CHUNK)
            if not chunk:
                break
            plain.update(chunk)
            transformed = bytes(
                byte ^ key[(offset + index) % key_length]
                for index, byte in enumerate(chunk)
            )
            offset += len(chunk)
            stored.update(transformed)
            writer.write(transformed)
    return plain.hexdigest(), stored.hexdigest()


# --- TOCTOU-safe access to the detected file (plan.md item 6) --------------
#
# Quarantine used to resolve the path, sanity-check it, then separately reopen
# it to copy and separately unlink it by path. Three path resolutions, and
# malware only has to win the gap between any two of them: replace the file (or
# swap the directory for a junction) after the checks and Neutron faithfully
# copies one file and deletes a different one -- with SYSTEM rights, in service
# mode, on a path the attacker chose. Retry-on-lock made the window wider, not
# narrower, because it reopened by path each attempt.
#
# The fix is to stop naming the file more than once. Open it exactly once,
# deny other writers for as long as we hold it, and drive every later step --
# reading, and the deletion itself -- off that one handle.
#
# On Windows this is exact:
#   * dwShareMode = FILE_SHARE_READ alone means no other process may write,
#     rename or delete the file while the handle is open. The file cannot
#     change under us at all, so there is no window left to race.
#   * FILE_FLAG_OPEN_REPARSE_POINT means a symlink or junction is opened as
#     itself and never followed, so a redirected path is rejected instead of
#     silently obeyed.
#   * Deletion goes through SetFileInformationByHandle(FileDispositionInfo),
#     which deletes the object the handle refers to. No path is re-resolved,
#     so there is nothing left to substitute.
#
# On POSIX (development only -- this engine is Windows-targeted) the same
# shape is approximated with O_NOFOLLOW plus an fstat identity check before
# unlinking. That is weaker, and is documented as such rather than presented
# as equivalent.
@contextmanager
def opened_for_quarantine(path: Path) -> Iterator[tuple[Any, Any]]:
    """Yield (reader, delete_original) for a file opened exactly once.

    `delete_original()` removes the very object the reader read, not whatever
    the path happens to name later. Raises OSError if the file cannot be
    opened exclusively, is a directory, or is a reparse point.
    """
    if os.name != "nt":
        descriptor = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            identity = os.fstat(descriptor)
            if not stat_module.S_ISREG(identity.st_mode):
                raise OSError(f"Karantina kaynağı normal dosya değil: {path}")

            def delete_original() -> None:
                current = os.lstat(str(path))
                if (current.st_dev, current.st_ino) != (identity.st_dev, identity.st_ino):
                    raise OSError(f"Karantina kaynağı işlem sırasında değişti: {path}")
                os.unlink(str(path))

            with open(descriptor, "rb", closefd=False) as reader:
                yield reader, delete_original
        finally:
            os.close(descriptor)
        return

    import msvcrt
    from ctypes import wintypes

    GENERIC_READ = 0x80000000
    DELETE = 0x00010000
    FILE_SHARE_READ = 0x00000001
    OPEN_EXISTING = 3
    FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
    FILE_ATTRIBUTE_DIRECTORY = 0x00000010
    FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
    FILE_DISPOSITION_INFO_CLASS = 4

    class BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("dwFileAttributes", wintypes.DWORD),
            ("ftCreationTime", wintypes.FILETIME),
            ("ftLastAccessTime", wintypes.FILETIME),
            ("ftLastWriteTime", wintypes.FILETIME),
            ("dwVolumeSerialNumber", wintypes.DWORD),
            ("nFileSizeHigh", wintypes.DWORD),
            ("nFileSizeLow", wintypes.DWORD),
            ("nNumberOfLinks", wintypes.DWORD),
            ("nFileIndexHigh", wintypes.DWORD),
            ("nFileIndexLow", wintypes.DWORD),
        ]

    class FILE_DISPOSITION_INFO(ctypes.Structure):
        _fields_ = [("DeleteFile", wintypes.BOOL)]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    ]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.GetFileInformationByHandle.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(BY_HANDLE_FILE_INFORMATION),
    ]
    kernel32.GetFileInformationByHandle.restype = wintypes.BOOL
    kernel32.SetFileInformationByHandle.argtypes = [
        wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
    ]
    kernel32.SetFileInformationByHandle.restype = wintypes.BOOL

    handle = kernel32.CreateFileW(
        str(path), GENERIC_READ | DELETE, FILE_SHARE_READ, None,
        OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, None,
    )
    if not handle or handle == INVALID_HANDLE_VALUE:
        # Carries .winerror, so the caller's sharing-violation hint still works.
        raise ctypes.WinError(ctypes.get_last_error())

    descriptor = None
    try:
        information = BY_HANDLE_FILE_INFORMATION()
        if not kernel32.GetFileInformationByHandle(handle, ctypes.byref(information)):
            raise ctypes.WinError(ctypes.get_last_error())
        if information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY:
            raise OSError(f"Karantina kaynağı bir klasör: {path}")
        if information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT:
            raise OSError(f"Karantina kaynağı bir bağlantı noktası: {path}")

        # Confirm the handle actually landed on the path that was validated.
        # Opening by name re-walks every directory component, and
        # FILE_FLAG_OPEN_REPARSE_POINT only protects the last one -- an
        # intermediate directory swapped for a junction would otherwise
        # redirect this open somewhere else entirely. Asking the handle where
        # it ended up is the only answer that cannot be raced, and it is the
        # same API Path.resolve() used to produce the expected value, so the
        # two are directly comparable.
        kernel32.GetFinalPathNameByHandleW.argtypes = [
            wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD,
        ]
        kernel32.GetFinalPathNameByHandleW.restype = wintypes.DWORD
        name_buffer = ctypes.create_unicode_buffer(32768)
        name_length = kernel32.GetFinalPathNameByHandleW(
            handle, name_buffer, len(name_buffer) - 1, 0,
        )
        if not name_length or name_length >= len(name_buffer) - 1:
            raise ctypes.WinError(ctypes.get_last_error())
        opened_path = name_buffer.value
        if opened_path.startswith("\\\\?\\UNC\\"):
            opened_path = "\\\\" + opened_path[len("\\\\?\\UNC\\"):]
        elif opened_path.startswith("\\\\?\\"):
            opened_path = opened_path[len("\\\\?\\"):]
        if os.path.normcase(opened_path) != os.path.normcase(str(path)):
            raise OSError(
                f"Karantina kaynağı beklenenden farklı bir dosyaya çözüldü: {path} -> {opened_path}"
            )

        def delete_original() -> None:
            disposition = FILE_DISPOSITION_INFO(True)
            if not kernel32.SetFileInformationByHandle(
                handle, FILE_DISPOSITION_INFO_CLASS,
                ctypes.byref(disposition), ctypes.sizeof(disposition),
            ):
                raise ctypes.WinError(ctypes.get_last_error())

        # open_osfhandle transfers ownership of the handle to the CRT
        # descriptor, so from here the handle must be released via os.close()
        # and never CloseHandle(). closefd=False keeps the descriptor (and
        # therefore the handle) alive after the reader is closed, because
        # delete_original() still needs it.
        descriptor = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
        with open(descriptor, "rb", closefd=False) as reader:
            yield reader, delete_original
    finally:
        if descriptor is not None:
            os.close(descriptor)
        else:
            kernel32.CloseHandle(handle)


def restore_quarantine_payload(
    stored: Path,
    original: Path,
    key: bytes | None,
    payload_version: int | None,
    expected_sha256: str | None,
) -> None:
    """Rebuilds the original file from the store, atomically.

    Writes to a temporary file beside the destination and os.replace()s it
    into place, so a failure halfway through cannot leave a truncated file
    where the user's data used to be. Raises ValueError if the rebuilt bytes
    do not match the digest recorded at quarantine time -- a mismatch means
    the store was tampered with or corrupted, and handing back a file that is
    not what was taken away is worse than refusing.
    """
    original.parent.mkdir(parents=True, exist_ok=True)
    staging = original.parent / f".neutron-restore-{secrets.token_hex(8)}.tmp"
    plain = hashlib.sha256()
    try:
        if payload_version is None or not key:
            # Legacy row: the store holds the file verbatim.
            with stored.open("rb") as reader, staging.open("wb") as writer:
                while True:
                    chunk = reader.read(QUARANTINE_PAYLOAD_CHUNK)
                    if not chunk:
                        break
                    plain.update(chunk)
                    writer.write(chunk)
        else:
            key_length = len(key)
            offset = 0
            with stored.open("rb") as reader, staging.open("wb") as writer:
                while True:
                    chunk = reader.read(QUARANTINE_PAYLOAD_CHUNK)
                    if not chunk:
                        break
                    decoded = bytes(
                        byte ^ key[(offset + index) % key_length]
                        for index, byte in enumerate(chunk)
                    )
                    offset += len(chunk)
                    plain.update(decoded)
                    writer.write(decoded)

        if expected_sha256 and plain.hexdigest() != expected_sha256:
            raise ValueError("karantina dosyasının bütünlüğü doğrulanamadı")

        # O_EXCL so the "does the destination already exist" check and the
        # write are one atomic step; a plain exists() test beforehand is a
        # race another process can win.
        handle = os.open(str(original), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.close(handle)
        os.replace(str(staging), str(original))
    finally:
        try:
            staging.unlink(missing_ok=True)
        except OSError:
            pass


def quarantine_file(raw_path: str, reason: str) -> int:
    """Move a detected file to a recoverable local quarantine, retrying transient locks."""
    try:
        original = Path(raw_path).resolve(strict=True)
    except (OSError, RuntimeError):
        emit("error", code="QUARANTINE_SOURCE_MISSING", message="Dosya artık bulunamıyor.")
        return 2
    # These two are fast pre-filters for a clear error message, NOT the
    # security boundary -- every one of them is a path lookup that can be
    # raced. The authoritative checks run against the open handle inside
    # opened_for_quarantine(), which also proves the handle landed on exactly
    # this resolved path, so the data-directory rule below cannot be dodged by
    # substituting a component afterwards.
    if not original.is_file() or original.is_symlink():
        emit("error", code="QUARANTINE_SOURCE_INVALID", message="Yalnız normal dosyalar karantinaya alınabilir.")
        return 2
    if path_is_inside(original, data_directory()):
        emit("error", code="QUARANTINE_SOURCE_INVALID", message="Neutron veri alanındaki dosyalar karantinaya alınamaz.")
        return 2

    destination_directory = quarantine_directory()
    safe_name = "".join(character if character.isalnum() or character in ".-_" else "_" for character in original.name)
    # The stored blob is not the original file and must not carry its
    # extension: a ".exe" in the store invites exactly the accidental
    # execution the transform exists to prevent.
    destination = destination_directory / f"{int(time.time())}-{secrets.token_hex(6)}-{safe_name}.qbin"
    key = secrets.token_bytes(32)
    last_error: OSError | sqlite3.Error | None = None
    for attempt in range(5):
        stored_written = False
        inserted_id: int | None = None
        try:
            # Ordering is chosen so that no failure can destroy the user's
            # file. The store copy is completed first, the database row is
            # written second, and only then is the original removed -- through
            # the same handle it was read from. The worst outcome of a failure
            # at any step is a redundant copy that gets cleaned up below,
            # never a file that exists in neither place.
            with opened_for_quarantine(original) as (reader, delete_original):
                digest, stored_digest = quarantine_stream_transform(reader, destination, key)
                stored_written = True
                with open_database() as connection:
                    cursor = connection.execute(
                    """
                    INSERT INTO quarantine_items (
                      original_path, stored_path, file_name, sha256, reason, quarantined_at,
                      payload_version, payload_key, stored_sha256
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (str(original), str(destination), original.name, digest, reason[:500],
                     datetime.now(timezone.utc).isoformat(),
                     QUARANTINE_PAYLOAD_VERSION, key.hex(), stored_digest),
                    )
                    inserted_id = int(cursor.lastrowid)
                delete_original()
            emit("quarantined", item_id=inserted_id, file_name=original.name)
            return 0
        except (OSError, sqlite3.Error) as error:
            last_error = error
            # The original is still on disk in every failure path, so the only
            # cleanup needed is undoing whatever partial bookkeeping was done.
            if inserted_id is not None:
                try:
                    with open_database() as connection:
                        connection.execute("DELETE FROM quarantine_items WHERE id = ?", (inserted_id,))
                except (OSError, sqlite3.Error):
                    pass
            if stored_written:
                try:
                    destination.unlink(missing_ok=True)
                except OSError:
                    pass
            if attempt < 4:
                time.sleep(0.4 * (attempt + 1))
    locked_hint = " Dosya başka bir uygulamada açıksa kapatıp yeniden deneyin." if getattr(last_error, "winerror", None) in {5, 32} else ""
    emit("error", code="QUARANTINE_FAILED", message=f"Karantina işlemi tamamlanamadı: {last_error}.{locked_hint}")
    return 2


def read_quarantine() -> int:
    try:
        with open_database() as connection:
            rows = connection.execute(
                """SELECT id, original_path, file_name, reason, quarantined_at, sha256
                   FROM quarantine_items WHERE state = 'active' ORDER BY id DESC"""
            ).fetchall()
        emit("quarantine-list", items=[{
            "id": row[0], "original_path": row[1], "file_name": row[2],
            "reason": row[3], "quarantined_at": row[4], "sha256": row[5],
        } for row in rows])
        return 0
    except (OSError, sqlite3.Error):
        emit("error", code="QUARANTINE_UNAVAILABLE", message="Karantina listesi okunamadı.")
        return 2


def update_quarantine_item(item_id: int, action: str) -> int:
    """Geri yükleme veya kalıcı silme, yalnız kullanıcı onayından sonra çağrılır."""
    try:
        with open_database() as connection:
            row = connection.execute(
                """SELECT original_path, stored_path, file_name, sha256,
                          payload_version, payload_key, stored_sha256
                   FROM quarantine_items WHERE id = ? AND state = 'active'""",
                (item_id,),
            ).fetchone()
            if not row:
                emit("error", code="QUARANTINE_ITEM_MISSING", message="Karantina kaydı bulunamadı.")
                return 2
            original, stored, file_name = (Path(row[0]), Path(row[1]), row[2])
            expected_sha256, payload_version, payload_key, stored_sha256 = row[3], row[4], row[5], row[6]
            if not path_is_inside(stored, quarantine_directory()) or not stored.is_file():
                emit("error", code="QUARANTINE_FILE_MISSING", message="Karantina dosyası bulunamadı.")
                return 2
            if action == "restore":
                # Verify the store blob itself before decoding it, so
                # corruption is reported as corruption rather than surfacing
                # as a confusing digest mismatch on the rebuilt file.
                if stored_sha256:
                    actual = sha256_for(stored, stored.stat().st_size)
                    if actual != stored_sha256:
                        emit("error", code="QUARANTINE_STORE_TAMPERED",
                             message="Karantina dosyası değiştirilmiş veya bozulmuş; geri yükleme yapılmadı.")
                        return 2
                try:
                    restore_quarantine_payload(
                        stored, original,
                        bytes.fromhex(payload_key) if payload_key else None,
                        payload_version, expected_sha256,
                    )
                except FileExistsError:
                    emit("error", code="RESTORE_DESTINATION_EXISTS", message="Orijinal konumda aynı adlı bir dosya var; üzerine yazılmadı.")
                    return 2
                except ValueError as error:
                    emit("error", code="QUARANTINE_INTEGRITY_FAILED", message=f"Geri yükleme doğrulanamadı: {error}.")
                    return 2
                stored.unlink(missing_ok=True)
                connection.execute("UPDATE quarantine_items SET state = 'restored', restored_at = ? WHERE id = ?", (datetime.now(timezone.utc).isoformat(), item_id))
                emit("restored", item_id=item_id, file_name=file_name)
                return 0
            stored.unlink()
            connection.execute("UPDATE quarantine_items SET state = 'deleted', deleted_at = ? WHERE id = ?", (datetime.now(timezone.utc).isoformat(), item_id))
            emit("deleted", item_id=item_id, file_name=file_name)
            return 0
    except (OSError, sqlite3.Error) as error:
        emit("error", code="QUARANTINE_ACTION_FAILED", message=f"İşlem tamamlanamadı: {error}")
        return 2


# --- Firewall rule bookkeeping --------------------------------------------
# Neutron never filters packets itself: it manages Windows' own built-in
# firewall (WFP-backed, already supports per-application rules) via
# PowerShell's NetSecurity cmdlets, run elevated from main.cjs
# (runElevatedPowerShell/firewallAddCommand etc). engine.py itself never
# needs admin -- it only keeps a local record of what Neutron created, the
# same elevation split already used for the watchdog task (see plan.md).
# The actual New-NetFirewallRule/Remove-NetFirewallRule/Set-NetFirewallRule
# calls happen in main.cjs; this module only tracks state and hands back
# the deterministic rule name main.cjs needs to target.


def firewall_rule_name(program_path: str, direction: str) -> str:
    """Deterministic per (program, direction) PowerShell -Name, so adding
    the same app+direction again updates in place instead of duplicating,
    and removal/toggle can target the exact rule without ambiguity."""
    digest = hashlib.sha256(program_path.casefold().encode("utf-8", errors="replace")).hexdigest()[:16]
    return f"Neutron-FW-{digest}-{direction}"


def firewall_list_rules() -> int:
    try:
        with open_database() as connection:
            rows = connection.execute(
                """SELECT id, program_path, program_name, action, direction, rule_name, enabled, created_at
                   FROM firewall_rules ORDER BY id DESC"""
            ).fetchall()
        emit("firewall-rules", items=[{
            "id": row[0], "program_path": row[1], "program_name": row[2],
            "action": row[3], "direction": row[4], "rule_name": row[5],
            "enabled": bool(row[6]), "created_at": row[7],
        } for row in rows])
        return 0
    except (OSError, sqlite3.Error):
        emit("error", code="FIREWALL_LIST_UNAVAILABLE", message="Güvenlik duvarı kuralları okunamadı.")
        return 2


def firewall_add_rule(raw_path: str, action: str, direction: str) -> int:
    try:
        program = Path(raw_path).expanduser().resolve(strict=True)
    except (OSError, RuntimeError):
        emit("error", code="FIREWALL_TARGET_MISSING", message="Seçilen uygulama bulunamadı.")
        return 2
    if not program.is_file() or program.suffix.casefold() != ".exe":
        emit("error", code="FIREWALL_TARGET_INVALID", message="Yalnız .exe dosyaları için kural eklenebilir.")
        return 2
    if action not in {"block", "allow"} or direction not in {"out", "in"}:
        emit("error", code="FIREWALL_RULE_INVALID", message="Geçersiz kural yönü veya eylemi.")
        return 2

    rule_name = firewall_rule_name(str(program), direction)
    try:
        with open_database() as connection:
            connection.execute(
                """
                INSERT INTO firewall_rules (program_path, program_name, action, direction, rule_name, enabled, created_at)
                VALUES (?, ?, ?, ?, ?, 1, ?)
                ON CONFLICT(rule_name) DO UPDATE SET
                  action = excluded.action, enabled = 1, created_at = excluded.created_at
                """,
                (str(program), program.name, action, direction, rule_name, datetime.now(timezone.utc).isoformat()),
            )
            row = connection.execute(
                "SELECT id FROM firewall_rules WHERE rule_name = ?", (rule_name,)
            ).fetchone()
        emit(
            "firewall-rule-added", id=int(row[0]), rule_name=rule_name,
            program_path=str(program), program_name=program.name, action=action, direction=direction,
        )
        return 0
    except (OSError, sqlite3.Error) as error:
        emit("error", code="FIREWALL_ADD_FAILED", message=f"Kural kaydedilemedi: {error}")
        return 2


def firewall_remove_rule(rule_id: int) -> int:
    try:
        with open_database() as connection:
            row = connection.execute(
                "SELECT rule_name FROM firewall_rules WHERE id = ?", (rule_id,)
            ).fetchone()
            if not row:
                emit("error", code="FIREWALL_RULE_MISSING", message="Güvenlik duvarı kuralı bulunamadı.")
                return 2
            rule_name = str(row[0])
            connection.execute("DELETE FROM firewall_rules WHERE id = ?", (rule_id,))
        emit("firewall-rule-removed", id=rule_id, rule_name=rule_name)
        return 0
    except (OSError, sqlite3.Error) as error:
        emit("error", code="FIREWALL_REMOVE_FAILED", message=f"Kural silinemedi: {error}")
        return 2


def firewall_toggle_rule(rule_id: int, enabled: bool) -> int:
    try:
        with open_database() as connection:
            row = connection.execute(
                "SELECT rule_name FROM firewall_rules WHERE id = ?", (rule_id,)
            ).fetchone()
            if not row:
                emit("error", code="FIREWALL_RULE_MISSING", message="Güvenlik duvarı kuralı bulunamadı.")
                return 2
            rule_name = str(row[0])
            connection.execute("UPDATE firewall_rules SET enabled = ? WHERE id = ?", (1 if enabled else 0, rule_id))
        emit("firewall-rule-toggled", id=rule_id, rule_name=rule_name, enabled=enabled)
        return 0
    except (OSError, sqlite3.Error) as error:
        emit("error", code="FIREWALL_TOGGLE_FAILED", message=f"Kural güncellenemedi: {error}")
        return 2


def firewall_recent_apps() -> int:
    """Apps currently holding a TCP connection, as a shortcut for 'which
    program do I want to block' -- reuses the same driver-free connection
    enumeration already built for watch_network()."""
    processes = windows_process_snapshot()
    counts: dict[str, int] = {}
    for pid, _remote_ip, _remote_port in active_tcp_connections():
        image_path = processes.get(pid, "")
        if not image_path:
            continue
        counts[image_path] = counts.get(image_path, 0) + 1
    items = [
        {"path": path, "name": Path(path).name, "connection_count": count}
        for path, count in sorted(counts.items(), key=lambda entry: entry[1], reverse=True)
    ]
    emit("firewall-recent-apps", items=items)
    return 0


# --- Startup manager --------------------------------------------------------
# "Disable" never deletes outright: registry values and Startup-folder files
# are backed up into startup_item_backups first (same reversible philosophy
# as quarantine_items), so a mistaken disable is always restorable. HKCU
# registry values and the per-user Startup folder don't need admin; HKLM
# values and the all-users Startup folder do -- same elevation split as the
# firewall feature (engine.py backs up/reads, main.cjs does the actual
# elevated write via runElevatedPowerShell, then calls back to finalize).
HIVE_BY_NAME = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE} if winreg else {}


def startup_disabled_directory() -> Path:
    directory = data_directory() / "startup-disabled"
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def startup_needs_elevation(source: str, hive: str | None, key_path: str) -> bool:
    if source == "registry":
        return hive == "HKLM"
    program_data = os.environ.get("ProgramData")
    return bool(program_data and key_path.casefold().startswith(program_data.casefold()))


def startup_list_items() -> int:
    items = [{
        "id": None, "enabled": True, "source": entry["source"], "hive": entry["hive"],
        "key_path": entry["key_path"], "view": entry["view"], "value_name": entry["value_name"],
        "command": entry["command"],
    } for entry in startup_entries()]
    try:
        with open_database() as connection:
            rows = connection.execute(
                """SELECT id, source, hive, key_path, view, value_name, original_path
                   FROM startup_item_backups WHERE state IN ('disabled', 'pending') ORDER BY id DESC"""
            ).fetchall()
        items.extend({
            "id": row[0], "enabled": False, "source": row[1], "hive": row[2],
            "key_path": row[3], "view": row[4], "value_name": row[5], "command": row[6],
        } for row in rows)
    except sqlite3.Error:
        pass
    emit("startup-items", items=items)
    return 0


def startup_disable_entry(source: str, hive: str | None, key_path: str, view: int, value_name: str, command: str) -> int:
    if source not in {"registry", "startup-folder"} or not key_path or not value_name or not command:
        emit("error", code="STARTUP_INVALID", message="Geçersiz başlangıç öğesi verisi.")
        return 2
    needs_elevation = startup_needs_elevation(source, hive, key_path)
    stored_path = (
        str(startup_disabled_directory() / f"{int(time.time())}-{secrets.token_hex(6)}-{Path(command).name}")
        if source == "startup-folder" else None
    )
    now = datetime.now(timezone.utc).isoformat()
    try:
        with open_database() as connection:
            cursor = connection.execute(
                """INSERT INTO startup_item_backups
                   (source, hive, key_path, view, value_name, original_path, stored_path, state, disabled_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (source, hive, key_path, view, value_name, command, stored_path,
                 "pending" if needs_elevation else "disabled", now),
            )
            row_id = int(cursor.lastrowid)
            if not needs_elevation:
                try:
                    if source == "registry":
                        with winreg.OpenKey(HIVE_BY_NAME[hive], key_path, 0, winreg.KEY_SET_VALUE | view) as key:
                            winreg.DeleteValue(key, value_name)
                    else:
                        shutil.move(command, stored_path)
                except OSError as error:
                    connection.execute("DELETE FROM startup_item_backups WHERE id = ?", (row_id,))
                    emit("error", code="STARTUP_DISABLE_FAILED", message=f"Öğe devre dışı bırakılamadı: {error}")
                    return 2
    except sqlite3.Error as error:
        emit("error", code="STARTUP_DISABLE_FAILED", message=f"İşlem tamamlanamadı: {error}")
        return 2
    emit(
        "startup-item-disabled", id=row_id, needs_elevation=needs_elevation, source=source,
        hive=hive, key_path=key_path, view=view, value_name=value_name,
        original_path=command, stored_path=stored_path,
    )
    return 0


def startup_finalize_disable(row_id: int) -> int:
    try:
        with open_database() as connection:
            connection.execute("UPDATE startup_item_backups SET state = 'disabled' WHERE id = ? AND state = 'pending'", (row_id,))
    except sqlite3.Error as error:
        emit("error", code="STARTUP_FINALIZE_FAILED", message=str(error))
        return 2
    emit("startup-item-finalized", id=row_id)
    return 0


def startup_cancel_disable(row_id: int) -> int:
    try:
        with open_database() as connection:
            connection.execute("DELETE FROM startup_item_backups WHERE id = ? AND state = 'pending'", (row_id,))
    except sqlite3.Error as error:
        emit("error", code="STARTUP_CANCEL_FAILED", message=str(error))
        return 2
    emit("startup-item-cancelled", id=row_id)
    return 0


def startup_restore_entry(row_id: int) -> int:
    try:
        with open_database() as connection:
            row = connection.execute(
                """SELECT source, hive, key_path, view, value_name, original_path, stored_path
                   FROM startup_item_backups WHERE id = ? AND state = 'disabled'""",
                (row_id,),
            ).fetchone()
            if not row:
                emit("error", code="STARTUP_ITEM_MISSING", message="Başlangıç öğesi kaydı bulunamadı.")
                return 2
            source, hive, key_path, view, value_name, original_path, stored_path = row
            needs_elevation = startup_needs_elevation(source, hive, key_path)
            if not needs_elevation:
                try:
                    if source == "registry":
                        with winreg.OpenKey(HIVE_BY_NAME[hive], key_path, 0, winreg.KEY_SET_VALUE | view) as key:
                            winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, original_path)
                    else:
                        if Path(original_path).exists():
                            emit("error", code="STARTUP_RESTORE_CONFLICT", message="Aynı adda bir dosya zaten var; üzerine yazılmadı.")
                            return 2
                        shutil.move(stored_path, original_path)
                except OSError as error:
                    emit("error", code="STARTUP_RESTORE_FAILED", message=f"Geri yükleme tamamlanamadı: {error}")
                    return 2
                connection.execute(
                    "UPDATE startup_item_backups SET state = 'restored', restored_at = ? WHERE id = ?",
                    (datetime.now(timezone.utc).isoformat(), row_id),
                )
                emit("startup-item-restored", id=row_id, needs_elevation=False)
                return 0
    except sqlite3.Error as error:
        emit("error", code="STARTUP_RESTORE_FAILED", message=f"İşlem tamamlanamadı: {error}")
        return 2
    emit(
        "startup-item-restored", id=row_id, needs_elevation=True, source=source, hive=hive,
        key_path=key_path, view=view, value_name=value_name, original_path=original_path, stored_path=stored_path,
    )
    return 0


def startup_finalize_restore(row_id: int) -> int:
    try:
        with open_database() as connection:
            connection.execute(
                "UPDATE startup_item_backups SET state = 'restored', restored_at = ? WHERE id = ? AND state = 'disabled'",
                (datetime.now(timezone.utc).isoformat(), row_id),
            )
    except sqlite3.Error as error:
        emit("error", code="STARTUP_FINALIZE_FAILED", message=str(error))
        return 2
    emit("startup-item-finalized", id=row_id)
    return 0


def terminate_process_tree_for_image(raw_path: str) -> list[dict[str, Any]]:
    """Terminate only trees whose current root image still matches raw_path.

    PID reuse, Neutron's own PID, protected Windows paths and critical low PIDs
    are rejected. This is intentionally narrower than taskkill /T /F.
    """
    if os.name != "nt":
        return []
    try:
        expected = canonical_path(Path(raw_path))
    except (OSError, RuntimeError):
        return []
    images = windows_process_snapshot()
    parents = toolhelp_parent_processes()
    roots = [pid for pid, image in images.items() if pid > 4 and pid != os.getpid() and canonical_path(Path(image)) == expected]
    if not roots:
        return []
    children: dict[int, list[int]] = {}
    for pid, parent in parents.items():
        children.setdefault(parent, []).append(pid)
    ordered: list[int] = []
    seen: set[int] = set()
    def collect(pid: int) -> None:
        if pid in seen:
            return
        seen.add(pid)
        for child in children.get(pid, []):
            collect(child)
        ordered.append(pid)
    for root in roots:
        collect(root)

    from ctypes import wintypes
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel32.TerminateProcess.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    results: list[dict[str, Any]] = []
    protected_roots = protected_system_quarantine_roots()
    for pid in ordered:
        image = images.get(pid, "")
        if pid <= 4 or pid == os.getpid():
            continue
        if image:
            try:
                normalized = canonical_path(Path(image))
                if any(path_is_within(normalized, root) for root in protected_roots):
                    results.append({"pid": pid, "image": image, "terminated": False, "reason": "protected-system-path"})
                    continue
            except (OSError, RuntimeError):
                pass
        handle = kernel32.OpenProcess(0x0001 | 0x1000, False, pid)
        if not handle:
            results.append({"pid": pid, "image": image, "terminated": False, "reason": "open-failed"})
            continue
        try:
            terminated = bool(kernel32.TerminateProcess(handle, 1))
            results.append({"pid": pid, "image": image, "terminated": terminated})
        finally:
            kernel32.CloseHandle(handle)
    return results


def record_response_action(
    incident_id: int, action_type: str, target: str, *, before: Any = None,
    after: Any = None, reversible: bool = False, state: str = "applied",
) -> int:
    with open_database() as connection:
        cursor = connection.execute(
            """
            INSERT INTO response_actions (
              incident_id, action_type, target, before_json, after_json,
              reversible, state, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (incident_id, action_type, target,
             json.dumps(before, ensure_ascii=False) if before is not None else None,
             json.dumps(after, ensure_ascii=False) if after is not None else None,
             1 if reversible else 0, state, datetime.now(timezone.utc).isoformat()),
        )
        return int(cursor.lastrowid)


def remediate_protection_event(event_id: int) -> int:
    """Apply a compensating, logged response to one pending file event."""
    try:
        with open_database() as connection:
            connection.row_factory = sqlite3.Row
            event = connection.execute(
                "SELECT id, file_path, reason, disposition FROM protection_events WHERE id = ?", (event_id,)
            ).fetchone()
            if event is None or event["disposition"] != "pending":
                raise ValueError("Müdahale bekleyen koruma olayı bulunamadı")
            cursor = connection.execute(
                "INSERT INTO response_incidents (protection_event_id, created_at, summary) VALUES (?, ?, ?)",
                (event_id, datetime.now(timezone.utc).isoformat(), f"{event['file_path']} için olay müdahalesi"),
            )
            incident_id = int(cursor.lastrowid)

        file_path = str(event["file_path"])
        terminated = terminate_process_tree_for_image(file_path)
        if terminated:
            record_response_action(incident_id, "terminate-process-tree", file_path, after=terminated, reversible=False)

        quarantine_result = quarantine_file(file_path, str(event["reason"] or "Olay müdahalesi"))
        if quarantine_result != 0:
            raise ValueError("Dosya karantinaya alınamadığı için müdahale durduruldu")
        with open_database() as connection:
            row = connection.execute(
                "SELECT id, stored_path FROM quarantine_items WHERE original_path = ? AND state = 'active' ORDER BY id DESC LIMIT 1",
                (file_path,),
            ).fetchone()
            if row is None:
                raise ValueError("Karantina kaydı oluşturulamadı")
            quarantine_id, stored_path = int(row[0]), str(row[1])
            connection.execute("UPDATE quarantine_items SET incident_id = ? WHERE id = ?", (incident_id, quarantine_id))
        record_response_action(
            incident_id, "quarantine", file_path,
            before={"path": file_path}, after={"item_id": quarantine_id, "stored_path": stored_path}, reversible=True,
        )

        path_key = file_path.casefold()
        for item in startup_entries():
            command = str(item.get("command") or "")
            if path_key not in command.casefold():
                continue
            if startup_needs_elevation(str(item["source"]), item.get("hive"), str(item["key_path"])):
                record_response_action(
                    incident_id, "startup-disable", command, before=item,
                    reversible=True, state="needs-elevation",
                )
                continue
            result = startup_disable_entry(
                str(item["source"]), item.get("hive"), str(item["key_path"]),
                int(item.get("view") or 0), str(item["value_name"]), command,
            )
            if result == 0:
                with open_database() as connection:
                    backup = connection.execute(
                        "SELECT id FROM startup_item_backups WHERE original_path = ? ORDER BY id DESC LIMIT 1", (command,)
                    ).fetchone()
                record_response_action(
                    incident_id, "startup-disable", command, before=item,
                    after={"backup_id": int(backup[0]) if backup else None}, reversible=True,
                )

        resolved_at = datetime.now(timezone.utc).isoformat()
        with open_database() as connection:
            connection.execute(
                "UPDATE protection_events SET disposition='remediated', disposition_at=?, quarantine_item_id=?, incident_id=? WHERE id=?",
                (resolved_at, quarantine_id, incident_id, event_id),
            )
        emit(
            "incident-remediated", incident_id=incident_id, event_id=event_id,
            quarantine_item_id=quarantine_id, target_path=file_path,
        )
        return 0
    except (OSError, sqlite3.Error, ValueError) as error:
        emit("error", code="INCIDENT_REMEDIATION_FAILED", message=f"Olay müdahalesi tamamlanamadı: {error}")
        return 2


def rollback_response_incident(incident_id: int) -> int:
    try:
        with open_database() as connection:
            connection.row_factory = sqlite3.Row
            incident = connection.execute(
                "SELECT id, protection_event_id, state FROM response_incidents WHERE id = ?", (incident_id,)
            ).fetchone()
            if incident is None or incident["state"] != "active":
                raise ValueError("Geri alınabilecek etkin müdahale bulunamadı")
            actions = connection.execute(
                "SELECT id, action_type, target, after_json, state FROM response_actions WHERE incident_id=? AND reversible=1 ORDER BY id DESC",
                (incident_id,),
            ).fetchall()
        pending: list[dict[str, Any]] = []
        for action in actions:
            if action["state"] in {"reverted", "cancelled"}:
                continue
            if action["state"] == "needs-elevation":
                with open_database() as connection:
                    connection.execute("UPDATE response_actions SET state='cancelled' WHERE id=?", (int(action["id"]),))
                continue
            if action["action_type"] == "firewall-block":
                pending.append({"action_id": int(action["id"]), "type": action["action_type"], "target": action["target"], "after": json.loads(action["after_json"] or "{}")})
                continue
            after = json.loads(action["after_json"] or "{}")
            result = 0
            if action["action_type"] == "quarantine" and after.get("item_id"):
                result = update_quarantine_item(int(after["item_id"]), "restore")
            elif action["action_type"] == "startup-disable" and after.get("backup_id"):
                result = startup_restore_entry(int(after["backup_id"]))
            if result == 0:
                with open_database() as connection:
                    connection.execute(
                        "UPDATE response_actions SET state='reverted', reverted_at=? WHERE id=?",
                        (datetime.now(timezone.utc).isoformat(), int(action["id"])),
                    )
        rolled_back_at = datetime.now(timezone.utc).isoformat()
        with open_database() as connection:
            connection.execute(
                "UPDATE response_incidents SET state=?, rolled_back_at=? WHERE id=?",
                ("partial" if pending else "rolled-back", rolled_back_at, incident_id),
            )
            connection.execute(
                "UPDATE protection_events SET disposition=?, disposition_at=? WHERE incident_id=?",
                ("rollback-partial" if pending else "restored", rolled_back_at, incident_id),
            )
        emit("incident-rolled-back", incident_id=incident_id, partial=bool(pending), pending_actions=pending)
        return 0
    except (OSError, sqlite3.Error, ValueError, json.JSONDecodeError) as error:
        emit("error", code="INCIDENT_ROLLBACK_FAILED", message=f"Müdahale geri alınamadı: {error}")
        return 2


def record_incident_firewall_action(incident_id: int, raw_detail: str) -> int:
    try:
        detail = json.loads(raw_detail)
        rule_name = str(detail.get("rule_name") or "")
        target_path = str(detail.get("target_path") or "")
        if not rule_name.startswith("Neutron-Incident-") or not target_path:
            raise ValueError("Geçersiz olay güvenlik duvarı kaydı")
        with open_database() as connection:
            incident = connection.execute(
                "SELECT id FROM response_incidents WHERE id=? AND state='active'", (incident_id,)
            ).fetchone()
        if incident is None:
            raise ValueError("Etkin müdahale bulunamadı")
        action_id = record_response_action(
            incident_id, "firewall-block", target_path,
            after={"rule_name": rule_name}, reversible=True,
        )
        emit("incident-firewall-recorded", incident_id=incident_id, action_id=action_id, rule_name=rule_name)
        return 0
    except (json.JSONDecodeError, ValueError, sqlite3.Error) as error:
        emit("error", code="INCIDENT_FIREWALL_RECORD_FAILED", message=str(error))
        return 2


def incident_status(incident_id: int) -> int:
    try:
        with open_database() as connection:
            connection.row_factory = sqlite3.Row
            incident = connection.execute("SELECT * FROM response_incidents WHERE id=?", (incident_id,)).fetchone()
            if incident is None:
                raise ValueError("Müdahale kaydı bulunamadı")
            actions = [dict(row) for row in connection.execute(
                "SELECT * FROM response_actions WHERE incident_id=? ORDER BY id", (incident_id,)
            ).fetchall()]
        emit("incident-status", incident=dict(incident), actions=actions)
        return 0
    except (ValueError, sqlite3.Error) as error:
        emit("error", code="INCIDENT_STATUS_FAILED", message=str(error))
        return 2


def finalize_incident_external_rollback(action_id: int) -> int:
    try:
        with open_database() as connection:
            cursor = connection.execute(
                "UPDATE response_actions SET state='reverted', reverted_at=? WHERE id=? AND action_type='firewall-block' AND state='applied'",
                (datetime.now(timezone.utc).isoformat(), action_id),
            )
        if cursor.rowcount != 1:
            raise ValueError("Güvenlik duvarı müdahale kaydı bulunamadı")
        emit("incident-external-rollback-finalized", action_id=action_id)
        return 0
    except (ValueError, sqlite3.Error) as error:
        emit("error", code="INCIDENT_FINALIZE_FAILED", message=str(error))
        return 2


_emit_sink: Any = None  # set by service_host() to route events over the
# service pipe instead of stdout; every existing watch_*() function keeps
# calling emit() completely unchanged, so no other code needed to know
# it's now running as a thread inside the service instead of its own
# stdout-JSON-lines subprocess.


def emit(event_type: str, **payload: Any) -> None:
    """Tek bir JSON Lines olayı yazar; protokol dışında çıktı üretmez."""
    message = {"type": event_type, **payload}
    if _emit_sink is not None:
        _emit_sink(message)
    else:
        print(json.dumps(message, ensure_ascii=False), flush=True)


def home_scan_targets() -> list[Path]:
    home = Path.home()
    # Watches the whole user profile (C:\Users\<user>) rather than just
    # Desktop/Downloads/Documents, per user request -- safe to do because
    # SKIP_DIRECTORIES already excludes AppData/node_modules/venv/.git/etc,
    # so the file-count bound isn't burned on noise before ever reaching
    # the folders users actually receive/stage files in.
    candidates = [home]
    candidates.extend(Path(value) for value in (os.environ.get("TEMP"), os.environ.get("TMP")) if value)

    targets: list[Path] = []
    seen: set[Path] = set()
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
        except OSError:
            continue
        if resolved.is_dir() and resolved not in seen:
            targets.append(resolved)
            seen.add(resolved)
    return targets


def configured_scan_targets(settings: dict[str, Any] | None = None) -> list[Path]:
    current = settings or read_app_settings()
    configured = current.get("watch_paths") or []
    if not configured:
        return home_scan_targets()
    targets: list[Path] = []
    for raw_path in configured:
        try:
            path = Path(raw_path).resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        if path.is_dir() and path not in targets:
            targets.append(path)
    return targets or home_scan_targets()


def iter_files(
    targets: list[Path],
    max_files: int = MAX_FILES,
    exclusions: ExclusionSet | None = None,
    max_depth: int = MAX_DEPTH,
) -> Iterator[Path]:
    """Sembolik bağları takip etmeden, derinliği ve sayıyı sınırlı tutar."""
    yielded = 0
    active_exclusions = exclusions or ExclusionSet((), frozenset(), frozenset())
    stack: list[tuple[Path, int]] = [(target, 0) for target in reversed(targets)]

    while stack and yielded < max_files:
        directory, depth = stack.pop()
        if directory.is_file():
            if not is_path_excluded(directory, active_exclusions):
                yielded += 1
                yield directory
            continue
        if is_path_excluded(directory, active_exclusions, include_extension=False):
            continue
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    if yielded >= max_files:
                        return
                    try:
                        if entry.is_symlink():
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            child_path = Path(entry.path)
                            if (
                                depth < max_depth
                                and entry.name.casefold() not in SKIP_DIRECTORIES
                                and not is_path_excluded(child_path, active_exclusions, include_extension=False)
                            ):
                                stack.append((child_path, depth + 1))
                            continue
                        if entry.is_file(follow_symlinks=False):
                            file_path = Path(entry.path)
                            if is_path_excluded(file_path, active_exclusions):
                                continue
                            yielded += 1
                            yield file_path
                    except OSError:
                        continue
        except (OSError, PermissionError):
            continue


def is_engine_data_file(path: Path) -> bool:
    """The watcher must not react to its own SQLite and quarantine writes."""
    try:
        path.resolve().relative_to(data_directory().resolve())
        return True
    except (OSError, ValueError):
        return False


def file_signature(path: Path) -> tuple[int, int] | None:
    try:
        stat = path.stat()
        return stat.st_mtime_ns, stat.st_size
    except (OSError, PermissionError):
        return None


def snapshot_targets(
    targets: list[Path],
    max_files: int = MAX_FILES,
    exclusions: ExclusionSet | None = None,
) -> dict[str, tuple[int, int]]:
    snapshot: dict[str, tuple[int, int]] = {}
    for path in iter_files(targets, max_files, exclusions):
        if is_engine_data_file(path):
            continue
        signature = file_signature(path)
        if signature is not None:
            snapshot[str(path)] = signature
    return snapshot


def save_protection_event(event_kind: str, finding: Finding) -> int:
    stored_path = finding.container_path or finding.path
    stored_reason = (
        f"{finding.path} · {finding.reason}"
        if finding.container_path and finding.path != finding.container_path
        else finding.reason
    )
    with open_database() as connection:
        cursor = connection.execute(
            """
            INSERT INTO protection_events (
              occurred_at, event_kind, file_path, finding_kind, severity,
              reason, sha256, risk_score, publisher_subject, publisher_thumbprint
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.now(timezone.utc).isoformat(),
                event_kind,
                stored_path,
                finding.kind,
                finding.severity,
                stored_reason,
                finding.sha256,
                finding.risk_score,
                finding.publisher_subject,
                finding.publisher_thumbprint,
            ),
        )
        return int(cursor.lastrowid)


# Combined static risk score (see combine_static_risk) above which a
# structural PE finding is treated with the same confidence as an exact
# signature hit for real-time auto-quarantine purposes. This is what lets
# Neutron act on malware it has never seen a signature for -- deliberately
# conservative (multiple independent structural techniques, e.g. unsigned +
# process-injection imports + a packed high-entropy executable section, must
# already agree) so it stays rare enough not to become a false-positive risk.
HEURISTIC_AUTO_QUARANTINE_RISK_SCORE = 90

# ML corroboration bounds (see the block in the PE analyser). The models may
# only reinforce a file the heuristics already scored at least
# ML_CORROBORATION_MIN_HEURISTIC, and only when they are near-certain
# themselves. With the auto-quarantine bar at 90, a +15 bonus means the
# affected band is heuristic 75-89: files that already tripped several
# independent deterministic checks. Nothing below 60 can ever be moved by the
# models, and no validly signed file can be moved by them at all.
ML_CORROBORATION_MIN_SCORE = 90
ML_CORROBORATION_MIN_HEURISTIC = 60
ML_CORROBORATION_BONUS = 15
# All five shipped classifiers are one family in one category, so the
# ensemble's own "high-consensus" state (which needs two independent
# categories) can never be reached today -- that state is reserved for when a
# genuinely independent adaptor, e.g. raw-byte or behavioural, is added. Until
# then the quorum is measured among the members that actually scored the file:
# applies_to means a 64-bit PE is seen by a different subset than a .NET
# assembly, so this is a count of models that looked, not of models that exist.
ML_CORROBORATION_MIN_MEMBERS = 2
ML_CORROBORATION_MAX_SPREAD = 25

# Model-led detection: the models may now reach the auto-quarantine bar on
# their own, without the heuristics having built a case first. This is
# strictly stronger than corroboration and therefore strictly harder to
# trigger -- every bound below is tighter than its ML_CORROBORATION_
# counterpart, because here there is no second, independent line of evidence
# behind the decision.
#
# Honest statement of the risk: the false-positive rate of these thresholds
# has NOT been measured on a real safe-software corpus (plan.md item 2). The
# guards that make this acceptable are the exclusions, not the numbers --
# nothing validly signed, nothing allowlisted, nothing under a Windows system
# folder and nothing belonging to Neutron itself can be removed this way, and
# every removal is reversible from Quarantine.
ML_AUTONOMOUS_MIN_SCORE = 97
ML_AUTONOMOUS_MIN_MEMBERS = 3
ML_AUTONOMOUS_MAX_SPREAD = 10
# Exactly the auto-quarantine bar, not above it: a model-led detection should
# act, but it should never outrank a case the deterministic heuristics built.
ML_AUTONOMOUS_RISK_SCORE = 90

# Structural PE traits are useful supporting evidence, but common installers,
# browsers and self-extracting archives legitimately share many of them.  A
# weak, single heuristic must never be presented as a threat by itself.
MINIMUM_PE_FINDING_RISK_SCORE = 40


# Burst brake on automatic quarantine.
#
# Neutron moves files without a human in the loop, and since the models were
# allowed to reach that decision on their own (ML_AUTONOMOUS_*) with no
# measured false-positive rate behind them, a single bad model or a bad
# signature batch could sweep a folder before anyone notices. Nothing in the
# code counted how often this fired.
#
# The brake does not weaken detection: a blocked finding is still recorded and
# still shown, it just stays 'pending' for the user to action instead of being
# moved silently. That is the right failure mode -- a real infection that
# genuinely drops 30 files is still fully visible, while a misfiring model
# cannot empty a directory while the user is away from the screen.
AUTO_QUARANTINE_BURST_WINDOW_SECONDS = 600
AUTO_QUARANTINE_BURST_LIMIT = 12


def record_auto_quarantine(path: str, driver: str) -> None:
    try:
        with open_database() as connection:
            connection.execute(
                "INSERT INTO auto_quarantine_log (occurred_at, file_path, driver) VALUES (?, ?, ?)",
                (datetime.now(timezone.utc).isoformat(), path, driver),
            )
            connection.execute(
                """DELETE FROM auto_quarantine_log WHERE id NOT IN (
                     SELECT id FROM auto_quarantine_log ORDER BY id DESC LIMIT 500)"""
            )
    except (OSError, sqlite3.Error):
        # Bookkeeping must never block a real removal.
        pass


def recent_auto_quarantine_count() -> int:
    cutoff = (
        datetime.now(timezone.utc) - timedelta(seconds=AUTO_QUARANTINE_BURST_WINDOW_SECONDS)
    ).isoformat()
    try:
        with open_database() as connection:
            row = connection.execute(
                "SELECT COUNT(*) FROM auto_quarantine_log WHERE occurred_at >= ?", (cutoff,)
            ).fetchone()
        return int(row[0] or 0)
    except (OSError, sqlite3.Error):
        return 0


def trip_auto_quarantine_brake(driver: str, count: int) -> None:
    """Stops the bleeding and tells the user, once.

    When the models drove the burst they are also switched off, because an
    uncalibrated model firing this often is the likeliest explanation and
    leaving it armed would just refill the window the moment it reopens. A
    signature-driven burst does not disarm anything -- signatures are exact,
    and the brake alone is enough to keep the damage bounded.
    """
    ml_disabled = False
    if driver == "ml":
        try:
            write_app_setting("ml_assisted_detection_enabled", False)
            ml_disabled = True
        except (OSError, sqlite3.Error, ValueError):
            ml_disabled = False
    emit(
        "auto-quarantine-brake",
        driver=driver,
        count=count,
        window_seconds=AUTO_QUARANTINE_BURST_WINDOW_SECONDS,
        ml_disabled=ml_disabled,
        message=(
            f"Son {AUTO_QUARANTINE_BURST_WINDOW_SECONDS // 60} dakikada {count} dosya "
            "otomatik karantinaya alındı. Bu, normal bir tespit hızının çok üstünde. "
            "Otomatik karantina geçici olarak durduruldu; yeni bulgular silinmeden "
            "'beklemede' olarak listelenecek."
            + (" Makine öğrenmesi destekli tespit de kapatıldı." if ml_disabled else "")
        ),
    )


def auto_quarantine_driver(finding: Finding) -> str:
    if finding.kind in {"test-signature", "signature"}:
        return "signature"
    reasons = finding.reason or ""
    return "ml" if "modellerinin" in reasons else "heuristic"


def auto_quarantine_confirmed_finding(event_id: int | None, finding: Finding) -> int | None:
    """Quarantine exact known-file signatures, plus very-high-confidence
    unsigned heuristic PE findings (see HEURISTIC_AUTO_QUARANTINE_RISK_SCORE)
    so previously-unseen malware with no signature can still be caught
    automatically. Anything under a protected system folder, or below the
    heuristic threshold, always stays pending for manual review instead."""
    if event_id is None:
        return None
    # Neutron never removes its own files automatically, not even on an exact
    # signature match: an antivirus that quarantines its own engine disables
    # itself silently, and a byte-identical hit inside our own install is far
    # more likely to be a bad signature set than a real infection. System
    # folders stay reachable by exact signatures (real malware does hide
    # there) but not by inference -- see is_high_confidence_heuristic.
    if is_neutron_own_path(Path(finding.path)):
        return None
    is_confirmed_signature = finding.kind in {"test-signature", "signature"}
    is_high_confidence_heuristic = (
        finding.kind == "pe-analysis"
        and (finding.risk_score or 0) >= HEURISTIC_AUTO_QUARANTINE_RISK_SCORE
        and "imza geçerli" not in finding.reason
        and not is_protected_system_path(Path(finding.path))
    )
    if not is_confirmed_signature and not is_high_confidence_heuristic:
        return None

    # Burst brake. Checked after the decision but before the move, so a
    # blocked finding still reaches the user as a pending detection.
    driver = auto_quarantine_driver(finding)
    recent = recent_auto_quarantine_count()
    if recent >= AUTO_QUARANTINE_BURST_LIMIT:
        # Trip once per window, not once per file: the brake fires on the
        # crossing, and every later blocked file in the same window is
        # silently held back rather than emitting another alert.
        if recent == AUTO_QUARANTINE_BURST_LIMIT:
            trip_auto_quarantine_brake(driver, recent)
            record_auto_quarantine(finding.path, f"{driver}-blocked")
        return None

    result = quarantine_file(finding.path, finding.reason)
    if result != 0:
        return None
    record_auto_quarantine(finding.path, driver)
    with open_database() as connection:
        row = connection.execute(
            """SELECT id FROM quarantine_items WHERE original_path = ? AND state = 'active'
               ORDER BY id DESC LIMIT 1""",
            (finding.path,),
        ).fetchone()
        quarantine_item_id = int(row[0]) if row else None
        connection.execute(
            """UPDATE protection_events
               SET disposition = 'quarantined', disposition_at = ?, quarantine_item_id = ?
               WHERE id = ? AND disposition = 'pending'""",
            (datetime.now(timezone.utc).isoformat(), quarantine_item_id, event_id),
        )
    return quarantine_item_id


def read_protection_history(limit: int) -> list[dict[str, Any]]:
    if not database_path().is_file():
        return []
    with open_database() as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """
            SELECT id, occurred_at, event_kind, file_path, finding_kind,
                   severity, reason, sha256, disposition, disposition_at,
                   quarantine_item_id, risk_score, publisher_subject, publisher_thumbprint,
                   incident_id
            FROM protection_events
            ORDER BY CASE WHEN disposition = 'pending' THEN 0 ELSE 1 END,
                     occurred_at DESC, id DESC
            LIMIT ?
            """,
            (max(1, min(limit, 100)),),
        ).fetchall()
    return [dict(row) for row in rows]


def protection_event_action(item_id: int, action: str) -> int:
    if action not in {"quarantine", "trust", "trust-publisher", "ignore"}:
        emit("error", code="PROTECTION_ACTION_INVALID", message="Desteklenmeyen tehdit işlemi.")
        return 2
    try:
        with open_database() as connection:
            connection.row_factory = sqlite3.Row
            event = connection.execute(
                """
                SELECT id, file_path, reason, sha256, disposition,
                       publisher_subject, publisher_thumbprint
                FROM protection_events WHERE id = ?
                """,
                (item_id,),
            ).fetchone()
        if event is None:
            raise ValueError("Koruma olayı bulunamadı")
        if event["disposition"] != "pending":
            emit(
                "protection-action",
                event_id=item_id,
                action=str(event["disposition"]),
                already_resolved=True,
            )
            return 0

        disposition = {
            "quarantine": "quarantined", "trust": "trusted",
            "trust-publisher": "trusted-publisher", "ignore": "ignored",
        }[action]
        quarantine_item_id: int | None = None
        if action == "trust":
            digest = str(event["sha256"] or "")
            if not PROTON_SHA256_PATTERN.fullmatch(digest):
                raise ValueError("Bu bulgunun güvenilir olarak kaydedilebilecek SHA-256 özeti yok")
            current = load_exclusion_set()
            if digest not in current.hashes:
                add_exclusion("hash", digest, str(event["file_path"]))
        elif action == "trust-publisher":
            thumbprint = str(event["publisher_thumbprint"] or "")
            subject = str(event["publisher_subject"] or "")
            if not thumbprint:
                raise ValueError("Bu bulgunun güvenilir olarak kaydedilebilecek yayıncı sertifikası yok")
            trust_publisher(thumbprint, subject)
        elif action == "quarantine":
            result = quarantine_file(str(event["file_path"]), str(event["reason"] or "Gerçek zamanlı koruma bulgusu"))
            if result != 0:
                return result
            with open_database() as connection:
                row = connection.execute(
                    """
                    SELECT id FROM quarantine_items
                    WHERE original_path = ? AND state = 'active'
                    ORDER BY id DESC LIMIT 1
                    """,
                    (str(event["file_path"]),),
                ).fetchone()
            quarantine_item_id = int(row[0]) if row else None

        resolved_at = datetime.now(timezone.utc).isoformat()
        with open_database() as connection:
            connection.execute(
                """
                UPDATE protection_events
                SET disposition = ?, disposition_at = ?, quarantine_item_id = ?
                WHERE id = ? AND disposition = 'pending'
                """,
                (disposition, resolved_at, quarantine_item_id, item_id),
            )
        emit(
            "protection-action",
            event_id=item_id,
            action=disposition,
            disposition_at=resolved_at,
            quarantine_item_id=quarantine_item_id,
        )
        return 0
    except (OSError, sqlite3.Error, ValueError) as error:
        emit("error", code="PROTECTION_ACTION_FAILED", message=f"Tehdit işlemi tamamlanamadı: {error}")
        return 2


def sha256_for(path: Path, size: int) -> str | None:
    if size > MAX_HASH_BYTES:
        return None
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(64 * 1024), b""):
                digest.update(block)
    except (OSError, PermissionError):
        return None
    return digest.hexdigest()


def verify_authenticode(path: Path, has_embedded_signature: bool) -> str:
    """Verify an embedded Windows signature without opening UI or using the network."""
    if not has_embedded_signature:
        return "not-embedded"
    if os.name != "nt":
        return "present-unverified"
    from ctypes import wintypes

    class GUID(ctypes.Structure):
        _fields_ = [
            ("Data1", wintypes.DWORD),
            ("Data2", wintypes.WORD),
            ("Data3", wintypes.WORD),
            ("Data4", ctypes.c_ubyte * 8),
        ]

    class WINTRUST_FILE_INFO(ctypes.Structure):
        _fields_ = [
            ("cbStruct", wintypes.DWORD),
            ("pcwszFilePath", wintypes.LPCWSTR),
            ("hFile", wintypes.HANDLE),
            ("pgKnownSubject", ctypes.POINTER(GUID)),
        ]

    class WINTRUST_DATA(ctypes.Structure):
        _fields_ = [
            ("cbStruct", wintypes.DWORD),
            ("pPolicyCallbackData", wintypes.LPVOID),
            ("pSIPClientData", wintypes.LPVOID),
            ("dwUIChoice", wintypes.DWORD),
            ("fdwRevocationChecks", wintypes.DWORD),
            ("dwUnionChoice", wintypes.DWORD),
            ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
            ("dwStateAction", wintypes.DWORD),
            ("hWVTStateData", wintypes.HANDLE),
            ("pwszURLReference", wintypes.LPCWSTR),
            ("dwProvFlags", wintypes.DWORD),
            ("dwUIContext", wintypes.DWORD),
        ]

    action = GUID(
        0x00AAC56B,
        0xCD44,
        0x11D0,
        (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE),
    )
    file_info = WINTRUST_FILE_INFO(
        ctypes.sizeof(WINTRUST_FILE_INFO), str(path), None, None
    )
    trust_data = WINTRUST_DATA(
        ctypes.sizeof(WINTRUST_DATA),
        None,
        None,
        2,
        0,
        1,
        ctypes.pointer(file_info),
        0,
        None,
        None,
        0x00001000,
        0,
    )
    try:
        wintrust = ctypes.WinDLL("wintrust", use_last_error=True)
        wintrust.WinVerifyTrust.argtypes = [
            wintypes.HWND, ctypes.POINTER(GUID), ctypes.POINTER(WINTRUST_DATA)
        ]
        wintrust.WinVerifyTrust.restype = ctypes.c_long
        return "trusted" if wintrust.WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(trust_data)) == 0 else "invalid"
    except (OSError, ValueError):
        return "present-unverified"


def windows_signature_details(path: Path) -> tuple[str, str | None, str | None]:
    """Return Windows trust status plus the exact signing certificate identity."""
    if os.name != "nt":
        return "not-embedded", None, None
    script = (
        "$signature = Get-AuthenticodeSignature -LiteralPath $args[0]; "
        "$certificate = $signature.SignerCertificate; "
        "[pscustomobject]@{ status=$signature.Status.ToString(); "
        "thumbprint=if($certificate){$certificate.Thumbprint}else{''}; "
        "subject=if($certificate){$certificate.Subject}else{''} } | ConvertTo-Json -Compress"
    )
    creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        result = subprocess.run(
            [
                "powershell.exe", "-NoProfile", "-NonInteractive",
                "-Command", script, str(path),
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=6,
            check=False,
            creationflags=creation_flags,
        )
    except (OSError, subprocess.SubprocessError):
        return "present-unverified", None, None
    try:
        detail = json.loads(result.stdout.strip().lstrip("\ufeff"))
    except (json.JSONDecodeError, TypeError):
        return "present-unverified", None, None
    status = str(detail.get("status") or "").casefold()
    mapped = "trusted" if result.returncode == 0 and status == "valid" else "unsigned" if status == "notsigned" else "invalid" if status else "present-unverified"
    thumbprint = re.sub(r"[^A-Fa-f0-9]", "", str(detail.get("thumbprint") or "")).upper() or None
    subject = str(detail.get("subject") or "").strip()[:500] or None
    return mapped, thumbprint, subject


# --- Signed-image trust gate ----------------------------------------------
#
# Every process watcher below (memory, behaviour, hidden-process) needs the
# same question answered for each process that starts: "is this executable
# validly signed by a publisher Windows already trusts?"
#
# This matters more than any single heuristic in the file. The largest source
# of false positives in this engine was behavioural checks firing on ordinary
# signed software -- the textbook case being a browser's JIT compiler
# allocating RWX memory, which is indistinguishable from shellcode injection
# by memory layout alone (Edge/Chrome's V8, .NET, and Java all do it). A
# structural indicator that fires on Microsoft Edge every time a tab opens is
# not a detection, it is noise, and noise trains the user to ignore real
# findings.
#
# WinVerifyTrust is not free and a watcher polling every few seconds would
# otherwise re-verify the same handful of images forever, so verdicts are
# cached on identity-plus-content: (path, mtime, size). Any rewrite of the
# file changes mtime or size and invalidates the entry, which is what stops a
# cached "trusted" verdict from covering a binary swapped underneath it.
TRUSTED_IMAGE_CACHE_LIMIT = 512
_trusted_image_cache: dict[tuple[str, int, int], bool] = {}


def is_trusted_signed_image(path: Path | str) -> bool:
    """True only when Windows itself validates the file's Authenticode chain.

    Deliberately conservative in both directions: an unreadable, missing or
    unverifiable file is reported as untrusted (so a failure to check never
    silently suppresses a finding), and only a full WinVerifyTrust success
    counts as trusted (so a merely *present* signature does not).
    """
    if os.name != "nt":
        return False
    try:
        resolved = Path(path)
        stat_result = resolved.stat()
        key = (os.path.normcase(str(resolved)), int(stat_result.st_mtime_ns), int(stat_result.st_size))
    except (OSError, RuntimeError, ValueError):
        return False
    cached = _trusted_image_cache.get(key)
    if cached is not None:
        return cached
    # has_embedded_signature=True unconditionally: WinVerifyTrust reports an
    # unsigned file as an error, which maps to "invalid" here, so letting it
    # make the call is both correct and one less PE parse than checking the
    # security directory ourselves.
    try:
        verdict = verify_authenticode(resolved, True) == "trusted"
    except (OSError, ValueError):
        verdict = False
    if len(_trusted_image_cache) >= TRUSTED_IMAGE_CACHE_LIMIT:
        _trusted_image_cache.clear()
    _trusted_image_cache[key] = verdict
    return verdict


def analyze_pe(path: Path, size: int, payload: bytes | None = None) -> PEAnalysis | None:
    if pefile is None or size < 64 or size > MAX_PE_BYTES:
        return None
    try:
        pe = pefile.PE(data=payload, fast_load=True) if payload is not None else pefile.PE(str(path), fast_load=True)
    except (OSError, pefile.PEFormatError):
        return None
    try:
        sections = list(pe.sections)
        if not sections or len(sections) > MAX_PE_SECTIONS:
            return None
        directory_names = [
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"],
        ]
        try:
            pe.parse_data_directories(directories=directory_names)
        except (AttributeError, IndexError, pefile.PEFormatError):
            pass

        machine = int(pe.FILE_HEADER.Machine)
        architecture = {
            0x014C: "x86",
            0x8664: "x64",
            0x01C4: "ARM Thumb-2",
            0xAA64: "ARM64",
        }.get(machine, f"machine-0x{machine:04x}")
        characteristics = int(pe.FILE_HEADER.Characteristics)
        subsystem = int(getattr(pe.OPTIONAL_HEADER, "Subsystem", 0))
        image_kind = "DLL" if characteristics & 0x2000 else "sürücü" if subsystem == 1 else "EXE"
        entry_point = int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        reasons: list[tuple[int, str]] = []

        executable_high_entropy = []
        writable_executable = []
        suspicious_section_names = []
        section_entropies: list[float] = []
        executable_section_count = 0
        packer_section_markers = ("upx", "aspack", "mpress", "themida", "vmp", "petite", "pec")
        for section in sections:
            flags = int(section.Characteristics)
            executable = bool(flags & 0x20000000)
            writable = bool(flags & 0x80000000)
            raw_size = int(section.SizeOfRawData)
            name = section.Name.rstrip(b"\0").decode("ascii", errors="replace") or "isimsiz"
            entropy = float(section.get_entropy()) if raw_size else 0.0
            section_entropies.append(entropy)
            normalized_name = name.casefold().strip(". _")
            if any(marker in normalized_name for marker in packer_section_markers):
                suspicious_section_names.append(name)
            if executable and writable:
                writable_executable.append(name)
            if executable:
                executable_section_count += 1
            if executable and raw_size >= 4096 and entropy >= 7.35:
                executable_high_entropy.append(f"{name} ({entropy:.2f})")
        if writable_executable:
            reasons.append((32, f"yazılabilir ve çalıştırılabilir bölüm: {', '.join(writable_executable[:3])}"))
        if executable_high_entropy:
            reasons.append((22, f"yüksek entropili çalıştırılabilir bölüm: {', '.join(executable_high_entropy[:3])}"))
        if suspicious_section_names:
            reasons.append((24, f"bilinen packer/koruyucu bölüm adı: {', '.join(suspicious_section_names[:3])}"))

        entry_section = pe.get_section_by_rva(entry_point) if entry_point else None
        entrypoint_outside_sections = bool(entry_point and entry_section is None)
        entrypoint_non_executable = bool(
            entry_section is not None and not int(entry_section.Characteristics) & 0x20000000
        )
        if entry_point and entry_section is None:
            reasons.append((25, "giriş noktası hiçbir PE bölümünün içinde değil"))
        elif entry_section is not None and not int(entry_section.Characteristics) & 0x20000000:
            reasons.append((24, "giriş noktası çalıştırılabilir olmayan bölümde"))
        if len(sections) > 12:
            reasons.append((7, f"olağandışı yüksek bölüm sayısı: {len(sections)}"))

        import_names: set[str] = set()
        import_count = 0
        for directory_name in ("DIRECTORY_ENTRY_IMPORT", "DIRECTORY_ENTRY_DELAY_IMPORT"):
            for library in list(getattr(pe, directory_name, []) or [])[:256]:
                for imported in list(getattr(library, "imports", []) or []):
                    if import_count >= MAX_PE_IMPORTS:
                        break
                    import_count += 1
                    if imported.name:
                        import_names.add(imported.name.decode("ascii", errors="ignore").casefold())
                if import_count >= MAX_PE_IMPORTS:
                    break

        api_groups = (
            (30, "süreç enjeksiyonu API kümesi", {
                "virtualallocex", "writeprocessmemory", "createremotethread",
                "queueuserapc", "ntunmapviewofsection", "setthreadcontext",
            }, 3),
            (30, "kimlik bilgisi dökümü API kümesi", {
                "minidumpwritedump", "openprocesstoken", "adjusttokenprivileges",
                "duplicatehandle", "ntquerysysteminformation",
            }, 3),
            (18, "kalıcılık değiştirme API kümesi", {
                "regsetvalueexa", "regsetvalueexw", "regcreatekeyexa", "regcreatekeyexw",
                "createservicea", "createservicew", "changeserviceconfiga", "changeserviceconfigw",
            }, 3),
            (14, "ağdan içerik alma API kümesi", {
                "urldownloadtofilea", "urldownloadtofilew", "internetopenurla",
                "internetopenurlw", "winhttpopenrequest", "httpsendrequesta",
                "httpsendrequestw", "winhttpreceiveresponse",
            }, 3),
        )
        api_match_counts: dict[str, int] = {}
        for points, description, names, threshold in api_groups:
            matches = sorted(import_names.intersection(names))
            api_match_counts[description] = len(matches)
            if len(matches) >= threshold:
                reasons.append((points, f"{description}: {', '.join(matches[:4])}"))
        if import_count == 0 and image_kind in {"EXE", "DLL"} and size >= 64 * 1024:
            reasons.append((12, "çalıştırılabilir dosyada okunabilir import tablosu yok"))

        overlay_ratio = 0.0
        overlay_offset = pe.get_overlay_data_start_offset()
        if overlay_offset is not None and size > 0:
            overlay_ratio = max(0, size - int(overlay_offset)) / size
            if overlay_ratio >= 0.65 and size >= 128 * 1024:
                reasons.append((8, f"dosyanın %{overlay_ratio * 100:.0f} bölümü PE dışı ek veri"))

        security_index = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
        has_signature = False
        if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > security_index:
            security = pe.OPTIONAL_HEADER.DATA_DIRECTORY[security_index]
            has_signature = bool(int(security.VirtualAddress) and int(security.Size) >= 8)
        preliminary_score = min(100, sum(points for points, _reason in reasons))
        publisher_thumbprint = None
        publisher_subject = None
        if payload is None:
            signature_status = verify_authenticode(path, has_signature)
            if has_signature or preliminary_score >= 20:
                detailed_status, publisher_thumbprint, publisher_subject = windows_signature_details(path)
                if detailed_status != "present-unverified":
                    signature_status = detailed_status
        else:
            # Arşiv üyeleri diske çıkarılmaz; Windows güven zinciri yalnız dosya yolu
            # üzerinden doğrulanabildiğinden gömülü imzanın varlığı raporlanır.
            signature_status = "present-unverified" if has_signature else "not-embedded"
        if signature_status == "invalid":
            reasons.append((25, "gömülü dijital imza Windows doğrulamasından geçmedi"))

        com_descriptor_index = pefile.DIRECTORY_ENTRY.get("IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR", 14)
        is_dotnet = False
        if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > com_descriptor_index:
            com_descriptor = pe.OPTIONAL_HEADER.DATA_DIRECTORY[com_descriptor_index]
            is_dotnet = bool(int(com_descriptor.VirtualAddress) and int(com_descriptor.Size))
        model_contexts = {"pe"}
        if image_kind == "sürücü":
            model_contexts.add("driver")
        elif is_dotnet:
            model_contexts.add("dotnet")
        elif architecture in {"x64", "ARM64"}:
            model_contexts.add("win64")
        else:
            model_contexts.add("win32")

        ml_features = None
        ml_shadow_score = None
        ml_model_version = None
        ml_shadow_details = None
        try:
            features = build_feature_vector(
                file_size_log2=math.log2(max(1, size)),
                section_count=len(sections),
                import_count_log2=math.log2(1 + import_count),
                executable_section_count=executable_section_count,
                writable_executable_count=len(writable_executable),
                high_entropy_executable_count=len(executable_high_entropy),
                packer_marker_count=len(suspicious_section_names),
                max_section_entropy_normalized=max(section_entropies, default=0.0) / 8.0,
                overlay_ratio=overlay_ratio,
                entrypoint_outside_sections=entrypoint_outside_sections,
                entrypoint_non_executable=entrypoint_non_executable,
                injection_api_match_count=api_match_counts.get("süreç enjeksiyonu API kümesi", 0),
                credential_api_match_count=api_match_counts.get("kimlik bilgisi dökümü API kümesi", 0),
                persistence_api_match_count=api_match_counts.get("kalıcılık değiştirme API kümesi", 0),
                network_api_match_count=api_match_counts.get("ağdan içerik alma API kümesi", 0),
                missing_import_table=import_count == 0 and image_kind in {"EXE", "DLL"} and size >= 64 * 1024,
                has_embedded_signature=has_signature,
                trusted_signature=signature_status == "trusted",
                invalid_signature=signature_status == "invalid",
                is_dll=image_kind == "DLL",
                is_driver=image_kind == "sürücü",
                is_64_bit=architecture in {"x64", "ARM64"},
            )
            legacy_prediction = predict_ensemble(
                data_directory() / "ml", features, contexts=frozenset(model_contexts),
            )
            ember_prediction = predict_ember2024(
                data_directory() / "ml" / "ember2024", path, payload,
                contexts=frozenset(model_contexts),
            )
            prediction = merge_ensemble_predictions(
                "neutron-shadow-ensemble-2", legacy_prediction, ember_prediction,
            )
            if prediction is not None:
                ml_features = features
                ml_shadow_score = prediction.score
                ml_model_version = prediction.ensemble_version
                ml_shadow_details = prediction.as_payload()
        except (OSError, TypeError, ValueError):
            # Shadow ML must always fail open and never alter the deterministic
            # scanner's result while the model is being introduced.
            pass

        risk_score = min(100, sum(points for points, _reason in reasons))

        # --- ML corroboration -------------------------------------------
        # The lower of the two model paths: here the models only strengthen a
        # case the deterministic heuristics already built, and cannot act on a
        # validly signed file. The model-led path that CAN raise a detection
        # on its own follows immediately below, behind much tighter bounds.
        #
        # Why this weaker path still exists: picking a single "quarantine at
        # ML score >= X" needs measured false-positive data this build does
        # not have yet (see --ml-shadow-report). Bounding the models to a
        # bonus keeps the existing heuristic gate as the floor, so the worst
        # case is a file that already looked suspicious on several
        # independent deterministic grounds crossing the line sooner.
        #
        # Also deliberate: the five EMBER classifiers count as ONE piece of
        # evidence, not five votes. They share a feature space and a training
        # set, so their agreement is not independent corroboration.
        ml_details = ml_shadow_details or {}
        ml_member_count = int(ml_details.get("member_count") or 0)
        ml_member_spread = int(ml_details.get("member_spread") or 0)
        if (
            ml_shadow_score is not None
            and ml_shadow_score >= ML_CORROBORATION_MIN_SCORE
            and risk_score >= ML_CORROBORATION_MIN_HEURISTIC
            and signature_status not in {"trusted"}
            # The ensemble collapses its members into one averaged score, so
            # the score alone cannot distinguish "every applicable model said
            # malicious" from "one model was certain and dragged the mean up".
            # Require a real quorum, and require them to actually agree.
            and ml_member_count >= ML_CORROBORATION_MIN_MEMBERS
            and ml_member_spread <= ML_CORROBORATION_MAX_SPREAD
            and ml_assisted_detection_enabled()
        ):
            risk_score = min(100, risk_score + ML_CORROBORATION_BONUS)
            reasons.append((
                ML_CORROBORATION_BONUS,
                f"Statik PE modellerinin {ml_member_count} tanesi bu dosyayı yüksek olasılıkla "
                f"zararlı buldu (ortak puan {ml_shadow_score}/100, modeller arası fark "
                f"{ml_member_spread} puan, sezgisel bulgularla aynı yönde)",
            ))

        # --- Model-led detection ----------------------------------------
        # Unlike corroboration above, this needs no prior heuristic case: a
        # near-unanimous, near-certain verdict from enough models is allowed
        # to reach the auto-quarantine bar by itself, so malware whose
        # structure gives the deterministic checks nothing to hold onto can
        # still be caught.
        #
        # The path exclusions are applied here rather than left to the
        # quarantine gate on purpose: this keeps a model-led score off the
        # file's *risk* entirely, so an excluded file is not paraded through
        # the UI as a 90-risk threat that Neutron then declines to act on.
        if (
            ml_shadow_score is not None
            and ml_shadow_score >= ML_AUTONOMOUS_MIN_SCORE
            and ml_member_count >= ML_AUTONOMOUS_MIN_MEMBERS
            and ml_member_spread <= ML_AUTONOMOUS_MAX_SPREAD
            and signature_status not in {"trusted"}
            and risk_score < ML_AUTONOMOUS_RISK_SCORE
            # Archive members are scored from memory and have no real path on
            # disk, so neither the signature chain nor the path exclusions can
            # be evaluated for them. Nothing is auto-removed from inside an
            # archive anyway; leave those as review-only findings.
            and payload is None
            and not is_auto_quarantine_forbidden(path)
            and ml_assisted_detection_enabled()
        ):
            reasons.append((
                ML_AUTONOMOUS_RISK_SCORE - risk_score,
                f"Statik PE modellerinin {ml_member_count} tanesi bu imzasız dosyayı neredeyse "
                f"kesin zararlı buldu (ortak puan {ml_shadow_score}/100, modeller arası fark "
                f"{ml_member_spread} puan); sezgisel kontroller tek başına bu sonuca varmamıştı",
            ))
            risk_score = ML_AUTONOMOUS_RISK_SCORE

        # A trusted signature discounts the structural score but deliberately
        # does NOT floor it: this value is also written to
        # ml_shadow_observations.heuristic_score, which is the corpus the
        # false-positive calibration in plan.md item 2 has to measure. Zeroing
        # or capping it here would hide exactly the behaviour that work needs
        # to see. Suppressing the user-facing finding is pe_finding()'s job,
        # and it drops trusted-signed files outright.
        if signature_status == "trusted" and risk_score:
            risk_score = max(0, risk_score - 18)
        if signature_status == "trusted" and publisher_thumbprint:
            try:
                publisher_allowed = publisher_thumbprint in trusted_publisher_thumbprints()
            except (OSError, sqlite3.Error):
                publisher_allowed = False
            if publisher_allowed:
                risk_score = 0
        ordered_reasons = tuple(reason for _points, reason in sorted(reasons, reverse=True))
        return PEAnalysis(
            architecture=architecture,
            image_kind=image_kind,
            entry_point=entry_point,
            section_count=len(sections),
            import_count=import_count,
            signature_status=signature_status,
            publisher_subject=publisher_subject,
            publisher_thumbprint=publisher_thumbprint,
            risk_score=risk_score,
            reasons=ordered_reasons,
            ml_shadow_score=ml_shadow_score,
            ml_model_version=ml_model_version,
            ml_features=ml_features,
            ml_shadow_details=ml_shadow_details,
        )
    except (AttributeError, IndexError, MemoryError, OSError, OverflowError, ValueError, pefile.PEFormatError):
        return None
    finally:
        pe.close()


def pe_finding(
    path: Path, size: int, digest: str | None, payload: bytes | None = None,
    analysis: PEAnalysis | None = None,
) -> Finding | None:
    analysis = analysis or analyze_pe(path, size, payload)
    if analysis is None or not analysis.reasons:
        return None
    # A valid Authenticode chain is strong benign evidence regardless of the
    # download folder. Installers such as ChromeSetup are commonly packed and
    # may import networking/process APIs, so structural traits alone must not
    # turn a Windows-trusted binary into a threat. Exact hashes, YARA and cloud
    # reputation are evaluated separately and can still flag the file.
    if analysis.signature_status == "trusted":
        return None
    if analysis.risk_score < MINIMUM_PE_FINDING_RISK_SCORE:
        return None
    severity = (
        "critical" if analysis.risk_score >= 85
        else "high" if analysis.risk_score >= 60
        else "medium" if analysis.risk_score >= 35
        else "low"
    )
    signature_labels = {
        "trusted": "imza geçerli",
        "unsigned": "imzasız",
        "invalid": "imza geçersiz",
        "not-embedded": "gömülü imza yok",
        "present-unverified": "imza doğrulanamadı",
    }
    summary = "; ".join(analysis.reasons[:3])
    reason = (
        f"PE risk puanı {analysis.risk_score}/100 · {analysis.image_kind} {analysis.architecture} · "
        f"{signature_labels.get(analysis.signature_status, analysis.signature_status)} · {summary}"
    )
    return Finding(
        path=str(path),
        kind="pe-analysis",
        severity=severity,
        reason=reason,
        sha256=digest,
        risk_score=analysis.risk_score,
        publisher_subject=analysis.publisher_subject,
        publisher_thumbprint=analysis.publisher_thumbprint,
        ml_shadow_score=analysis.ml_shadow_score,
        ml_model_version=analysis.ml_model_version,
        ml_shadow_details=analysis.ml_shadow_details,
    )


def severity_for_risk(score: int) -> str:
    return "critical" if score >= 85 else "high" if score >= 60 else "medium" if score >= 35 else "low"


# --- Independent evidence categories --------------------------------------
#
# Two findings about the same file only corroborate each other when they could
# have failed independently. Counting *findings* instead of independent
# evidence is how a detector talks itself into confidence it has not earned:
# the five EMBER classifiers share a feature space and a training set, so their
# agreement is one opinion repeated, not five. The same trap sits one level up
# -- three YARA rules matching the same packer stub is one piece of content
# evidence, not three.
#
# So every finding kind is mapped to the category of evidence it actually
# comes from, and consensus is counted over categories, taking only the
# strongest finding within each.
#
# `planned` categories are named here on purpose. They are the ones plan.md
# item 3 says must exist before Neutron may claim genuinely diverse consensus,
# and writing them down as *absent* is what keeps that gap visible instead of
# letting a future adapter quietly inherit confidence it has not been measured
# for. A planned category has no adapter and can never contribute evidence.
DETECTION_CATEGORY_STATUS = {
    "reputation-exact": "armed",     # exact hash known to Proton
    "reputation-cloud": "armed",     # third-party hash verdict
    "content-pattern": "armed",      # byte/text patterns in the content itself
    "static-pe": "armed",            # PE structure heuristics AND the EMBER models
    "filename": "armed",             # naming and metadata only
    "container": "armed",            # archive structure abuse
    "behaviour": "armed",            # runtime watchers, never available to a static scan
    "raw-byte-ml": "planned",        # no adapter yet -- see plan.md item 3
}

DETECTION_CATEGORY_BY_KIND = {
    "signature": "reputation-exact",
    "test-signature": "reputation-exact",
    "cloud-reputation": "reputation-cloud",
    "network-reputation": "reputation-cloud",
    "yara": "content-pattern",
    "script-analysis": "content-pattern",
    "document-analysis": "content-pattern",
    # Deliberately the same category as the models: both read PE structure, so
    # a heuristic agreeing with EMBER is not independent confirmation.
    "pe-analysis": "static-pe",
    "review": "filename",
    "usb-autorun": "filename",
    "archive-structure": "container",
    "behavior": "behaviour",
    "memory-injection": "behaviour",
    "hidden-process": "behaviour",
    "persistence": "behaviour",
    "ransomware-canary": "behaviour",
    "ransomware-bulk": "behaviour",
    "service-tamper": "behaviour",
}

# Categories a static file scan can actually produce. "behaviour" is armed but
# never appears here: it comes from the live watchers, so a file sitting on
# disk cannot earn behavioural corroboration at scan time.
STATIC_SCAN_CATEGORIES = frozenset({
    "reputation-exact", "reputation-cloud", "content-pattern", "static-pe",
    "filename", "container",
})


def detection_category(kind: str) -> str | None:
    """Evidence category for a finding kind, or None when it carries no
    independent evidence (informational notices such as archive-warning)."""
    category = DETECTION_CATEGORY_BY_KIND.get(kind)
    if category is None or DETECTION_CATEGORY_STATUS.get(category) != "armed":
        return None
    return category


def combine_static_risk(findings: list[Finding]) -> None:
    """Raise the leading finding's score when independent categories agree.

    Only the strongest finding per category contributes, so repeated evidence
    of the same kind cannot inflate the result -- previously three YARA hits
    were summed as three separate confirmations of each other.
    """
    best_by_category: dict[str, Finding] = {}
    for finding in findings:
        if finding.risk_score is None:
            continue
        category = detection_category(finding.kind)
        if category is None or category not in STATIC_SCAN_CATEGORIES:
            continue
        current = best_by_category.get(category)
        if current is None or (finding.risk_score or 0) > (current.risk_score or 0):
            best_by_category[category] = finding
    if len(best_by_category) < 2:
        return
    contributors = list(best_by_category.values())
    primary = next(
        (finding for finding in contributors if finding.kind == "pe-analysis"),
        max(contributors, key=lambda finding: finding.risk_score or 0),
    )
    scores = sorted((finding.risk_score or 0 for finding in contributors), reverse=True)
    combined = min(100, round(scores[0] + sum(scores[1:]) * 0.35))
    primary.risk_score = combined
    primary.severity = severity_for_risk(combined)
    primary.reason = (
        f"Birleşik statik risk {combined}/100 · {len(best_by_category)} bağımsız kanıt kategorisi "
        f"({', '.join(sorted(best_by_category))}) · {primary.reason}"
    )


def append_archive_notice(
    findings: list[Finding], budget: ArchiveBudget, path: str, reason: str,
    *, severity: str = "low", kind: str = "archive-warning", risk_score: int = 0,
) -> None:
    if budget.findings >= MAX_ARCHIVE_FINDINGS:
        return
    findings.append(Finding(
        path=path, kind=kind, severity=severity, reason=reason,
        sha256=None, risk_score=risk_score, container_path=path.split(" → ", 1)[0],
    ))
    budget.findings += 1


def normalized_archive_member_name(raw_name: str) -> tuple[str, bool]:
    value = str(raw_name).replace("\\", "/").strip()
    drive_prefix = bool(re.match(r"^[A-Za-z]:", value))
    absolute = value.startswith("/") or drive_prefix
    parts = [part for part in value.split("/") if part not in {"", "."}]
    traversal = any(part == ".." for part in parts)
    safe_parts = [part for part in parts if part != ".."]
    normalized = "/".join(safe_parts) or "isimsiz-üye"
    return normalized[:1024], absolute or traversal


def detect_archive_format(name: str, header: bytes) -> str | None:
    suffix = Path(name).suffix.casefold()
    if suffix in ARCHIVE_EXTENSIONS:
        return suffix
    if header.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return ".zip"
    if header.startswith(b"7z\xbc\xaf\x27\x1c"):
        return ".7z"
    if header.startswith((b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00")):
        return ".rar"
    return None


def inspect_memory_payload(
    display_path: str,
    member_name: str,
    payload: bytes,
    signatures: dict[int, dict[str, dict[str, Any]]],
    yara_rules: Any | None,
    exclusions: ExclusionSet,
    depth: int,
    budget: ArchiveBudget,
) -> list[Finding]:
    if budget.findings >= MAX_ARCHIVE_FINDINGS:
        return []
    findings: list[Finding] = []
    size = len(payload)
    digest = hashlib.sha256(payload).hexdigest()
    if digest in exclusions.hashes:
        return findings

    name = Path(member_name).name.casefold()
    suffix = Path(member_name).suffix.casefold()
    stem_parts = name.split(".")
    if (
        suffix in EXECUTABLE_EXTENSIONS
        and len(stem_parts) >= 3
        and f".{stem_parts[-2]}" in DOCUMENT_EXTENSIONS
    ):
        findings.append(Finding(
            path=display_path, kind="review", severity="medium",
            reason="Arşivde belge uzantısını taklit eden çalıştırılabilir dosya adı",
            sha256=digest, risk_score=45, container_path=display_path.split(" → ", 1)[0],
        ))
    if suffix in EXECUTABLE_EXTENSIONS and any(word in name for word in RISK_WORDS):
        findings.append(Finding(
            path=display_path, kind="review", severity="low",
            reason="Arşivde inceleme gerektiren dosya adı ve çalıştırılabilir tür",
            sha256=digest, risk_score=20, container_path=display_path.split(" → ", 1)[0],
        ))

    if suffix in {".exe", ".dll", ".scr"}:
        structural = pe_finding(Path(member_name), size, digest, payload)
        if structural is not None:
            structural.path = display_path
            structural.container_path = display_path.split(" → ", 1)[0]
            findings.append(structural)

    signature = signatures.get(size, {}).get(digest)
    if signature:
        findings.append(Finding(
            path=display_path,
            kind="test-signature" if signature["source"] == "builtin" else "signature",
            severity=str(signature["severity"]),
            reason=f'{signature["name"]} eşleşmesi arşiv içinde bulundu',
            sha256=digest, risk_score=100, container_path=display_path.split(" → ", 1)[0],
        ))

    if payload.strip() == EICAR_MARKER and not any(
        finding.kind == "test-signature" for finding in findings
    ):
        findings.append(Finding(
            path=display_path, kind="test-signature", severity="high",
            reason="EICAR güvenli antivirüs test imzası arşiv içinde bulundu",
            sha256=digest, risk_score=100, container_path=display_path.split(" → ", 1)[0],
        ))

    if yara_rules is not None and size <= MAX_YARA_BYTES:
        try:
            for match in yara_rules.match(data=payload, timeout=2):
                metadata = match.meta or {}
                description = str(metadata.get("description") or match.rule)
                severity = str(metadata.get("severity") or "medium").casefold()
                if severity not in {"low", "medium", "high", "critical"}:
                    severity = "medium"
                findings.append(Finding(
                    path=display_path, kind="yara", severity=severity,
                    reason=f"YARA arşiv üyesi: {description}", sha256=digest,
                    risk_score={"low": 20, "medium": 40, "high": 70, "critical": 95}[severity],
                    container_path=display_path.split(" → ", 1)[0],
                ))
        except (MemoryError, TimeoutError, yara.Error):
            pass

    combine_static_risk(findings)
    remaining = max(0, MAX_ARCHIVE_FINDINGS - budget.findings)
    accepted = findings[:remaining]
    budget.findings += len(accepted)

    nested_archive_format = detect_archive_format(member_name, payload[:8])
    if nested_archive_format:
        if depth >= MAX_ARCHIVE_DEPTH:
            append_archive_notice(
                accepted, budget, display_path,
                f"İç içe arşiv derinliği {MAX_ARCHIVE_DEPTH} sınırına ulaştı; daha derin içerik atlandı.",
            )
        else:
            accepted.extend(inspect_archive_bytes(
                display_path, nested_archive_format, payload, signatures, yara_rules,
                exclusions, depth + 1, budget
            ))
    return accepted


def inspect_archive_member(
    findings: list[Finding],
    outer_path: str,
    raw_name: str,
    declared_size: int,
    compressed_size: int,
    encrypted: bool,
    is_link: bool,
    loader: Any,
    signatures: dict[int, dict[str, dict[str, Any]]],
    yara_rules: Any | None,
    exclusions: ExclusionSet,
    depth: int,
    budget: ArchiveBudget,
) -> bool:
    if budget.members >= MAX_ARCHIVE_MEMBERS or budget.findings >= MAX_ARCHIVE_FINDINGS:
        return False
    budget.members += 1
    member_name, unsafe_path = normalized_archive_member_name(raw_name)
    display_path = f"{outer_path} → {member_name}"
    if unsafe_path:
        append_archive_notice(
            findings, budget, display_path,
            "Arşiv üyesi üst dizine veya mutlak konuma çıkmaya çalışan güvensiz yol içeriyor.",
            severity="medium", kind="archive-structure", risk_score=40,
        )
    if is_link:
        append_archive_notice(
            findings, budget, display_path,
            "Arşivdeki sembolik bağlantı güvenlik nedeniyle izlenmedi.",
        )
        return True
    if encrypted:
        append_archive_notice(
            findings, budget, display_path,
            "Parolalı arşiv üyesi açılamadığı için içerik taranamadı.",
        )
        return True
    if declared_size < 0 or declared_size > MAX_ARCHIVE_MEMBER_BYTES:
        append_archive_notice(
            findings, budget, display_path,
            f"Arşiv üyesi {MAX_ARCHIVE_MEMBER_BYTES // (1024 * 1024)} MB güvenlik sınırını aştığı için atlandı.",
        )
        return True
    ratio = declared_size / compressed_size if compressed_size > 0 else 0.0
    if compressed_size > 0 and declared_size >= 1024 * 1024 and ratio > MAX_ARCHIVE_COMPRESSION_RATIO:
        append_archive_notice(
            findings, budget, display_path,
            f"Olağandışı sıkıştırma oranı ({ratio:.0f}:1) nedeniyle zip-bomb koruması üyeyi durdurdu.",
            severity="medium", kind="archive-structure", risk_score=35,
        )
        return True
    if budget.expanded_bytes + declared_size > MAX_ARCHIVE_TOTAL_BYTES:
        append_archive_notice(
            findings, budget, outer_path,
            f"Arşivin toplam açılmış boyutu {MAX_ARCHIVE_TOTAL_BYTES // (1024 * 1024)} MB sınırını aştı; kalan içerik atlandı.",
        )
        return False
    try:
        payload = loader()
    except Exception as error:
        append_archive_notice(
            findings, budget, display_path,
            f"Arşiv üyesi güvenli biçimde okunamadı: {type(error).__name__}.",
        )
        return True
    if not isinstance(payload, bytes) or len(payload) > MAX_ARCHIVE_MEMBER_BYTES:
        append_archive_notice(
            findings, budget, display_path,
            "Arşiv üyesi okuma sırasında boyut sınırını aştığı için atlandı.",
        )
        return True
    budget.expanded_bytes += len(payload)
    findings.extend(inspect_memory_payload(
        display_path, member_name, payload, signatures, yara_rules, exclusions, depth, budget
    ))
    return True


def inspect_zip_bytes(
    outer_path: str, payload: bytes, signatures: dict[int, dict[str, dict[str, Any]]],
    yara_rules: Any | None, exclusions: ExclusionSet, depth: int, budget: ArchiveBudget,
) -> list[Finding]:
    findings: list[Finding] = []
    archive_host = os.environ.get("NEUTRON_ARCHIVE_HOST") or shutil.which("node")
    archive_script = Path(
        os.environ.get("NEUTRON_ARCHIVE_SCRIPT")
        or Path(__file__).resolve().with_name("neutron-archive.cjs")
    )
    if not archive_host or not archive_script.is_file():
        append_archive_notice(
            findings, budget, outer_path,
            "Neutron Archive Engine başlatılamadığı için ZIP içeriği taranamadı.",
        )
        return findings

    environment = os.environ.copy()
    if environment.get("NEUTRON_ARCHIVE_RUN_AS_NODE") == "1":
        environment["ELECTRON_RUN_AS_NODE"] = "1"
    process: subprocess.Popen[bytes] | None = None
    engine_reported_error = False
    try:
        process = subprocess.Popen(
            [archive_host, str(archive_script)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            cwd=str(archive_script.parent),
            env=environment,
            shell=False,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        if process.stdin is None or process.stdout is None:
            raise OSError("archive engine pipe unavailable")
        process.stdin.write(payload)
        process.stdin.close()

        header_seen = False
        for raw_line in process.stdout:
            if len(raw_line) > (MAX_ARCHIVE_MEMBER_BYTES * 2):
                raise ValueError("archive engine record exceeds limit")
            try:
                event = json.loads(raw_line)
            except (UnicodeDecodeError, json.JSONDecodeError):
                raise ValueError("archive engine returned invalid JSON") from None
            if not isinstance(event, dict):
                continue
            event_type = str(event.get("type") or "")
            if event_type == "archive":
                if event.get("protocol") != 1 or event.get("format") != "zip":
                    raise ValueError("archive engine protocol mismatch")
                header_seen = True
                declared_members = int(event.get("members_declared") or 0)
                if declared_members > MAX_ARCHIVE_MEMBERS:
                    append_archive_notice(
                        findings, budget, outer_path,
                        f"Arşiv {MAX_ARCHIVE_MEMBERS} üye güvenlik sınırını aşıyor; fazlası atlandı.",
                    )
                continue
            if event_type == "warning":
                append_archive_notice(
                    findings, budget, outer_path,
                    str(event.get("message") or "Arşiv motoru bir güvenlik sınırına ulaştı."),
                )
                continue
            if event_type == "error":
                engine_reported_error = True
                append_archive_notice(
                    findings, budget, outer_path,
                    f"ZIP arşivi bozuk veya desteklenmeyen yapıda: {event.get('code') or 'archive-error'}.",
                )
                continue
            if event_type != "member" or not header_seen:
                continue

            skipped = str(event.get("skipped") or "")
            encrypted = bool(event.get("encrypted")) or skipped == "encrypted"
            is_link = bool(event.get("is_link")) or skipped == "link"
            data_value = event.get("data")

            def load(encoded: Any = data_value, skipped_reason: str = skipped) -> bytes:
                if skipped_reason:
                    messages = {
                        "member-limit": "archive member exceeds limit",
                        "compression-ratio": "archive compression ratio exceeds limit",
                        "unsupported-method": "unsupported ZIP compression method",
                    }
                    raise ValueError(messages.get(skipped_reason, skipped_reason))
                if not isinstance(encoded, str):
                    raise ValueError("archive member data is missing")
                return base64.b64decode(encoded, validate=True)

            if not inspect_archive_member(
                findings,
                outer_path,
                str(event.get("name") or "isimsiz-üye"),
                int(event.get("declared_size") or 0),
                int(event.get("compressed_size") or 0),
                encrypted,
                is_link,
                load,
                signatures,
                yara_rules,
                exclusions,
                depth,
                budget,
            ):
                break

        return_code = process.wait(timeout=5)
        if not header_seen and not engine_reported_error:
            raise ValueError(f"archive engine stopped before header ({return_code})")
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        append_archive_notice(
            findings, budget, outer_path,
            f"Neutron Archive Engine ZIP içeriğini güvenli biçimde okuyamadı: {type(error).__name__}.",
        )
    finally:
        if process is not None:
            if process.poll() is None:
                process.kill()
            if process.stdout is not None:
                process.stdout.close()
            if process.stdin is not None and not process.stdin.closed:
                process.stdin.close()
    return findings


def inspect_7z_bytes(
    outer_path: str, payload: bytes, signatures: dict[int, dict[str, dict[str, Any]]],
    yara_rules: Any | None, exclusions: ExclusionSet, depth: int, budget: ArchiveBudget,
) -> list[Finding]:
    findings: list[Finding] = []
    append_archive_notice(
        findings, budget, outer_path,
        "7Z içerik taraması Neutron Archive Engine'in sonraki sürümüne ayrıldı; harici program çalıştırılmadı.",
    )
    return findings


def inspect_rar_bytes(
    outer_path: str, payload: bytes, signatures: dict[int, dict[str, dict[str, Any]]],
    yara_rules: Any | None, exclusions: ExclusionSet, depth: int, budget: ArchiveBudget,
) -> list[Finding]:
    findings: list[Finding] = []
    append_archive_notice(
        findings, budget, outer_path,
        "RAR içerik taraması Neutron Archive Engine'in sonraki sürümüne ayrıldı; harici program çalıştırılmadı.",
    )
    return findings


def inspect_archive_bytes(
    outer_path: str,
    suffix: str,
    payload: bytes,
    signatures: dict[int, dict[str, dict[str, Any]]],
    yara_rules: Any | None,
    exclusions: ExclusionSet,
    depth: int = 1,
    budget: ArchiveBudget | None = None,
) -> list[Finding]:
    active_budget = budget or ArchiveBudget()
    if len(payload) > MAX_ARCHIVE_INPUT_BYTES:
        findings: list[Finding] = []
        append_archive_notice(
            findings, active_budget, outer_path,
            f"Arşiv {MAX_ARCHIVE_INPUT_BYTES // (1024 * 1024)} MB giriş sınırını aştığı için içerik taranmadı.",
        )
        return findings
    if suffix == ".zip":
        return inspect_zip_bytes(
            outer_path, payload, signatures, yara_rules, exclusions, depth, active_budget
        )
    if suffix == ".7z":
        return inspect_7z_bytes(
            outer_path, payload, signatures, yara_rules, exclusions, depth, active_budget
        )
    if suffix == ".rar":
        return inspect_rar_bytes(
            outer_path, payload, signatures, yara_rules, exclusions, depth, active_budget
        )
    return []


# Unknown/no-result verdicts are re-checked periodically (a hash absent
# today may be added to a database tomorrow); "malicious" verdicts never
# expire since content doesn't un-become malware.
CLOUD_REPUTATION_CACHE_TTL_HOURS = 24 * 7
MALWAREBAZAAR_API_URL = "https://mb-api.abuse.ch/api/v1/"
CLOUD_LOOKUP_TIMEOUT_SECONDS = 5


def read_cloud_reputation_cache(sha256: str) -> dict[str, Any] | None:
    with open_database() as connection:
        row = connection.execute(
            "SELECT verdict, source, reason, checked_at FROM cloud_reputation_cache WHERE sha256 = ?",
            (sha256,),
        ).fetchone()
    if row is None:
        return None
    verdict, source, reason, checked_at = row
    if verdict != "malicious":
        try:
            checked = datetime.fromisoformat(checked_at)
        except ValueError:
            return None
        if datetime.now(timezone.utc) - checked > timedelta(hours=CLOUD_REPUTATION_CACHE_TTL_HOURS):
            return None
    return {"verdict": verdict, "source": source, "reason": reason}


def write_cloud_reputation_cache(sha256: str, verdict: str, source: str, reason: str | None) -> None:
    checked_at = datetime.now(timezone.utc).isoformat()
    with open_database() as connection:
        connection.execute(
            """INSERT INTO cloud_reputation_cache (sha256, verdict, source, reason, checked_at)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(sha256) DO UPDATE SET
                 verdict = excluded.verdict, source = excluded.source,
                 reason = excluded.reason, checked_at = excluded.checked_at""",
            (sha256, verdict, source, reason, checked_at),
        )


def query_malwarebazaar(sha256: str, api_key: str) -> dict[str, Any] | None:
    """Free but requires a personal Auth-Key since abuse.ch tightened API
    access in 2024 -- get one at https://auth.abuse.ch/, never a key
    embedded in the app (same reasoning as the VirusTotal key below)."""
    import urllib.error
    import urllib.parse
    import urllib.request

    if not api_key:
        return None
    data = urllib.parse.urlencode({"query": "get_info", "hash": sha256}).encode("ascii")
    request = urllib.request.Request(
        MALWAREBAZAAR_API_URL, data=data, method="POST", headers={"Auth-Key": api_key},
    )
    try:
        with urllib.request.urlopen(request, timeout=CLOUD_LOOKUP_TIMEOUT_SECONDS) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return None
    status = payload.get("query_status")
    if status in {"hash_not_found", "no_results"}:
        return {"verdict": "unknown", "source": "malwarebazaar", "reason": None}
    if status != "ok":
        return None
    entries = payload.get("data") or []
    if not entries:
        return {"verdict": "unknown", "source": "malwarebazaar", "reason": None}
    family = entries[0].get("signature") or "bilinmeyen aile"
    return {"verdict": "malicious", "source": "malwarebazaar", "reason": f"MalwareBazaar: {family}"}


def query_virustotal(sha256: str, api_key: str) -> dict[str, Any] | None:
    """Optional secondary lookup, only used if the user supplies their own
    free API key -- never a key embedded in the app, to avoid one shared
    key's rate limit being exhausted by every Neutron install."""
    import urllib.error
    import urllib.request

    request = urllib.request.Request(
        f"https://www.virustotal.com/api/v3/files/{sha256}",
        headers={"x-apikey": api_key},
    )
    try:
        with urllib.request.urlopen(request, timeout=CLOUD_LOOKUP_TIMEOUT_SECONDS) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return None
    stats = payload.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    malicious = int(stats.get("malicious") or 0)
    suspicious = int(stats.get("suspicious") or 0)
    # One noisy engine is a common false positive and is not sufficient for a
    # high-confidence verdict. Require independent agreement before Neutron
    # promotes a hash lookup to a threat finding.
    if malicious < 3 and malicious + suspicious < 4:
        return {"verdict": "unknown", "source": "virustotal", "reason": None}
    return {
        "verdict": "malicious", "source": "virustotal",
        "reason": f"VirusTotal: {malicious} motor kötü amaçlı olarak işaretledi",
    }


def cloud_reputation_lookup(
    sha256: str, malwarebazaar_api_key: str = "", virustotal_api_key: str = "",
) -> dict[str, Any] | None:
    """Consults free public threat-intel APIs by hash only -- file content
    is never uploaded. Both sources require the user's own free API key
    (neither service allows keyless access anymore); if neither key is
    configured this is a no-op. Fails open on any network error: returns
    None, caller treats that as "no cloud data" and never blocks/slows the
    scan on a failed lookup."""
    if not malwarebazaar_api_key and not virustotal_api_key:
        return None
    cached = read_cloud_reputation_cache(sha256)
    if cached is not None:
        return cached

    result = query_malwarebazaar(sha256, malwarebazaar_api_key) if malwarebazaar_api_key else None
    if (result is None or result["verdict"] == "unknown") and virustotal_api_key:
        vt_result = query_virustotal(sha256, virustotal_api_key)
        if vt_result is not None:
            result = vt_result

    if result is None:
        return None  # network failure: don't cache a failure, just retry next time

    write_cloud_reputation_cache(sha256, result["verdict"], result["source"], result.get("reason"))
    return result


# --- Script content analysis ----------------------------------------------
#
# Until now a .ps1/.js/.vbs/.bat was judged by its *name* only: the double
# extension and risk-word checks never opened the file. PE files got entropy,
# imports, signature checks and the models; scripts got nothing. That is
# backwards for how machines actually get infected today -- the mail
# attachment and the pasted one-liner are scripts, and the .exe arrives later
# because a script fetched it.
#
# Same shape as the PE analyser: weighted independent indicators, a floor
# below which nothing is reported, and reasons the user can read.
#
# Calibration note: legitimate admin scripts do download files and do call
# Invoke-WebRequest. So no single indicator can carry a file over the floor --
# the weights are set so that a real detection needs a *chain* (fetch AND
# execute, or obfuscation AND execution), which is what separates a dropper
# from a deployment script.
SCRIPT_EXTENSIONS = {
    ".bat", ".cmd", ".hta", ".js", ".jse", ".ps1", ".psm1",
    ".vbe", ".vbs", ".wsf",
}
MINIMUM_SCRIPT_FINDING_RISK_SCORE = 40
MAX_SCRIPT_ANALYSIS_BYTES = 2 * 1024 * 1024

# (weight, label, patterns). Weights are deliberately modest individually.
SCRIPT_INDICATORS: tuple[tuple[int, str, tuple[str, ...]], ...] = (
    (30, "uzaktan içerik indirme", (
        r"downloadstring", r"downloadfile", r"invoke-webrequest", r"\bwget\b",
        r"\bcurl\b", r"msxml2\.xmlhttp", r"winhttp\.winhttprequest",
        r"certutil\s+.*-urlcache", r"bitsadmin\s+/transfer",
        r"system\.net\.webclient",
    )),
    (30, "indirilen içeriği doğrudan çalıştırma", (
        r"invoke-expression", r"\biex\b", r"\beval\s*\(", r"\bexecute\b",
        r"wscript\.shell", r"shell\.application", r"cmd\s*/c",
        r"start-process", r"\.run\s*\(",
    )),
    (25, "kodlanmış PowerShell komutu", (
        r"-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/]{40,}", r"frombase64string",
        r"encodedcommand",
    )),
    (20, "gizlenmiş/karartılmış kod", (
        r"\[char\]\s*\d+", r"chr\s*\(\s*\d+\s*\)", r"-join\s*\(",
        r"\[convert\]::frombase64", r"\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}",
        r"unescape\s*\(", r"replace\s*\(.{0,20}\).{0,20}replace\s*\(",
    )),
    (20, "güvenlik denetimini atlatma", (
        r"executionpolicy\s+bypass", r"-nop\b", r"-noprofile",
        r"-w(indowstyle)?\s+hidden", r"amsiinitfailed", r"amsiutils",
        r"set-mppreference\s+.*disable", r"add-mppreference\s+.*exclusion",
    )),
    (30, "kalıcılık kurma", (
        r"currentversion\\run", r"schtasks\s+/create",
        r"new-scheduledtask", r"\bsc\s+create\b", r"\\startup\\",
    )),
    (35, "kurtarma/yedek imhası", (
        r"vssadmin\s+delete\s+shadows", r"wbadmin\s+delete",
        r"bcdedit\s+.*recoveryenabled\s+no", r"win32_shadowcopy.*delete",
    )),
    (20, "LOLBin ile dolaylı çalıştırma", (
        r"mshta\s+", r"regsvr32\s+.*/i:", r"rundll32\s+.*javascript:",
        r"\bmsiexec\s+/i\s+http", r"installutil", r"regasm\s+/u",
    )),
)

# Patterns are compiled individually rather than joined into one alternation
# so the number of *distinct* techniques inside a group is known. A script that
# runs vssadmin, wbadmin and bcdedit is far more certainly ransomware than one
# that only runs vssadmin, and collapsing the group to a single boolean threw
# that away.
_SCRIPT_INDICATOR_PATTERNS = tuple(
    (weight, label, tuple(re.compile(pattern, re.IGNORECASE) for pattern in patterns))
    for weight, label, patterns in SCRIPT_INDICATORS
)


def decode_script_text(payload: bytes) -> str:
    """PowerShell files are frequently UTF-16LE with a BOM; decoding those as
    UTF-8 yields NUL-separated bytes that match nothing."""
    if payload[:2] in (b"\xff\xfe", b"\xfe\xff"):
        try:
            return payload.decode("utf-16", errors="ignore")
        except (UnicodeDecodeError, LookupError):
            pass
    # No BOM but heavily NUL-padded: still very likely UTF-16LE.
    if payload[:512].count(0) > len(payload[:512]) // 3:
        try:
            return payload.decode("utf-16-le", errors="ignore")
        except (UnicodeDecodeError, LookupError):
            pass
    return payload.decode("utf-8", errors="ignore")


def analyze_script(path: Path, size: int) -> tuple[int, tuple[str, ...]] | None:
    """Returns (risk_score, reasons) or None when the file cannot be read."""
    if size == 0 or size > MAX_SCRIPT_ANALYSIS_BYTES:
        return None
    try:
        with path.open("rb") as handle:
            payload = handle.read(MAX_SCRIPT_ANALYSIS_BYTES)
    except (OSError, PermissionError):
        return None

    text = decode_script_text(payload)
    if not text:
        return None

    scored: list[tuple[int, str]] = []
    matched_labels: set[str] = set()
    for weight, label, patterns in _SCRIPT_INDICATOR_PATTERNS:
        hits = sum(1 for pattern in patterns if pattern.search(text))
        if not hits:
            continue
        # Extra techniques in the same group add less than the first, so a
        # group can at most double: breadth is evidence, not a multiplier.
        bonus = min(weight, (hits - 1) * max(6, weight // 3))
        scored.append((weight + bonus, label if hits == 1 else f"{label} ({hits} ayrı teknik)"))
        matched_labels.add(label)

    if not scored:
        return None

    score = sum(weight for weight, _label in scored)

    # A fetch that is never executed, or an execution with nothing fetched, is
    # ordinary scripting. The pair is the dropper pattern, so it is worth more
    # than the sum of its parts.
    if {"uzaktan içerik indirme", "indirilen içeriği doğrudan çalıştırma"} <= matched_labels:
        score += 15
        scored.append((15, "indirme ve çalıştırma aynı betikte zincirlenmiş"))

    # Very long unbroken base64/hex runs are not something a person writes.
    if re.search(r"[A-Za-z0-9+/]{600,}={0,2}", text):
        score += 15
        scored.append((15, "betik içinde çok uzun kodlanmış veri bloğu"))

    # A script that already looks suspicious and arrived from the internet is
    # the actual attack shape. Only applied on top of existing evidence, so a
    # downloaded but unremarkable script is not penalised for its origin.
    if scored and file_came_from_internet(path):
        score += 15
        scored.append((15, "betik internetten indirilmiş (Mark-of-the-Web)"))

    score = min(100, score)
    reasons = tuple(reason for _weight, reason in sorted(scored, reverse=True))
    return score, reasons


def script_finding(path: Path, size: int) -> Finding | None:
    result = analyze_script(path, size)
    if result is None:
        return None
    score, reasons = result
    if score < MINIMUM_SCRIPT_FINDING_RISK_SCORE:
        return None
    return Finding(
        path=str(path),
        kind="script-analysis",
        severity="high" if score >= 70 else "medium",
        reason="Betik içeriği şüpheli: " + "; ".join(reasons[:4]),
        risk_score=score,
    )


# --- Mark-of-the-Web -------------------------------------------------------
#
# Windows tags files written by browsers and mail clients with a
# Zone.Identifier alternate data stream. It is the cheapest high-value signal
# available: a script or executable that came from the internet is a different
# proposition from the same file a developer just compiled, and nothing in the
# engine was reading it.
MOTW_INTERNET_ZONES = {"3", "4"}


def file_came_from_internet(path: Path) -> bool:
    if os.name != "nt":
        return False
    try:
        with open(f"{path}:Zone.Identifier", "r", encoding="utf-8", errors="ignore") as stream:
            content = stream.read(4096)
    except (OSError, ValueError):
        return False
    match = re.search(r"ZoneId\s*=\s*(\d)", content)
    return bool(match and match.group(1) in MOTW_INTERNET_ZONES)


# --- Office macro analysis -------------------------------------------------
#
# Macro-bearing documents are the classic mail-attachment vector and the
# engine could not see them at all: a .docm is a zip, so archive scanning
# opened it, but the macro lives in vbaProject.bin, which is OLE rather than
# PE, so every check inside skipped it.
OFFICE_OOXML_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".docx", ".xlsx", ".pptx", ".dotm", ".xltm"}
OFFICE_OLE_EXTENSIONS = {".doc", ".xls", ".ppt", ".dot", ".xlt"}
OLE_CFB_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
MAX_OFFICE_ANALYSIS_BYTES = 16 * 1024 * 1024

# Auto-execution entry points: a macro that runs the moment the document opens,
# with no further click, is the whole point of a maldoc.
OFFICE_AUTOEXEC_PATTERNS = (
    rb"auto_?open", rb"auto_?close", rb"auto_?exec", rb"document_open",
    rb"workbook_open", rb"document_close", rb"workbook_activate",
)
# Things a macro has no business doing in a document.
OFFICE_PAYLOAD_PATTERNS = (
    rb"shell\s*\(", rb"wscript\.shell", rb"createobject", rb"powershell",
    rb"urldownloadtofile", rb"xmlhttp", rb"winhttp", rb"\.run\s*\(",
    rb"process\s*\.\s*create", rb"virtualalloc", rb"rundll32", rb"mshta",
)


def office_macro_evidence(path: Path, size: int) -> tuple[bool, int, int] | None:
    """Returns (has_macro, autoexec_hits, payload_hits) or None if unreadable.

    The VBA project stream is compressed, so this reads the raw container
    bytes rather than decompressing: uncompressed fragments of the macro
    source are reliably present, and a real VBA decompressor is a much larger
    dependency than the signal justifies."""
    if size == 0 or size > MAX_OFFICE_ANALYSIS_BYTES:
        return None
    suffix = path.suffix.casefold()
    try:
        with path.open("rb") as handle:
            header = handle.read(8)
            handle.seek(0)
            payload = handle.read(MAX_OFFICE_ANALYSIS_BYTES)
    except (OSError, PermissionError):
        return None

    has_macro = False
    scanned = payload
    if header.startswith(b"PK\x03\x04") or suffix in OFFICE_OOXML_EXTENSIONS:
        # OOXML: the macro project is a zip member with a fixed name.
        try:
            import io
            import zipfile

            with zipfile.ZipFile(io.BytesIO(payload)) as archive:
                names = archive.namelist()
                macro_members = [
                    name for name in names
                    if name.casefold().endswith("vbaproject.bin")
                    or name.casefold().endswith(".bin") and "vba" in name.casefold()
                ]
                has_macro = bool(macro_members)
                if has_macro:
                    chunks = []
                    for name in macro_members[:4]:
                        try:
                            chunks.append(archive.read(name)[:2 * 1024 * 1024])
                        except (KeyError, OSError, zipfile.BadZipFile, RuntimeError):
                            continue
                    scanned = b"".join(chunks) or payload
        except (zipfile.BadZipFile, OSError, RuntimeError, ValueError):
            return None
    elif header.startswith(OLE_CFB_MAGIC) or suffix in OFFICE_OLE_EXTENSIONS:
        lowered = payload.lower()
        has_macro = b"vba" in lowered and (b"_vba_project" in lowered or b"macros" in lowered)
    else:
        return None

    if not has_macro:
        return False, 0, 0

    lowered = scanned.lower()
    autoexec = sum(1 for pattern in OFFICE_AUTOEXEC_PATTERNS if re.search(pattern, lowered))
    payload_hits = sum(1 for pattern in OFFICE_PAYLOAD_PATTERNS if re.search(pattern, lowered))
    return True, autoexec, payload_hits


def office_finding(path: Path, size: int) -> Finding | None:
    evidence = office_macro_evidence(path, size)
    if evidence is None:
        return None
    has_macro, autoexec, payload_hits = evidence
    if not has_macro:
        return None

    reasons = ["belge gömülü VBA makrosu içeriyor"]
    score = 30
    if autoexec:
        score += 30
        reasons.append(f"makro belge açılır açılmaz çalışacak şekilde bağlanmış ({autoexec} giriş noktası)")
    if payload_hits:
        score += min(35, 12 * payload_hits)
        reasons.append(f"makro içinde komut çalıştırma/indirme çağrıları ({payload_hits} ayrı gösterge)")
    if file_came_from_internet(path):
        score += 15
        reasons.append("dosya internetten indirilmiş (Mark-of-the-Web)")

    score = min(100, score)
    # A macro on its own is common in real business documents; it is the
    # auto-execution and the payload calls that make it a threat.
    if score < 55:
        return None
    return Finding(
        path=str(path),
        kind="document-analysis",
        severity="high" if score >= 75 else "medium",
        reason="Makro içeren belge: " + "; ".join(reasons),
        risk_score=score,
    )


# --- Windows shortcut (.lnk) analysis --------------------------------------
#
# A .lnk carries its own command line, so "double-click the shortcut" runs
# whatever the attacker put in the arguments field -- typically a PowerShell
# one-liner. The file was only ever checked by name.
LNK_MAGIC = b"\x4c\x00\x00\x00"
LNK_GUID = b"\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"


def lnk_command_arguments(path: Path, size: int) -> str | None:
    """Parses the ShellLinkHeader far enough to reach COMMAND_LINE_ARGUMENTS."""
    if size < 76 or size > 4 * 1024 * 1024:
        return None
    try:
        payload = path.read_bytes()
    except (OSError, PermissionError):
        return None
    if not payload.startswith(LNK_MAGIC) or payload[4:20] != LNK_GUID:
        return None

    flags = int.from_bytes(payload[20:24], "little")
    has_target_idlist = bool(flags & 0x01)
    has_link_info = bool(flags & 0x02)
    has_name = bool(flags & 0x04)
    has_relative_path = bool(flags & 0x08)
    has_working_dir = bool(flags & 0x10)
    has_arguments = bool(flags & 0x20)
    is_unicode = bool(flags & 0x80)
    if not has_arguments:
        return None

    offset = 76
    try:
        if has_target_idlist:
            offset += 2 + int.from_bytes(payload[offset:offset + 2], "little")
        if has_link_info:
            offset += max(4, int.from_bytes(payload[offset:offset + 4], "little"))

        def read_string() -> str:
            nonlocal offset
            count = int.from_bytes(payload[offset:offset + 2], "little")
            offset += 2
            width = 2 if is_unicode else 1
            raw = payload[offset:offset + count * width]
            offset += count * width
            return raw.decode("utf-16-le" if is_unicode else "mbcs", errors="ignore")

        for present in (has_name, has_relative_path, has_working_dir):
            if present:
                read_string()
        return read_string()
    except (IndexError, ValueError, UnicodeDecodeError, LookupError):
        return None


def lnk_finding(path: Path, size: int) -> Finding | None:
    arguments = lnk_command_arguments(path, size)
    if not arguments or not arguments.strip():
        return None

    # Reuse the script indicator table: a malicious shortcut's argument string
    # is a script one-liner, so the same evidence applies.
    scored: list[tuple[int, str]] = []
    for weight, label, patterns in _SCRIPT_INDICATOR_PATTERNS:
        hits = sum(1 for pattern in patterns if pattern.search(arguments))
        if hits:
            scored.append((weight + min(weight, (hits - 1) * max(6, weight // 3)), label))
    if not scored:
        return None

    score = min(100, sum(weight for weight, _ in scored))
    # A shortcut invoking an interpreter at all is already unusual.
    if re.search(r"powershell|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32", arguments, re.IGNORECASE):
        score = min(100, score + 20)
        scored.append((20, "kısayol doğrudan bir betik yorumlayıcısı çağırıyor"))
    if score < MINIMUM_SCRIPT_FINDING_RISK_SCORE:
        return None

    reasons = [reason for _weight, reason in sorted(scored, reverse=True)]
    return Finding(
        path=str(path),
        kind="script-analysis",
        severity="high" if score >= 70 else "medium",
        reason="Kısayol gizli komut çalıştırıyor: " + "; ".join(reasons[:3]),
        risk_score=score,
    )


# --- PDF analysis ----------------------------------------------------------
#
# Scored conservatively: forms, embedded files and even JavaScript appear in
# entirely legitimate PDFs, so a single marker is never enough.
PDF_INDICATORS: tuple[tuple[int, str, bytes], ...] = (
    (25, "açılışta otomatik eylem", rb"/OpenAction"),
    (20, "ek otomatik eylem tetikleyicisi", rb"/AA"),
    (25, "gömülü JavaScript", rb"/JavaScript"),
    (15, "JavaScript kısa gösterimi", rb"/JS"),
    (35, "harici program çalıştırma", rb"/Launch"),
    (20, "gömülü dosya", rb"/EmbeddedFile"),
    (20, "uzak kaynak çağrısı", rb"/SubmitForm"),
)


def pdf_finding(path: Path, size: int) -> Finding | None:
    if size == 0 or size > MAX_OFFICE_ANALYSIS_BYTES:
        return None
    try:
        with path.open("rb") as handle:
            payload = handle.read(MAX_OFFICE_ANALYSIS_BYTES)
    except (OSError, PermissionError):
        return None
    if not payload.startswith(b"%PDF"):
        return None

    scored = [(weight, label) for weight, label, marker in PDF_INDICATORS if marker in payload]
    if not scored:
        return None
    score = sum(weight for weight, _ in scored)
    labels = {label for _weight, label in scored}
    if {"açılışta otomatik eylem"} & labels and {"gömülü JavaScript", "JavaScript kısa gösterimi"} & labels:
        score += 20
        scored.append((20, "JavaScript belge açılır açılmaz çalışacak"))
    if file_came_from_internet(path):
        score += 10
        scored.append((10, "dosya internetten indirilmiş (Mark-of-the-Web)"))

    score = min(100, score)
    if score < 55:
        return None
    reasons = [reason for _weight, reason in sorted(scored, reverse=True)]
    return Finding(
        path=str(path),
        kind="document-analysis",
        severity="high" if score >= 75 else "medium",
        reason="PDF etkin içerik taşıyor: " + "; ".join(reasons[:4]),
        risk_score=score,
    )


def inspect_file(
    path: Path,
    signatures: dict[int, dict[str, dict[str, Any]]] | None = None,
    yara_rules: Any | None = None,
    exclusions: ExclusionSet | None = None,
    cloud_lookup: bool = False,
    malwarebazaar_api_key: str = "",
    virustotal_api_key: str = "",
) -> list[Finding]:
    findings: list[Finding] = []
    try:
        size = path.stat().st_size
    except (OSError, PermissionError):
        return findings

    active_exclusions = exclusions or ExclusionSet((), frozenset(), frozenset())
    if is_path_excluded(path, active_exclusions):
        return findings
    digest_value: str | None = None
    digest_loaded = False

    def file_digest() -> str | None:
        nonlocal digest_value, digest_loaded
        if not digest_loaded:
            digest_value = sha256_for(path, size)
            digest_loaded = True
        return digest_value

    if active_exclusions.hashes and file_digest() in active_exclusions.hashes:
        return findings

    suffix = path.suffix.casefold()
    name = path.name.casefold()
    archive_format = suffix if suffix in ARCHIVE_EXTENSIONS else None
    if archive_format is None and size >= 4:
        try:
            with path.open("rb") as stream:
                archive_format = detect_archive_format(path.name, stream.read(8))
        except (OSError, PermissionError):
            archive_format = None
    stem_parts = name.split(".")
    looks_like_double_extension = (
        suffix in EXECUTABLE_EXTENSIONS
        and len(stem_parts) >= 3
        and f".{stem_parts[-2]}" in DOCUMENT_EXTENSIONS
    )
    if looks_like_double_extension:
        findings.append(Finding(
            path=str(path),
            kind="review",
            severity="medium",
            reason="Belge uzantısını taklit eden çalıştırılabilir dosya adı",
            sha256=file_digest(),
            risk_score=45,
        ))

    if suffix in EXECUTABLE_EXTENSIONS and any(word in name for word in RISK_WORDS):
        findings.append(Finding(
            path=str(path),
            kind="review",
            severity="low",
            reason="İnceleme gerektiren dosya adı ve çalıştırılabilir tür",
            sha256=file_digest(),
            risk_score=20,
        ))

    if suffix in {".exe", ".dll", ".scr"}:
        pe_analysis = analyze_pe(path, size)
        structural_finding = pe_finding(path, size, None, analysis=pe_analysis)
        if pe_analysis is not None and pe_analysis.ml_shadow_score is not None:
            try:
                record_ml_shadow_observation(file_digest(), pe_analysis)
            except (OSError, sqlite3.Error, ValueError):
                pass
        if structural_finding is not None:
            structural_finding.sha256 = file_digest()
            findings.append(structural_finding)

    if suffix in SCRIPT_EXTENSIONS:
        content_finding = script_finding(path, size)
        if content_finding is not None:
            content_finding.sha256 = file_digest()
            findings.append(content_finding)

    if suffix == ".lnk":
        shortcut_finding = lnk_finding(path, size)
        if shortcut_finding is not None:
            shortcut_finding.sha256 = file_digest()
            findings.append(shortcut_finding)

    if suffix in OFFICE_OOXML_EXTENSIONS or suffix in OFFICE_OLE_EXTENSIONS:
        macro_finding = office_finding(path, size)
        if macro_finding is not None:
            macro_finding.sha256 = file_digest()
            findings.append(macro_finding)

    if suffix == ".pdf":
        document_finding = pdf_finding(path, size)
        if document_finding is not None:
            document_finding.sha256 = file_digest()
            findings.append(document_finding)

    size_signatures = (signatures or {}).get(size, {})
    if size_signatures:
        digest = file_digest()
        signature = size_signatures.get(digest or "")
        if signature:
            findings.append(Finding(
                path=str(path),
                kind="test-signature" if signature["source"] == "builtin" else "signature",
                severity=str(signature["severity"]),
                reason=f'{signature["name"]} eşleşmesi bulundu',
                sha256=digest,
                risk_score=100,
            ))

    # İçerik taraması yalnız küçük/orta dosyalarda yapılır. Bir eşleşme EICAR
    # test imzasıdır; gerçek kötü amaçlı yazılım tespiti için imza veritabanı
    # sonraki geliştirme aşamasında eklenecektir.
    if size <= MAX_CONTENT_BYTES:
        try:
            with path.open("rb") as stream:
                sample = stream.read(MAX_CONTENT_BYTES)
            # Kaynak kodu veya derlenmiş bytecode içindeki açıklama/metin parçaları
            # yanlış pozitif üretmesin diye EICAR dizgesini bağımsız dosya içeriği
            # olarak doğrularız; alt dizge eşleşmesi yeterli değildir.
            if sample.strip() in {EICAR_MARKER, NEUTRON_QUARANTINE_TEST_MARKER} and not any(
                finding.kind == "test-signature" for finding in findings
            ):
                findings.append(Finding(
                    path=str(path),
                    kind="test-signature",
                    severity="high",
                    reason=(
                        "EICAR güvenli antivirüs test imzası bulundu"
                        if sample.strip() == EICAR_MARKER
                        else "Neutron güvenli otomatik karantina test imzası bulundu"
                    ),
                    sha256=hashlib.sha256(sample).hexdigest(),
                    risk_score=100,
                ))
        except (OSError, PermissionError):
            pass

    if yara_rules is not None and size <= MAX_YARA_BYTES:
        try:
            matches = yara_rules.match(filepath=str(path), timeout=2)
            for match in matches:
                metadata = match.meta or {}
                description = str(metadata.get("description") or match.rule)
                severity = str(metadata.get("severity") or "medium").casefold()
                if severity not in {"low", "medium", "high", "critical"}:
                    severity = "medium"
                findings.append(Finding(
                    path=str(path),
                    kind="yara",
                    severity=severity,
                    reason=f"YARA: {description}",
                    sha256=file_digest(),
                    risk_score={"low": 20, "medium": 40, "high": 70, "critical": 95}[severity],
                ))
        except (OSError, PermissionError, yara.Error):
            pass

    if archive_format:
        if size > MAX_ARCHIVE_INPUT_BYTES:
            findings.append(Finding(
                path=str(path), kind="archive-warning", severity="low",
                reason=f"Arşiv {MAX_ARCHIVE_INPUT_BYTES // (1024 * 1024)} MB giriş sınırını aştığı için içerik taranmadı.",
                sha256=file_digest(), risk_score=0, container_path=str(path),
            ))
        else:
            try:
                with path.open("rb") as stream:
                    archive_payload = stream.read(MAX_ARCHIVE_INPUT_BYTES + 1)
                findings.extend(inspect_archive_bytes(
                    str(path), archive_format, archive_payload, signatures or {}, yara_rules,
                    active_exclusions,
                ))
            except (OSError, PermissionError, MemoryError) as error:
                findings.append(Finding(
                    path=str(path), kind="archive-warning", severity="low",
                    reason=f"Arşiv güvenli biçimde okunamadı: {type(error).__name__}.",
                    sha256=None, risk_score=0, container_path=str(path),
                ))

    # Only consulted when nothing local (signature/EICAR/YARA/archive) has
    # already found something -- a confirmed local hit needs no outside
    # confirmation, and this keeps outbound calls to a minimum.
    if cloud_lookup and not findings and size <= MAX_CONTENT_BYTES:
        digest = file_digest()
        if digest:
            cloud_result = cloud_reputation_lookup(digest, malwarebazaar_api_key, virustotal_api_key)
            if cloud_result is not None and cloud_result["verdict"] == "malicious":
                findings.append(Finding(
                    path=str(path), kind="cloud-reputation", severity="high",
                    reason=cloud_result.get("reason") or "Bulut itibar sorgusunda kötü amaçlı olarak işaretlendi",
                    sha256=digest, risk_score=90,
                ))

    combine_static_risk(findings)
    return findings


def windows_process_image_path(process_id: int) -> str | None:
    """Image path for one PID, without enumerating every process.

    Used on the service control pipe, where a full snapshot per connection
    would be a needless sweep of the machine just to identify one caller.
    """
    if os.name != "nt":
        return None
    from ctypes import wintypes

    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.QueryFullProcessImageNameW.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD),
    ]
    kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL

    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(process_id))
    if not handle:
        return None
    try:
        buffer = ctypes.create_unicode_buffer(32768)
        size = wintypes.DWORD(len(buffer))
        if not kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
            return None
        return buffer.value or None
    finally:
        kernel32.CloseHandle(handle)


def windows_process_snapshot() -> dict[int, str]:
    """Return readable Windows process image paths without admin privileges."""
    if os.name != "nt":
        return {}
    from ctypes import wintypes

    process_ids = (wintypes.DWORD * 8192)()
    bytes_returned = wintypes.DWORD()
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi.EnumProcesses.argtypes = [
        ctypes.POINTER(wintypes.DWORD), wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)
    ]
    psapi.EnumProcesses.restype = wintypes.BOOL
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.QueryFullProcessImageNameW.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)
    ]
    kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    if not psapi.EnumProcesses(
        process_ids, ctypes.sizeof(process_ids), ctypes.byref(bytes_returned)
    ):
        return {}

    result: dict[int, str] = {}
    count = bytes_returned.value // ctypes.sizeof(wintypes.DWORD)
    for process_id in process_ids[:count]:
        if not process_id:
            continue
        handle = kernel32.OpenProcess(0x1000, False, process_id)
        if not handle:
            continue
        try:
            capacity = wintypes.DWORD(32768)
            buffer = ctypes.create_unicode_buffer(capacity.value)
            if kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(capacity)):
                result[int(process_id)] = buffer.value
        finally:
            kernel32.CloseHandle(handle)
    return result


class _ProcessEntry32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", ctypes.c_uint32), ("cntUsage", ctypes.c_uint32),
        ("th32ProcessID", ctypes.c_uint32), ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID", ctypes.c_uint32), ("cntThreads", ctypes.c_uint32),
        ("th32ParentProcessID", ctypes.c_uint32), ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", ctypes.c_uint32), ("szExeFile", ctypes.c_wchar * 260),
    ]


def psapi_process_ids() -> set[int]:
    """Raw PID set from EnumProcesses, with no OpenProcess-based name
    resolution -- see detect_hidden_processes() for why the unfiltered set
    matters (windows_process_snapshot() silently drops PIDs it can't name,
    which would false-positive protected system processes as 'hidden')."""
    if os.name != "nt":
        return set()
    from ctypes import wintypes
    process_ids = (wintypes.DWORD * 8192)()
    bytes_returned = wintypes.DWORD()
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    psapi.EnumProcesses.argtypes = [
        ctypes.POINTER(wintypes.DWORD), wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)
    ]
    psapi.EnumProcesses.restype = wintypes.BOOL
    if not psapi.EnumProcesses(process_ids, ctypes.sizeof(process_ids), ctypes.byref(bytes_returned)):
        return set()
    count = bytes_returned.value // ctypes.sizeof(wintypes.DWORD)
    return {int(pid) for pid in process_ids[:count] if pid}


def toolhelp_process_ids() -> set[int]:
    """Second, independent process enumeration path (CreateToolhelp32Snapshot
    instead of EnumProcesses). A PID visible to one API but not the other is
    a classic sign of user-mode API hooking -- see detect_hidden_processes()."""
    if os.name != "nt":
        return set()
    from ctypes import wintypes
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ProcessEntry32W)]
    kernel32.Process32FirstW.restype = wintypes.BOOL
    kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ProcessEntry32W)]
    kernel32.Process32NextW.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    snapshot = kernel32.CreateToolhelp32Snapshot(0x00000002, 0)  # TH32CS_SNAPPROCESS
    if not snapshot or snapshot in (-1, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF):
        return set()
    try:
        entry = _ProcessEntry32W()
        entry.dwSize = ctypes.sizeof(_ProcessEntry32W)
        if not kernel32.Process32FirstW(snapshot, ctypes.byref(entry)):
            return set()
        pids = {int(entry.th32ProcessID)}
        while kernel32.Process32NextW(snapshot, ctypes.byref(entry)):
            pids.add(int(entry.th32ProcessID))
        return pids
    finally:
        kernel32.CloseHandle(snapshot)


def toolhelp_parent_processes() -> dict[int, int]:
    """Return PID -> parent PID using the same read-only Toolhelp snapshot."""
    if os.name != "nt":
        return {}
    from ctypes import wintypes
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ProcessEntry32W)]
    kernel32.Process32FirstW.restype = wintypes.BOOL
    kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ProcessEntry32W)]
    kernel32.Process32NextW.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    snapshot = kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
    if not snapshot or snapshot in (-1, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF):
        return {}
    result: dict[int, int] = {}
    try:
        entry = _ProcessEntry32W()
        entry.dwSize = ctypes.sizeof(_ProcessEntry32W)
        if not kernel32.Process32FirstW(snapshot, ctypes.byref(entry)):
            return result
        while True:
            result[int(entry.th32ProcessID)] = int(entry.th32ParentProcessID)
            if not kernel32.Process32NextW(snapshot, ctypes.byref(entry)):
                break
        return result
    finally:
        kernel32.CloseHandle(snapshot)


def windows_process_command_line(process_id: int) -> str:
    """Fetch one new process command line on demand; never shells user data."""
    if os.name != "nt" or process_id <= 0:
        return ""
    script = (
        "$p = Get-CimInstance Win32_Process -Filter ('ProcessId = ' + [int]$args[0]) -ErrorAction SilentlyContinue; "
        "if($p){[Console]::Out.Write([string]$p.CommandLine)}"
    )
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script, str(process_id)],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=3,
            check=False, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return result.stdout.strip()[:8192] if result.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def detect_hidden_processes() -> list["Finding"]:
    """Cross-check two independent process-enumeration APIs; a PID the
    snapshot-based Toolhelp32 sees but EnumProcesses doesn't (or vice versa)
    is a classic driver-free rootkit-hiding indicator. Skips the comparison
    entirely if either API call failed outright, to avoid false-flagging
    everything on a transient enumeration error. The two calls aren't
    atomic, so an ordinary process starting/exiting between them looks
    identical to "hidden" for a single sample -- three samples are taken
    and only PIDs hidden in all of them are reported, which a transient
    start/exit race won't survive."""
    samples: list[set[int]] = []
    for attempt in range(3):
        psapi_pids = psapi_process_ids()
        toolhelp_pids = toolhelp_process_ids()
        if not psapi_pids or not toolhelp_pids:
            return []
        samples.append(psapi_pids.symmetric_difference(toolhelp_pids))
        if attempt < 2:
            time.sleep(0.3)
    # PID 0 ("System Idle Process") is a permanent, universal case: Toolhelp32
    # always reports it, EnumProcesses never does -- not a hiding indicator.
    hidden = set.intersection(*samples) - {0}
    if not hidden:
        return []
    # A process whose image is still resolvable AND validly signed is not
    # hiding from anything: protected-process-light and cross-session images
    # (anti-malware services, DRM and browser sandbox helpers) routinely fail
    # to open for one enumeration API while succeeding for the other. Real
    # user-mode hiding leaves nothing legitimately signed behind to find.
    process_paths = windows_process_snapshot()
    findings: list[Finding] = []
    for pid in sorted(hidden):
        raw_path = process_paths.get(pid, "")
        if raw_path and is_trusted_signed_image(Path(raw_path)):
            continue
        findings.append(Finding(
            path=f"pid://{pid}", kind="hidden-process", severity="critical",
            reason=f"PID {pid} yalnızca bir process listeleme API'sinde görünüyor (olası kullanıcı-modu gizleme)",
            sha256=None, risk_score=90,
        ))
    return findings


def active_tcp_connections() -> list[tuple[int, str, int]]:
    """Enumerate active IPv4 TCP connections as (pid, remote_ip, remote_port)
    via iphlpapi's GetExtendedTcpTable. No admin privileges required. This
    is the driver-free approximation of network visibility: a poll-based
    snapshot, not packet inspection -- see watch_network() for context."""
    if os.name != "nt":
        return []
    from ctypes import wintypes

    AF_INET = 2
    TCP_TABLE_OWNER_PID_ALL = 5
    ERROR_INSUFFICIENT_BUFFER = 122

    class MibTcpRowOwnerPid(ctypes.Structure):
        _fields_ = [
            ("dwState", wintypes.DWORD),
            ("dwLocalAddr", wintypes.DWORD),
            ("dwLocalPort", wintypes.DWORD),
            ("dwRemoteAddr", wintypes.DWORD),
            ("dwRemotePort", wintypes.DWORD),
            ("dwOwningPid", wintypes.DWORD),
        ]

    iphlpapi = ctypes.WinDLL("iphlpapi", use_last_error=True)
    iphlpapi.GetExtendedTcpTable.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD), wintypes.BOOL,
        wintypes.ULONG, ctypes.c_int, wintypes.ULONG,
    ]
    iphlpapi.GetExtendedTcpTable.restype = wintypes.DWORD

    size = wintypes.DWORD(0)
    status = iphlpapi.GetExtendedTcpTable(
        None, ctypes.byref(size), False, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0
    )
    if status != ERROR_INSUFFICIENT_BUFFER or size.value == 0:
        return []
    buffer = ctypes.create_string_buffer(size.value)
    status = iphlpapi.GetExtendedTcpTable(
        buffer, ctypes.byref(size), False, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0
    )
    if status != 0:
        return []

    entry_count = ctypes.cast(buffer, ctypes.POINTER(wintypes.DWORD))[0]
    row_size = ctypes.sizeof(MibTcpRowOwnerPid)
    rows_offset = ctypes.sizeof(wintypes.DWORD)

    connections: list[tuple[int, str, int]] = []
    for index in range(entry_count):
        offset = rows_offset + index * row_size
        if offset + row_size > len(buffer.raw):
            break
        row = MibTcpRowOwnerPid.from_buffer_copy(buffer.raw[offset:offset + row_size])
        if row.dwRemoteAddr == 0:
            continue
        remote_ip = socket.inet_ntoa(struct.pack("<L", row.dwRemoteAddr))
        remote_port = socket.ntohs(row.dwRemotePort & 0xFFFF)
        connections.append((int(row.dwOwningPid), remote_ip, int(remote_port)))
    return connections


def enable_debug_privilege() -> None:
    """Best-effort SeDebugPrivilege enable so process-memory reads below
    can reach processes outside the caller's own session (other users,
    higher-integrity levels). Silently does nothing if not available --
    running unprivileged just means rwx_private_region_count()/YARA
    memory scans only succeed for same-privilege processes, same
    limitation windows_process_snapshot() already has."""
    if os.name != "nt":
        return
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    class LUID(ctypes.Structure):
        _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]

    class LUID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]

    class TOKEN_PRIVILEGES(ctypes.Structure):
        _fields_ = [("PrivilegeCount", wintypes.DWORD), ("Privileges", LUID_AND_ATTRIBUTES * 1)]

    TOKEN_ADJUST_PRIVILEGES = 0x0020
    TOKEN_QUERY = 0x0008
    SE_PRIVILEGE_ENABLED = 0x00000002

    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ctypes.byref(token)
    ):
        return
    try:
        luid = LUID()
        if not advapi32.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(luid)):
            return
        privileges = TOKEN_PRIVILEGES()
        privileges.PrivilegeCount = 1
        privileges.Privileges[0].Luid = luid
        privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
        advapi32.AdjustTokenPrivileges(token, False, ctypes.byref(privileges), 0, None, None)
    finally:
        kernel32.CloseHandle(token)


def rwx_private_region_count(pid: int) -> int:
    """Counts committed, private (not file/module-backed), read+write+
    execute memory regions in a process -- a classic process-hollowing /
    shellcode-injection indicator, since legitimately loaded code is
    backed by a mapped module, not raw private memory. Not proof by
    itself (JIT engines in browsers/.NET/Java legitimately allocate RWX),
    which is why callers treat a nonzero count as "worth a closer look",
    not an automatic verdict."""
    if os.name != "nt":
        return 0
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_READ = 0x0010
    MEM_COMMIT = 0x1000
    MEM_PRIVATE = 0x20000
    PAGE_EXECUTE_READWRITE = 0x40

    class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BaseAddress", ctypes.c_void_p),
            ("AllocationBase", ctypes.c_void_p),
            ("AllocationProtect", wintypes.DWORD),
            ("RegionSize", ctypes.c_size_t),
            ("State", wintypes.DWORD),
            ("Protect", wintypes.DWORD),
            ("Type", wintypes.DWORD),
        ]

    kernel32.VirtualQueryEx.argtypes = [
        wintypes.HANDLE, ctypes.c_void_p, ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t,
    ]
    kernel32.VirtualQueryEx.restype = ctypes.c_size_t

    handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not handle:
        return 0
    try:
        count = 0
        address = 0
        mbi = MEMORY_BASIC_INFORMATION()
        scanned_regions = 0
        while scanned_regions < 20_000:  # bounded: never hang on a pathological address space
            written = kernel32.VirtualQueryEx(handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi))
            if written == 0:
                break
            scanned_regions += 1
            if mbi.State == MEM_COMMIT and mbi.Type == MEM_PRIVATE and mbi.Protect == PAGE_EXECUTE_READWRITE:
                count += 1
            next_address = (mbi.BaseAddress or 0) + mbi.RegionSize
            if next_address <= address:
                break
            address = next_address
        return count
    finally:
        kernel32.CloseHandle(handle)


def neutron_owned_roots() -> tuple[Path, ...]:
    """Return roots that are cryptographically scoped by this running build.

    A packaged engine is below ``resources/runtime/engine/<arch>``. Walking
    upward to the first directory containing the sibling Neutron.exe finds
    the exact install root without trusting a process name. Development mode
    is anchored by this source file plus the repository's package.json.
    """
    candidates: list[Path] = []
    try:
        executable = Path(sys.executable).resolve()
        for parent in executable.parents:
            if (parent / "Neutron.exe").is_file():
                candidates.append(parent)
                break
    except (OSError, RuntimeError):
        pass

    try:
        source_root = Path(__file__).resolve().parent.parent
        if (source_root / "package.json").is_file() and (source_root / "src" / "main.cjs").is_file():
            candidates.append(source_root)
    except (OSError, RuntimeError):
        pass

    unique: dict[str, Path] = {}
    for candidate in candidates:
        unique[os.path.normcase(str(candidate))] = candidate
    return tuple(unique.values())


def is_neutron_owned_process_path(raw_path: str | Path, roots: tuple[Path, ...] | None = None) -> bool:
    """True only for an executable inside this Neutron build's exact root."""
    try:
        candidate = Path(raw_path).resolve()
    except (OSError, RuntimeError, ValueError):
        return False
    for root in roots if roots is not None else neutron_owned_roots():
        try:
            candidate.relative_to(root)
            return True
        except ValueError:
            continue
    return False


def is_neutron_process_or_descendant(
    pid: int,
    processes: dict[int, str],
    parents: dict[int, int],
    roots: tuple[Path, ...] | None = None,
) -> bool:
    """Recognize Neutron helpers by a bounded parent chain, not by filename."""
    active_roots = roots if roots is not None else neutron_owned_roots()
    current = int(pid)
    visited: set[int] = set()
    for _depth in range(16):
        if current <= 0 or current in visited:
            return False
        visited.add(current)
        raw_path = processes.get(current)
        if raw_path and is_neutron_owned_process_path(raw_path, active_roots):
            return True
        current = int(parents.get(current, 0) or 0)
    return False


# How many private RWX regions a process must hold before that fact alone is
# worth reporting. The original 3 was chosen from the injection side of the
# problem without measuring the benign side, and it fired on essentially every
# JIT-hosting process on a normal desktop. Raising it does not weaken
# injection detection meaningfully -- shellcode loaders allocate RWX, but so
# does the browser they inject into, so the count was never the discriminator.
# The signing check in watch_memory() is what actually separates the two.
MEMORY_RWX_REPORT_THRESHOLD = 12


def watch_memory() -> int:
    """Runs as a service_host() thread: on each newly-started process
    (same new-process detection approach as watch_behavior(), kept as its
    own independent loop rather than modified into watch_behavior()
    itself to avoid touching an already-working function), scans that
    process's memory with the existing YARA rule set and flags a high
    private-RWX-region count. Reactive, not preventive -- by the time a
    process is scanned it has already started; there is no blocking here,
    only detection. Full visibility (other users' / higher-integrity
    processes) needs SeDebugPrivilege, only reliably available when this
    runs inside the LocalSystem service, not a plain user session."""
    if os.name != "nt":
        emit("memory-error", code="UNSUPPORTED_PLATFORM", message="Bellek taraması yalnız Windows'ta kullanılabilir.")
        return 2

    enable_debug_privilege()
    yara_rules, yara_status = load_yara_rules()
    exclusions = load_exclusion_set()
    own_roots = neutron_owned_roots()
    processes = windows_process_snapshot()
    parents = toolhelp_parent_processes()
    alerted_hidden: set[int] = set()
    emit("memory-ready", backend="windows-native", process_count=len(processes), yara=yara_status)

    try:
        while True:
            time.sleep(BEHAVIOR_INTERVAL_SECONDS)
            for finding in detect_hidden_processes():
                pid = int(finding.path.removeprefix("pid://"))
                if pid in alerted_hidden:
                    continue
                alerted_hidden.add(pid)
                try:
                    event_id = save_protection_event("memory-scan", finding)
                except (OSError, sqlite3.Error):
                    event_id = None
                emit("memory-finding", event_id=event_id, process_id=pid, file_name=f"PID {pid}", finding=asdict(finding))
            current_processes = windows_process_snapshot()
            current_parents = toolhelp_parent_processes()
            process_paths = {**processes, **current_processes}
            parent_links = {**parents, **current_parents}
            for pid, raw_path in current_processes.items():
                if pid in processes:
                    continue
                image_path = Path(raw_path)
                if pid == os.getpid() or is_neutron_process_or_descendant(
                    pid, process_paths, parent_links, own_roots,
                ):
                    continue
                if is_path_excluded(image_path, exclusions):
                    continue

                yara_hits: list[str] = []
                if yara_rules is not None:
                    try:
                        for match in yara_rules.match(pid=pid, timeout=2):
                            metadata = match.meta or {}
                            yara_hits.append(str(metadata.get("description") or match.rule))
                    except Exception:  # noqa: BLE001 -- a process can exit/deny access mid-scan
                        pass

                # A YARA hit in live memory is a targeted malware signature and
                # is reported whatever the file's signing status says -- signed
                # malware exists, and a stolen certificate must not buy silence.
                #
                # An RWX region count on its own is the opposite: weak, purely
                # structural evidence that legitimate JIT compilers produce by
                # design. It is therefore gated on the image NOT being validly
                # signed, and on a much higher count than the original 3, which
                # every Chromium tab, .NET app and JVM on the machine cleared.
                rwx_count = rwx_private_region_count(pid)
                rwx_alone_reportable = (
                    rwx_count >= MEMORY_RWX_REPORT_THRESHOLD
                    and not is_trusted_signed_image(image_path)
                )
                if not yara_hits and not rwx_alone_reportable:
                    continue

                severity = "critical" if yara_hits else "medium"
                reason_parts = []
                if yara_hits:
                    reason_parts.append(f"YARA belleği eşleşmesi: {', '.join(yara_hits[:3])}")
                if rwx_alone_reportable or (yara_hits and rwx_count >= MEMORY_RWX_REPORT_THRESHOLD):
                    reason_parts.append(f"{rwx_count} adet şüpheli RWX özel bellek bölgesi (process hollowing/injection izi olabilir)")
                finding = Finding(
                    path=str(image_path), kind="memory-injection", severity=severity,
                    reason=f"{image_path.name}: " + "; ".join(reason_parts),
                    sha256=None,
                )
                try:
                    event_id = save_protection_event("memory-scan", finding)
                except (OSError, sqlite3.Error):
                    event_id = None
                emit("memory-finding", event_id=event_id, process_id=pid, file_name=image_path.name, finding=asdict(finding))
            processes = current_processes
            parents = current_parents
    except KeyboardInterrupt:
        emit("memory-stopped")
        return 0


AUTORUN_REGISTRY_LOCATIONS = (
    (winreg.HKEY_CURRENT_USER, "HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run") if winreg else None,
    (winreg.HKEY_CURRENT_USER, "HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce") if winreg else None,
    (winreg.HKEY_LOCAL_MACHINE, "HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run") if winreg else None,
    (winreg.HKEY_LOCAL_MACHINE, "HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunOnce") if winreg else None,
)


def registry_wow64_views() -> list[int]:
    views = [0]
    if winreg is None:
        return views
    for view_name in ("KEY_WOW64_64KEY", "KEY_WOW64_32KEY"):
        view = getattr(winreg, view_name, 0)
        if view and view not in views:
            views.append(view)
    return views


def autorun_startup_directories() -> list[Path]:
    directories = []
    app_data = os.environ.get("APPDATA")
    program_data = os.environ.get("ProgramData")
    if app_data:
        directories.append(Path(app_data) / "Microsoft/Windows/Start Menu/Programs/Startup")
    if program_data:
        directories.append(Path(program_data) / "Microsoft/Windows/Start Menu/Programs/StartUp")
    return directories


def command_line_executable(value: str) -> Path | None:
    """Best-effort extraction of the program a Run-key command line invokes.

    Handles the two shapes Windows actually stores: a quoted path followed by
    arguments, and a bare path where the arguments start at the first switch.
    Returns None rather than guessing when neither yields an existing file --
    callers use this to *suppress* a finding, so an unparseable value must
    fall through to being reported, not silently trusted.
    """
    text = (value or "").strip()
    if not text:
        return None
    if text.startswith('"'):
        closing = text.find('"', 1)
        candidates = [text[1:closing] if closing > 1 else text[1:]]
    else:
        # An unquoted path containing spaces is genuinely ambiguous, so try
        # the whole string first and then each cut at a switch marker,
        # keeping the first candidate that names a real file.
        candidates = [text]
        for marker in (" /", " -"):
            index = text.find(marker)
            while index > 0:
                candidates.append(text[:index])
                index = text.find(marker, index + 1)
    for candidate in candidates:
        try:
            resolved = Path(os.path.expandvars(candidate.strip()))
        except (OSError, RuntimeError, ValueError):
            continue
        try:
            if resolved.is_file():
                return resolved
        except (OSError, ValueError):
            continue
    return None


def persistence_snapshot() -> dict[str, str]:
    """Read common Windows Run keys and Startup folders without modifying them."""
    if os.name != "nt":
        return {}
    snapshot: dict[str, str] = {}
    if winreg is not None:
        views = registry_wow64_views()
        for hive, hive_name, key_path in AUTORUN_REGISTRY_LOCATIONS:
            for view in views:
                try:
                    with winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ | view) as key:
                        index = 0
                        while True:
                            try:
                                name, value, _value_type = winreg.EnumValue(key, index)
                            except OSError:
                                break
                            identity = f"registry://{hive_name}/{key_path}/{view}/{name}"
                            snapshot[identity] = str(value)
                            index += 1
                except (OSError, PermissionError):
                    continue

    for directory in autorun_startup_directories():
        try:
            for entry in directory.iterdir():
                if not entry.is_file() or entry.is_symlink():
                    continue
                stat = entry.stat()
                snapshot[f"startup://{entry}"] = f"{stat.st_mtime_ns}:{stat.st_size}"
        except (OSError, PermissionError):
            continue
    return snapshot


def startup_entries() -> list[dict[str, Any]]:
    """Structured (name/command/location) version of persistence_snapshot(),
    for a human-facing Startup Manager rather than watch_behavior()'s diff."""
    if os.name != "nt":
        return []
    items: list[dict[str, Any]] = []
    if winreg is not None:
        views = registry_wow64_views()
        for hive, hive_name, key_path in AUTORUN_REGISTRY_LOCATIONS:
            for view in views:
                try:
                    with winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ | view) as key:
                        index = 0
                        while True:
                            try:
                                name, value, _value_type = winreg.EnumValue(key, index)
                            except OSError:
                                break
                            items.append({
                                "source": "registry", "hive": hive_name, "key_path": key_path,
                                "view": view, "value_name": name, "command": str(value),
                            })
                            index += 1
                except (OSError, PermissionError):
                    continue

    for directory in autorun_startup_directories():
        try:
            for entry in directory.iterdir():
                if not entry.is_file() or entry.is_symlink():
                    continue
                items.append({
                    "source": "startup-folder", "hive": None, "key_path": str(directory),
                    "view": 0, "value_name": entry.name, "command": str(entry),
                })
        except (OSError, PermissionError):
            continue
    return items


# --- Vulnerable/outdated software scanner -----------------------------------
# Read-only: enumerates installed programs via the Uninstall registry keys
# (same winreg/hive/WOW64-view idiom as AUTORUN_REGISTRY_LOCATIONS above) and
# flags known-vulnerable version ranges. Honest scope note: VULNERABLE_
# SOFTWARE_SEED is a small hand-curated starter list to prove the mechanism,
# not a real CVE feed -- broad coverage would need a Proton-distributed
# category (additive to the existing payload schema, see plan.md), which is
# a separate, larger content-curation effort not done here.
UNINSTALL_REGISTRY_LOCATIONS = (
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Uninstall") if winreg else None,
    (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall") if winreg else None,
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Uninstall") if winreg else None,
)

VULNERABLE_SOFTWARE_SEED: tuple[dict[str, str], ...] = (
    {"name_pattern": "winrar", "max_safe_version": "6.22", "severity": "high",
     "note": "WinRAR 6.23 öncesi sürümlerde uzaktan kod çalıştırmaya izin veren bilinen bir açık var (CVE-2023-40477)."},
    {"name_pattern": "putty", "max_safe_version": "0.80", "severity": "high",
     "note": "PuTTY 0.81 öncesi sürümlerde özel anahtarın kurtarılabildiği bilinen bir açık var (CVE-2024-31497)."},
    {"name_pattern": "7-zip", "max_safe_version": "21.06", "severity": "medium",
     "note": "7-Zip 21.07 öncesi sürümlerde bilinen güvenlik açıkları var, güncel sürüme geçilmesi önerilir."},
)


def parse_version_tuple(value: str) -> tuple[int, ...]:
    parts: list[int] = []
    for chunk in re.split(r"[.\-_]", str(value)):
        match = re.match(r"\d+", chunk)
        if not match:
            break
        parts.append(int(match.group()))
    return tuple(parts) if parts else (0,)


def version_at_most(version: str, max_safe_version: str) -> bool:
    """True if `version` is at or below the last known-vulnerable version
    (still needs updating)."""
    return parse_version_tuple(version) <= parse_version_tuple(max_safe_version)


def installed_software_snapshot() -> list[dict[str, str]]:
    if os.name != "nt" or winreg is None:
        return []
    items: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for hive, key_path in UNINSTALL_REGISTRY_LOCATIONS:
        for view in registry_wow64_views():
            try:
                with winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ | view) as root:
                    index = 0
                    while True:
                        try:
                            subkey_name = winreg.EnumKey(root, index)
                        except OSError:
                            break
                        index += 1
                        try:
                            with winreg.OpenKey(root, subkey_name, 0, winreg.KEY_READ) as subkey:
                                try:
                                    name = str(winreg.QueryValueEx(subkey, "DisplayName")[0])
                                except OSError:
                                    continue
                                try:
                                    version = str(winreg.QueryValueEx(subkey, "DisplayVersion")[0])
                                except OSError:
                                    version = ""
                                try:
                                    publisher = str(winreg.QueryValueEx(subkey, "Publisher")[0])
                                except OSError:
                                    publisher = ""
                                try:
                                    is_component = int(winreg.QueryValueEx(subkey, "SystemComponent")[0])
                                except OSError:
                                    is_component = 0
                        except OSError:
                            continue
                        if not name or is_component:
                            continue
                        dedupe_key = (name.casefold(), version)
                        if dedupe_key in seen:
                            continue
                        seen.add(dedupe_key)
                        items.append({"name": name, "version": version, "publisher": publisher})
            except (OSError, PermissionError):
                continue
    return items


def check_vulnerable_software() -> int:
    findings = []
    for software in installed_software_snapshot():
        if not software["version"]:
            continue
        name_cf = software["name"].casefold()
        for seed in VULNERABLE_SOFTWARE_SEED:
            if seed["name_pattern"] not in name_cf:
                continue
            if version_at_most(software["version"], seed["max_safe_version"]):
                findings.append({
                    "name": software["name"], "version": software["version"],
                    "publisher": software["publisher"], "severity": seed["severity"], "note": seed["note"],
                })
            break
    emit("vulnerable-software", items=findings)
    return 0


# --- Windows security posture audit -----------------------------------------
# Read-only checks of the machine's own hardening settings. Everything here is
# a registry read through winreg -- no PowerShell, no WMI, no subprocess -- so
# the audit is fast, cannot be blocked by execution policy, and cannot take a
# host process down with it. A setting that cannot be read reports "unknown"
# rather than being silently scored as a pass: an audit that hides what it
# could not see is worse than one that admits it.
AUDIT_PASS = "pass"
AUDIT_WARN = "warn"
AUDIT_CRITICAL = "critical"
AUDIT_UNKNOWN = "unknown"


def read_registry_value(hive: int, key_path: str, value_name: str) -> Any:
    """Returns the value, or None when the key/value is absent or unreadable.
    Absent is not an error: most of these settings only exist once someone has
    changed them away from the Windows default."""
    if os.name != "nt" or winreg is None:
        return None
    for view in registry_wow64_views():
        try:
            with winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ | view) as key:
                return winreg.QueryValueEx(key, value_name)[0]
        except OSError:
            continue
    return None


def registry_int(hive: int, key_path: str, value_name: str, default: int | None = None) -> int | None:
    raw = read_registry_value(hive, key_path, value_name)
    if raw is None:
        return default
    try:
        return int(raw)
    except (TypeError, ValueError):
        return default


def audit_check(
    check_id: str, title: str, status: str, detail: str, *, weight: int = 1, remedy: str = "",
    fix: str = "",
) -> dict[str, Any]:
    # `fix` names an entry in main.cjs's AUDIT_FIXES table. The engine never
    # applies a fix itself: it only reads the registry, so a compromised or
    # buggy engine process cannot change machine state. Empty means the
    # finding has no safe one-click remedy and the text stays advisory.
    return {
        "id": check_id, "title": title, "status": status,
        "detail": detail, "weight": weight, "remedy": remedy, "fix": fix,
    }


def audit_defender_realtime() -> dict[str, Any]:
    policy_off = registry_int(
        winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiSpyware")
    realtime_off = registry_int(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring")
    if policy_off == 1:
        return audit_check(
            "defender", "Microsoft Defender", AUDIT_CRITICAL,
            "Defender bir grup ilkesiyle tamamen kapatılmış.", weight=3,
            remedy="HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\DisableAntiSpyware ilkesini kaldır.",
            fix="defender_policy")
    if realtime_off == 1:
        return audit_check(
            "defender", "Microsoft Defender", AUDIT_WARN,
            "Defender'ın gerçek zamanlı koruması kapalı. Neutron'un dosya koruması bunun yerini "
            "tam olarak tutmaz; ikisi birlikte çalışacak biçimde tasarlandı.", weight=3,
            remedy="Windows Güvenliği > Virüs ve tehdit koruması ayarlarından gerçek zamanlı korumayı aç.",
            fix="defender_realtime")
    return audit_check(
        "defender", "Microsoft Defender", AUDIT_PASS,
        "Gerçek zamanlı koruma kapatılmış görünmüyor. Kayıtlı başka bir antivirüs varsa Defender'ın "
        "kendi isteğiyle pasif moda geçmiş olması normaldir.", weight=3)


def audit_firewall() -> dict[str, Any]:
    base = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"
    profiles = (("Etki alanı", "DomainProfile"), ("Özel", "StandardProfile"), ("Genel", "PublicProfile"))
    # An absent EnableFirewall value means "never configured", and the
    # Windows default for that is on -- so the default here is 1, not None.
    disabled = [
        label for label, key in profiles
        if registry_int(winreg.HKEY_LOCAL_MACHINE, f"{base}\\{key}", "EnableFirewall", default=1) == 0
    ]
    if disabled:
        return audit_check(
            "firewall", "Windows Güvenlik Duvarı", AUDIT_CRITICAL,
            f"Kapalı profiller: {', '.join(disabled)}.", weight=3,
            remedy="Windows Güvenliği > Güvenlik duvarı ve ağ koruması bölümünden ilgili profili aç.",
            fix="firewall_enable")
    return audit_check(
        "firewall", "Windows Güvenlik Duvarı", AUDIT_PASS,
        "Etki alanı, özel ve genel profillerin üçü de açık.", weight=3)


def audit_uac() -> dict[str, Any]:
    policy_key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    enable_lua = registry_int(winreg.HKEY_LOCAL_MACHINE, policy_key, "EnableLUA", default=1)
    consent = registry_int(winreg.HKEY_LOCAL_MACHINE, policy_key, "ConsentPromptBehaviorAdmin", default=5)
    secure_desktop = registry_int(winreg.HKEY_LOCAL_MACHINE, policy_key, "PromptOnSecureDesktop", default=1)
    if enable_lua == 0:
        return audit_check(
            "uac", "Kullanıcı Hesabı Denetimi (UAC)", AUDIT_CRITICAL,
            "UAC tamamen kapalı. Her yönetici süreci sormadan tam yetkiyle çalışır.", weight=3,
            remedy="Denetim Masası > Kullanıcı Hesapları > Kullanıcı Hesabı Denetimi ayarlarını varsayılana getir.",
            fix="uac_enable_lua")
    if consent == 0:
        return audit_check(
            "uac", "Kullanıcı Hesabı Denetimi (UAC)", AUDIT_WARN,
            "UAC açık ama yöneticiler için hiç onay istenmiyor (yükseltme sessizce veriliyor).", weight=2,
            remedy="UAC bildirim seviyesini en az \"Yalnızca uygulamalar değişiklik yapmaya çalıştığında\" yap.",
            fix="uac_consent")
    if secure_desktop == 0:
        return audit_check(
            "uac", "Kullanıcı Hesabı Denetimi (UAC)", AUDIT_WARN,
            "UAC istemi güvenli masaüstünde gösterilmiyor; istem taklit edilebilir.", weight=2,
            remedy="PromptOnSecureDesktop değerini 1 yap.", fix="uac_secure_desktop")
    return audit_check(
        "uac", "Kullanıcı Hesabı Denetimi (UAC)", AUDIT_PASS,
        "UAC açık ve yükseltme istemi güvenli masaüstünde gösteriliyor.", weight=3)


def audit_lsa_protection() -> dict[str, Any]:
    run_as_ppl = registry_int(
        winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL")
    if run_as_ppl in (1, 2):
        return audit_check(
            "lsa", "LSA korumalı süreç", AUDIT_PASS,
            "lsass.exe korumalı süreç olarak çalışıyor; oturum parolalarının bellekten çekilmesi zorlaşır.",
            weight=2)
    return audit_check(
        "lsa", "LSA korumalı süreç", AUDIT_WARN,
        "lsass.exe korumalı süreç olarak çalışmıyor. Yönetici yetkisi ele geçiren bir saldırgan "
        "oturum kimlik bilgilerini bellekten okuyabilir.", weight=2,
        remedy="HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RunAsPPL değerini 1 yapıp yeniden başlat.",
        fix="lsa_runasppl")


def audit_smb1() -> dict[str, Any]:
    server_smb1 = registry_int(
        winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1")
    client_start = registry_int(
        winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\mrxsmb10", "Start")
    server_on = server_smb1 == 1
    client_on = client_start is not None and client_start != 4
    if server_on or client_on:
        sides = []
        if server_on:
            sides.append("sunucu")
        if client_on:
            sides.append("istemci")
        return audit_check(
            "smb1", "SMBv1 protokolü", AUDIT_WARN,
            f"SMBv1 hâlâ etkin ({', '.join(sides)}). WannaCry sınıfı solucanların yayılma yolu budur.",
            weight=2,
            remedy="Windows Özellikleri'nden \"SMB 1.0/CIFS Dosya Paylaşımı Desteği\"ni kaldır.",
            fix="smb1_disable")
    return audit_check(
        "smb1", "SMBv1 protokolü", AUDIT_PASS, "SMBv1 devre dışı.", weight=2)


def audit_remote_desktop() -> dict[str, Any]:
    deny = registry_int(
        winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Terminal Server",
        "fDenyTSConnections", default=1)
    if deny != 0:
        return audit_check(
            "rdp", "Uzak Masaüstü", AUDIT_PASS, "Uzak Masaüstü bağlantıları kapalı.", weight=2)
    nla = registry_int(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
        "UserAuthentication", default=1)
    if nla != 1:
        return audit_check(
            "rdp", "Uzak Masaüstü", AUDIT_CRITICAL,
            "Uzak Masaüstü açık ve Ağ Düzeyinde Kimlik Doğrulama (NLA) kapalı: oturum açmadan önce "
            "kimlik doğrulanmıyor.", weight=2,
            remedy="Sistem > Uzak Masaüstü ayarlarında NLA'yı zorunlu kıl, ya da RDP'yi kapat.",
            fix="rdp_nla")
    return audit_check(
        "rdp", "Uzak Masaüstü", AUDIT_WARN,
        "Uzak Masaüstü açık (NLA etkin). Bu makineye dışarıdan bağlanmıyorsan kapatılması önerilir.",
        weight=2, remedy="Kullanmıyorsan Sistem > Uzak Masaüstü'nü kapat.", fix="rdp_disable")


def audit_auto_logon() -> dict[str, Any]:
    winlogon = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    auto_logon = read_registry_value(winreg.HKEY_LOCAL_MACHINE, winlogon, "AutoAdminLogon")
    stored_password = read_registry_value(winreg.HKEY_LOCAL_MACHINE, winlogon, "DefaultPassword")
    if str(auto_logon or "0").strip() == "1":
        if stored_password:
            return audit_check(
                "autologon", "Otomatik oturum açma", AUDIT_CRITICAL,
                "Otomatik oturum açma açık ve parola kayıt defterinde düz metin olarak duruyor.",
                weight=3,
                remedy="netplwiz ile otomatik oturum açmayı kapat ve Winlogon\\DefaultPassword değerini sil.",
                fix="autologon_disable")
        return audit_check(
            "autologon", "Otomatik oturum açma", AUDIT_WARN,
            "Otomatik oturum açma açık: bilgisayarı açan herkes parola girmeden oturuma düşer.",
            weight=3, remedy="netplwiz ile otomatik oturum açmayı kapat.", fix="autologon_disable")
    return audit_check(
        "autologon", "Otomatik oturum açma", AUDIT_PASS,
        "Oturum açmak için kimlik doğrulama gerekiyor.", weight=3)


def audit_windows_update() -> dict[str, Any]:
    no_auto = registry_int(
        winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "NoAutoUpdate")
    if no_auto == 1:
        return audit_check(
            "windows_update", "Windows Update", AUDIT_WARN,
            "Otomatik güncelleme bir ilkeyle kapatılmış. Yamalanmamış Windows açıkları en yaygın "
            "bulaşma yoludur.", weight=2,
            remedy="WindowsUpdate\\AU\\NoAutoUpdate ilkesini kaldır ve bekleyen güncellemeleri kur.",
            fix="windows_update_enable")
    return audit_check(
        "windows_update", "Windows Update", AUDIT_PASS,
        "Otomatik güncelleme kapatılmış görünmüyor.", weight=2)


def audit_autorun() -> dict[str, Any]:
    # 0xFF disables AutoRun on every drive type; 0x91 is the Windows default
    # (still autoruns on some), and anything lower is more permissive.
    policy = registry_int(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDriveTypeAutoRun")
    if policy is not None and policy >= 0xFF:
        return audit_check(
            "autorun", "Çıkarılabilir sürücü AutoRun", AUDIT_PASS,
            "Tüm sürücü türleri için AutoRun kapalı.", weight=1)
    return audit_check(
        "autorun", "Çıkarılabilir sürücü AutoRun", AUDIT_WARN,
        "AutoRun tamamen kapatılmamış. Takılan bir USB'nin içeriği kullanıcı onayı olmadan "
        "çalıştırılabilir.", weight=1,
        remedy="Explorer ilkelerinde NoDriveTypeAutoRun değerini 255 yap.", fix="autorun_disable")


def audit_hidden_extensions() -> dict[str, Any]:
    hide = registry_int(
        winreg.HKEY_CURRENT_USER,
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "HideFileExt", default=1)
    if hide == 0:
        return audit_check(
            "file_extensions", "Dosya uzantıları", AUDIT_PASS,
            "Bilinen dosya uzantıları gösteriliyor.", weight=1)
    return audit_check(
        "file_extensions", "Dosya uzantıları", AUDIT_WARN,
        "Bilinen uzantılar gizli. \"fatura.pdf.exe\" gibi dosyalar Gezgin'de \"fatura.pdf\" olarak görünür.",
        weight=1, remedy="Dosya Gezgini > Görünüm > Dosya adı uzantıları seçeneğini işaretle.",
        fix="file_extensions_show")


SYSTEM_AUDIT_CHECKS = (
    audit_defender_realtime,
    audit_firewall,
    audit_uac,
    audit_auto_logon,
    audit_lsa_protection,
    audit_remote_desktop,
    audit_smb1,
    audit_windows_update,
    audit_autorun,
    audit_hidden_extensions,
)

# Weight kept by a passing check. A warning keeps half its weight because it
# is a real but survivable gap; a critical finding keeps none. Unknown checks
# are excluded from both sides of the ratio so an unreadable setting cannot
# quietly inflate or deflate the score.
AUDIT_STATUS_CREDIT = {AUDIT_PASS: 1.0, AUDIT_WARN: 0.5, AUDIT_CRITICAL: 0.0}


def system_audit() -> int:
    if os.name != "nt" or winreg is None:
        emit("error", code="SYSTEM_AUDIT_UNSUPPORTED",
             message="Sistem denetimi yalnızca Windows üzerinde çalışır.")
        return 2
    checks: list[dict[str, Any]] = []
    for check in SYSTEM_AUDIT_CHECKS:
        try:
            checks.append(check())
        except Exception as error:  # noqa: BLE001 - one bad check must not sink the audit
            checks.append(audit_check(
                getattr(check, "__name__", "check"), "Denetim", AUDIT_UNKNOWN,
                f"Bu denetim tamamlanamadı: {error}"))

    scored = [item for item in checks if item["status"] in AUDIT_STATUS_CREDIT]
    total_weight = sum(item["weight"] for item in scored)
    earned = sum(AUDIT_STATUS_CREDIT[item["status"]] * item["weight"] for item in scored)
    score = int(round(earned / total_weight * 100)) if total_weight else 0

    counts = {
        status: sum(1 for item in checks if item["status"] == status)
        for status in (AUDIT_PASS, AUDIT_WARN, AUDIT_CRITICAL, AUDIT_UNKNOWN)
    }
    emit(
        "system-audit",
        checks=checks,
        score=score,
        counts=counts,
        checked_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )
    return 0


# --- Performance tools ------------------------------------------------------
# Deliberately narrow. "PC cleaner" features are where security products
# usually start shipping theatre: registry cleaners that break installs,
# "boosters" that free memory Windows was using as cache on purpose. These two
# do something real and nothing else.

# Files still being written to are normal in a temp directory; a browser or an
# installer mid-run owns them. Only files untouched for this long are removed,
# which is what makes the operation safe to run while the machine is in use.
TEMP_MIN_AGE_HOURS = 24


def temp_clean_roots() -> list[Path]:
    """Only these three, only ever these three. No registry, no user folders,
    no browser profiles -- deleting is irreversible and the blast radius of a
    'cleaner' that wanders is not worth the disk space it wins."""
    roots: list[Path] = []
    for variable in ("TEMP", "TMP"):
        value = os.environ.get(variable)
        if value:
            roots.append(Path(value))
    system_root = os.environ.get("SystemRoot")
    if system_root:
        roots.append(Path(system_root) / "Temp")

    resolved: list[Path] = []
    for root in roots:
        try:
            candidate = root.resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        if candidate.is_dir() and candidate not in resolved:
            resolved.append(candidate)
    return resolved


def _temp_candidates(root: Path, cutoff: float) -> Iterator[Path]:
    for current_directory, _directories, file_names in os.walk(root, onerror=lambda _error: None):
        for file_name in file_names:
            path = Path(current_directory) / file_name
            try:
                if path.is_symlink():
                    continue
                stat = path.stat()
            except OSError:
                continue
            if stat.st_mtime <= cutoff:
                yield path


def temp_usage() -> int:
    cutoff = time.time() - TEMP_MIN_AGE_HOURS * 3600
    entries = []
    total_bytes = 0
    total_files = 0
    for root in temp_clean_roots():
        root_bytes = 0
        root_files = 0
        for path in _temp_candidates(root, cutoff):
            try:
                root_bytes += path.stat().st_size
            except OSError:
                continue
            root_files += 1
        entries.append({"path": str(root), "bytes": root_bytes, "files": root_files})
        total_bytes += root_bytes
        total_files += root_files
    emit(
        "temp-usage", roots=entries, total_bytes=total_bytes, total_files=total_files,
        min_age_hours=TEMP_MIN_AGE_HOURS,
    )
    return 0


def temp_clean() -> int:
    cutoff = time.time() - TEMP_MIN_AGE_HOURS * 3600
    removed_files = 0
    removed_bytes = 0
    skipped = 0
    for root in temp_clean_roots():
        for path in _temp_candidates(root, cutoff):
            try:
                size = path.stat().st_size
                path.unlink()
            except OSError:
                # In use, locked, or owned by another account. Never force it.
                skipped += 1
                continue
            removed_files += 1
            removed_bytes += size
        # Second pass for the directory shells the deleted files left behind.
        # rmdir only succeeds on genuinely empty directories, so nothing that
        # still holds a file can be taken out from under its owner.
        for current_directory, directories, _files in os.walk(root, topdown=False, onerror=lambda _error: None):
            for name in directories:
                try:
                    (Path(current_directory) / name).rmdir()
                except OSError:
                    continue
    emit(
        "temp-cleaned", removed_files=removed_files, removed_bytes=removed_bytes,
        skipped=skipped, min_age_hours=TEMP_MIN_AGE_HOURS,
    )
    return 0


class _MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [
        ("dwLength", ctypes.c_ulong),
        ("dwMemoryLoad", ctypes.c_ulong),
        ("ullTotalPhys", ctypes.c_ulonglong),
        ("ullAvailPhys", ctypes.c_ulonglong),
        ("ullTotalPageFile", ctypes.c_ulonglong),
        ("ullAvailPageFile", ctypes.c_ulonglong),
        ("ullTotalVirtual", ctypes.c_ulonglong),
        ("ullAvailVirtual", ctypes.c_ulonglong),
        ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
    ]


def physical_memory_snapshot() -> dict[str, int] | None:
    if os.name != "nt":
        return None
    status = _MEMORYSTATUSEX()
    status.dwLength = ctypes.sizeof(_MEMORYSTATUSEX)
    try:
        if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            return None
    except (OSError, AttributeError):
        return None
    return {
        "total_bytes": int(status.ullTotalPhys),
        "available_bytes": int(status.ullAvailPhys),
        "used_bytes": int(status.ullTotalPhys - status.ullAvailPhys),
        "load_percent": int(status.dwMemoryLoad),
    }


def _process_working_sets() -> list[dict[str, Any]]:
    """(pid, name, working set) for every process this account can open."""
    if os.name != "nt":
        return []

    class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
        _fields_ = [
            ("cb", ctypes.c_ulong),
            ("PageFaultCount", ctypes.c_ulong),
            ("PeakWorkingSetSize", ctypes.c_size_t),
            ("WorkingSetSize", ctypes.c_size_t),
            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
            ("PagefileUsage", ctypes.c_size_t),
            ("PeakPagefileUsage", ctypes.c_size_t),
        ]

    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    PROCESS_SET_QUOTA = 0x0100
    kernel32 = ctypes.windll.kernel32
    psapi = ctypes.windll.psapi
    results: list[dict[str, Any]] = []

    for pid in psapi_process_ids():
        handle = kernel32.OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SET_QUOTA, False, pid)
        if not handle:
            continue
        try:
            counters = PROCESS_MEMORY_COUNTERS()
            counters.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
            if not psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
                continue
            name = ""
            buffer = ctypes.create_unicode_buffer(32768)
            size = ctypes.c_ulong(len(buffer))
            if kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
                name = Path(buffer.value).name
            results.append({
                "pid": int(pid), "name": name,
                "working_set_bytes": int(counters.WorkingSetSize),
                "handle": int(handle),
            })
            handle = None  # ownership moves to the caller for the trim pass
        finally:
            if handle:
                kernel32.CloseHandle(handle)
    return results


def memory_status() -> int:
    snapshot = physical_memory_snapshot()
    if snapshot is None:
        emit("error", code="MEMORY_STATUS_UNAVAILABLE", message="Bellek durumu okunamadı.")
        return 2
    entries = _process_working_sets()
    kernel32 = ctypes.windll.kernel32
    top = sorted(entries, key=lambda item: item["working_set_bytes"], reverse=True)[:12]
    top_payload = [
        {"pid": item["pid"], "name": item["name"], "working_set_bytes": item["working_set_bytes"]}
        for item in top
    ]
    for item in entries:
        kernel32.CloseHandle(item["handle"])
    emit("memory-status", **snapshot, process_count=len(entries), top_processes=top_payload)
    return 0


def memory_trim() -> int:
    """Asks Windows to page out each reachable process's working set.

    Honest about what this is: it does not create memory, it moves pages the
    processes were holding out to disk. Windows reloads whatever is needed
    again, so "available memory" rises briefly and then settles back, and the
    processes involved run slower for a moment while they fault their pages
    back in. It is genuinely useful in one case -- reclaiming a bloated
    working set after something heavy exits -- and useless as a routine habit.
    """
    before = physical_memory_snapshot()
    if before is None:
        emit("error", code="MEMORY_TRIM_UNAVAILABLE", message="Bellek durumu okunamadı.")
        return 2
    kernel32 = ctypes.windll.kernel32
    psapi = ctypes.windll.psapi
    trimmed = 0
    skipped = 0
    for item in _process_working_sets():
        handle = item["handle"]
        try:
            if psapi.EmptyWorkingSet(handle):
                trimmed += 1
            else:
                skipped += 1
        except OSError:
            skipped += 1
        finally:
            kernel32.CloseHandle(handle)
    after = physical_memory_snapshot() or before
    emit(
        "memory-trimmed",
        trimmed_processes=trimmed,
        skipped_processes=skipped,
        before_available_bytes=before["available_bytes"],
        after_available_bytes=after["available_bytes"],
        freed_bytes=max(0, after["available_bytes"] - before["available_bytes"]),
        total_bytes=after["total_bytes"],
        load_percent=after["load_percent"],
    )
    return 0


def suspicious_process_finding(
    path: Path, *, command_line: str = "", parent_path: str = "",
) -> Finding | None:
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    if not resolved.is_file():
        return None
    writable_roots: list[tuple[str, Path]] = []
    for label, raw_root in (
        ("geçici klasör", os.environ.get("TEMP")),
        ("geçici klasör", os.environ.get("TMP")),
        ("İndirilenler", str(Path.home() / "Downloads")),
    ):
        if not raw_root:
            continue
        try:
            writable_roots.append((label, Path(raw_root).resolve()))
        except (OSError, RuntimeError):
            continue
    location = next(
        (label for label, root in writable_roots if path_is_inside(resolved, root)),
        None,
    )
    executable_suffixes = {".exe", ".com", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js"}
    if resolved.suffix.casefold() not in executable_suffixes:
        return None
    parts = resolved.name.casefold().split(".")
    double_extension = len(parts) >= 3 and f".{parts[-2]}" in DOCUMENT_EXTENSIONS
    executable_name = resolved.name.casefold()
    command = command_line.casefold()
    parent_name = Path(parent_path).name.casefold() if parent_path else ""
    reasons: list[tuple[int, str]] = []
    if double_extension:
        reasons.append((45, "belge uzantısını taklit eden çalıştırılabilir dosya"))
    elif location is not None and not is_trusted_signed_image(resolved):
        # Running from Temp or Downloads is only suspicious for something
        # nobody vouched for. Practically every Windows installer unpacks
        # itself into Temp and runs from there, and every browser download is
        # launched from Downloads -- penalising validly signed software for
        # the folder it happens to sit in is a pure false-positive generator.
        # The command-line checks below are deliberately NOT gated this way:
        # they judge what a process is doing, not who signed it, and the
        # LOLBins they cover (powershell, mshta, regsvr32, certutil) are all
        # signed by Microsoft precisely because that is what makes them useful
        # to an attacker.
        reasons.append((22, f"{location} içinden çalıştırıldı"))

    suspicious_arguments = {
        "powershell.exe": (("-encodedcommand", "-enc ", "frombase64string", "downloadstring", "invoke-expression", "iex "), 38),
        "pwsh.exe": (("-encodedcommand", "-enc ", "frombase64string", "downloadstring", "invoke-expression", "iex "), 38),
        "mshta.exe": (("http://", "https://", "javascript:", "vbscript:"), 42),
        "rundll32.exe": (("javascript:", "http://", "https://", "\\temp\\", "\\downloads\\"), 35),
        "regsvr32.exe": (("/i:http", "/i:https", "scrobj.dll", "/n /u"), 42),
        "certutil.exe": (("-urlcache", "-decode", "-decodehex"), 30),
        "bitsadmin.exe": (("/transfer", "/addfile"), 32),
        "wscript.exe": (("\\temp\\", "\\downloads\\", ".js", ".vbs"), 26),
        "cscript.exe": (("\\temp\\", "\\downloads\\", ".js", ".vbs"), 26),
    }
    argument_rule = suspicious_arguments.get(executable_name)
    if argument_rule:
        matches = [marker for marker in argument_rule[0] if marker in command]
        if matches:
            reasons.append((argument_rule[1], f"şüpheli {executable_name} komut deseni: {', '.join(matches[:3])}"))
    office_parents = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe"}
    script_children = set(suspicious_arguments) | {"cmd.exe", "wscript.exe", "cscript.exe"}
    if parent_name in office_parents and executable_name in script_children:
        reasons.append((38, f"Office süreci {parent_name}, {executable_name} başlattı"))
    risk_score = min(100, sum(points for points, _reason in reasons))
    if risk_score < 25:
        return None
    severity = severity_for_risk(risk_score)
    reason = f"Davranış riski {risk_score}/100 · " + "; ".join(reason for _points, reason in sorted(reasons, reverse=True))
    size = resolved.stat().st_size
    return Finding(
        path=str(resolved),
        kind="behavior",
        severity=severity,
        reason=reason,
        sha256=sha256_for(resolved, size),
        risk_score=risk_score,
    )


def watch_behavior() -> int:
    """Monitor process starts and common persistence points in read-only mode."""
    if os.name != "nt":
        emit("behavior-error", code="UNSUPPORTED_PLATFORM", message="Davranış izleme yalnız Windows'ta kullanılabilir.")
        return 2
    processes = windows_process_snapshot()
    parents = toolhelp_parent_processes()
    persistence = persistence_snapshot()
    exclusions = load_exclusion_set()
    own_roots = neutron_owned_roots()
    emit(
        "behavior-ready",
        backend="windows-native",
        process_count=len(processes),
        persistence_points=len(persistence),
        interval_seconds=BEHAVIOR_INTERVAL_SECONDS,
    )
    try:
        while True:
            time.sleep(BEHAVIOR_INTERVAL_SECONDS)
            current_processes = windows_process_snapshot()
            current_parents = toolhelp_parent_processes()
            process_paths = {**processes, **current_processes}
            parent_links = {**parents, **current_parents}
            for process_id, raw_path in current_processes.items():
                if process_id in processes:
                    continue
                if is_neutron_process_or_descendant(process_id, process_paths, parent_links, own_roots):
                    continue
                parent_id = current_parents.get(process_id, 0)
                parent_path = current_processes.get(parent_id) or processes.get(parent_id, "")
                finding = suspicious_process_finding(
                    Path(raw_path), command_line=windows_process_command_line(process_id), parent_path=parent_path,
                )
                if finding is None:
                    continue
                if is_path_excluded(Path(finding.path), exclusions):
                    continue
                if finding.sha256 and finding.sha256 in exclusions.hashes:
                    continue
                try:
                    event_id = save_protection_event("process-started", finding)
                except (OSError, sqlite3.Error):
                    event_id = None
                emit(
                    "behavior-finding",
                    event_id=event_id,
                    process_id=process_id,
                    file_name=Path(raw_path).name,
                    finding=asdict(finding),
                )
            processes = current_processes
            parents = current_parents

            current_persistence = persistence_snapshot()
            for identity, value in current_persistence.items():
                if identity in persistence and persistence[identity] == value:
                    continue
                # Autostart entries change constantly on a healthy machine:
                # every updater rewrites its own Run value on each version
                # bump. Reporting those taught the user that this detector
                # means nothing. An entry pointing at a validly signed
                # executable is therefore not news -- an entry pointing at
                # something unsigned, unreadable or unparseable still is.
                target = command_line_executable(value)
                if target is not None and is_trusted_signed_image(target):
                    continue
                finding = Finding(
                    path=identity,
                    kind="persistence",
                    severity="medium",
                    reason="Windows otomatik başlangıç noktasında yeni veya değiştirilmiş kalıcılık kaydı",
                    sha256=None,
                )
                try:
                    event_id = save_protection_event("persistence-changed", finding)
                except (OSError, sqlite3.Error):
                    event_id = None
                emit(
                    "behavior-finding",
                    event_id=event_id,
                    file_name=identity.rsplit("/", 1)[-1],
                    finding=asdict(finding),
                )
            persistence = current_persistence
    except KeyboardInterrupt:
        emit("behavior-stopped")
        return 0


def load_network_indicators() -> dict[str, dict[str, str]]:
    with open_database() as connection:
        rows = connection.execute(
            "SELECT value, name, severity FROM network_ip_indicators"
        ).fetchall()
    return {str(value): {"name": name or "", "severity": severity} for value, name, severity in rows}


def watch_network() -> int:
    """Poll-based, driver-free approximation of network monitoring: no
    packet inspection, no DNS visibility, no blocking -- just periodic
    connection enumeration (active_tcp_connections) checked against a
    local IP reputation list. A real kernel-mode filter would see far
    more; this is what's achievable without one (see plan notes)."""
    if os.name != "nt":
        emit("network-error", code="UNSUPPORTED_PLATFORM", message="Ağ izleme yalnız Windows'ta kullanılabilir.")
        return 2

    indicators = load_network_indicators()
    exclusions = load_exclusion_set()
    alerted: set[tuple[int, str]] = set()
    emit(
        "network-ready",
        backend="windows-native",
        indicator_count=len(indicators),
        interval_seconds=NETWORK_INTERVAL_SECONDS,
    )
    try:
        while True:
            time.sleep(NETWORK_INTERVAL_SECONDS)
            connections = active_tcp_connections()
            if not connections:
                continue
            # Dedup on (pid, ip) as connections are found, not just
            # up front -- the same process can hold several simultaneous
            # connections (different ports) to the same flagged IP within
            # one poll, and without this a single poll would otherwise
            # emit one finding per port instead of one per process+IP.
            flagged: list[tuple[int, str, int]] = []
            for pid, ip, port in connections:
                if ip not in indicators or (pid, ip) in alerted:
                    continue
                alerted.add((pid, ip))
                flagged.append((pid, ip, port))
            if not flagged:
                continue
            processes = windows_process_snapshot()
            for pid, ip, port in flagged:
                image_path = processes.get(pid, "")
                if image_path and is_path_excluded(Path(image_path), exclusions):
                    continue
                indicator = indicators[ip]
                process_label = Path(image_path).name if image_path else f"PID {pid}"
                finding = Finding(
                    path=image_path or process_label,
                    kind="network-reputation",
                    severity=indicator["severity"] or "high",
                    reason=(
                        f"{process_label}, bilinen kötü amaçlı IP adresine bağlandı: "
                        f"{ip}:{port}" + (f" ({indicator['name']})" if indicator["name"] else "")
                    ),
                    sha256=None,
                )
                try:
                    event_id = save_protection_event("network-connection", finding)
                except (OSError, sqlite3.Error):
                    event_id = None
                emit(
                    "network-finding",
                    event_id=event_id,
                    process_id=pid,
                    remote_ip=ip,
                    remote_port=port,
                    finding=asdict(finding),
                )
            if len(alerted) > 2000:
                alerted.clear()
    except KeyboardInterrupt:
        emit("network-stopped")
        return 0


USB_POLL_INTERVAL_SECONDS = 3.0


def removable_drive_letters() -> set[str]:
    """Polls currently-attached removable drives (USB sticks, SD cards --
    not fixed disks, not optical/network drives) via GetLogicalDrives +
    GetDriveTypeW. No admin required, same ctypes style as the other
    Win32 introspection helpers in this file."""
    if os.name != "nt":
        return set()
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetLogicalDrives.restype = wintypes.DWORD
    kernel32.GetDriveTypeW.argtypes = [wintypes.LPCWSTR]
    kernel32.GetDriveTypeW.restype = wintypes.UINT
    DRIVE_REMOVABLE = 2

    mask = kernel32.GetLogicalDrives()
    drives: set[str] = set()
    for index in range(26):
        if not (mask & (1 << index)):
            continue
        letter = f"{chr(65 + index)}:\\"
        if kernel32.GetDriveTypeW(letter) == DRIVE_REMOVABLE:
            drives.add(letter)
    return drives


# --- Ransomware protection v1 ---------------------------------------------
#
# Scope, stated honestly up front: without a kernel minifilter Neutron cannot
# block a write. It can only notice one that already happened. So this is a
# tripwire, not a shield -- it exists to cut the time between "encryption
# started" and "the user knows" from hours to seconds.
#
# Two independent signals:
#
#   1. Canary files. Decoys planted in the folders ransomware goes for first.
#      Nothing legitimate has any reason to rewrite them, so a change is very
#      nearly proof rather than suspicion -- this is the high-confidence
#      signal, and the one worth waking the user for.
#
#   2. Bulk-rewrite detection. Ransomware rewrites many files quickly and the
#      result is high-entropy. Real work (a build, an export, an archive
#      extraction) can look similar, which is why on its own this only warns.
#
# What is deliberately NOT here: killing the process. Without a driver we
# cannot see which process wrote a file, so the "culprit" would be a guess
# from process-listing heuristics, and killing the wrong one on a false
# positive can lose the user's unsaved work. Reporting is honest; guessing and
# killing is not. Attribution needs the minifilter (plan.md items 4-5).
RANSOMWARE_POLL_INTERVAL_SECONDS = 5
# The two signals have very different costs, so they get different cadences.
# Checking four canaries is four small reads and is what actually needs to be
# fast -- that is the signal worth waking the user for. The bulk sweep stats
# thousands of files, so running it at the canary rate burned CPU continuously
# in the background for a signal that only warns.
RANSOMWARE_BULK_SWEEP_INTERVAL_SECONDS = 30
RANSOMWARE_BULK_SWEEP_FILE_LIMIT = 4000
RANSOMWARE_CANARY_PREFIX = "~$neutron-koruma"
# Chosen to sort to the ends of a directory listing so the decoys stay out of
# the user's way, while still sitting in the folders that get hit first.
RANSOMWARE_CANARY_FOLDERS = ("Documents", "Desktop", "Pictures", "Downloads")
RANSOMWARE_BULK_WINDOW_SECONDS = 60
RANSOMWARE_BULK_FILE_COUNT = 40
RANSOMWARE_BULK_MIN_ENTROPY = 7.2


def shannon_entropy(data: bytes) -> float:
    """Bits per byte, 0.0-8.0. Encrypted and compressed data sit near 8.0;
    documents, source and most real user files sit well below it.

    numpy is used when present because this runs inside a polling watcher: the
    pure-Python byte loop costs ~2.3 ms per 64 KB, which is ~17x slower and
    turns a directory of changed files into seconds of CPU. The fallback keeps
    the watcher working if numpy fails to load, matching the engine's
    fail-open handling of every other optional dependency."""
    if not data:
        return 0.0
    length = len(data)
    try:
        import numpy as np

        counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
        probabilities = counts[counts > 0].astype(np.float64) / length
        return float(-(probabilities * np.log2(probabilities)).sum())
    except (ImportError, ValueError):
        counts_list = [0] * 256
        for byte in data:
            counts_list[byte] += 1
        total = 0.0
        for count in counts_list:
            if count:
                probability = count / length
                total -= probability * math.log2(probability)
        return total


def ransomware_canary_paths() -> list[Path]:
    home = Path.home()
    paths: list[Path] = []
    for folder in RANSOMWARE_CANARY_FOLDERS:
        directory = home / folder
        if directory.is_dir():
            paths.append(directory / f"{RANSOMWARE_CANARY_PREFIX}.docx")
    return paths


def ransomware_canary_body(path: Path) -> bytes:
    return (
        b"Bu dosya Neutron Guvenlik tarafindan olusturuldu.\r\n"
        b"Fidye yazilimi korumasi icin kullanilan bir tuzak dosyasidir.\r\n"
        b"Silmeyin ve degistirmeyin; icerigi bilerek bostur.\r\n"
        b"Konum: " + str(path).encode("utf-8", errors="replace") + b"\r\n"
    )


def ensure_ransomware_canaries() -> dict[str, str]:
    """Creates any missing decoys and returns path -> expected digest.

    Marked hidden so they do not clutter the user's folders. A canary that
    cannot be created is skipped rather than failing the watcher: a read-only
    or redirected folder is common and is not an error worth stopping for.
    """
    expected: dict[str, str] = {}
    for path in ransomware_canary_paths():
        body = ransomware_canary_body(path)
        try:
            if not path.is_file() or path.read_bytes() != body:
                # Windows refuses an ordinary open-for-write on a file that
                # already carries HIDDEN/SYSTEM, so re-arming a tripped canary
                # fails unless the attributes are cleared and the file
                # replaced. Found by the re-arm test, not by inspection.
                if path.exists() and os.name == "nt":
                    ctypes.windll.kernel32.SetFileAttributesW(str(path), 0x80)  # NORMAL
                path.unlink(missing_ok=True)
                path.write_bytes(body)
                if os.name == "nt":
                    # FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM
                    ctypes.windll.kernel32.SetFileAttributesW(str(path), 0x02 | 0x04)
            expected[str(path)] = hashlib.sha256(body).hexdigest()
        except (OSError, AttributeError):
            continue
    return expected


def watch_ransomware() -> int:
    """Canary tripwire plus bulk-rewrite heuristic. Detection only -- see the
    block comment above for why nothing is killed here."""
    settings = read_app_settings()
    targets = configured_scan_targets(settings)
    expected = ensure_ransomware_canaries()
    emit("ransomware-ready", canaries=len(expected), targets=[str(t) for t in targets])
    if not expected:
        emit("ransomware-error", code="NO_CANARY",
             message="Tuzak dosyaları oluşturulamadı; fidye yazılımı koruması sınırlı çalışıyor.")

    # path -> (mtime, size) as last seen, for the bulk-rewrite signal.
    seen: dict[str, tuple[float, int]] = {}
    recent_rewrites: list[tuple[float, str]] = []
    alerted_canaries: set[str] = set()
    bulk_alerted_at = 0.0
    last_bulk_sweep_at = 0.0

    try:
        while True:
            time.sleep(RANSOMWARE_POLL_INTERVAL_SECONDS)
            now = time.time()

            # --- signal 1: canaries -----------------------------------
            for raw_path, digest in list(expected.items()):
                path = Path(raw_path)
                try:
                    changed = not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest
                except OSError:
                    changed = True
                if not changed or raw_path in alerted_canaries:
                    continue
                alerted_canaries.add(raw_path)
                finding = Finding(
                    path=raw_path, kind="ransomware-canary", severity="high",
                    reason="Fidye yazılımı tuzak dosyası değiştirildi veya silindi; "
                           "bu klasörde dosyalar şifreleniyor olabilir",
                )
                try:
                    event_id = save_protection_event("ransomware", finding)
                except (OSError, sqlite3.Error):
                    event_id = None
                emit("ransomware-finding", event_id=event_id, signal="canary",
                     folder=str(path.parent), finding=asdict(finding))

            # --- signal 2: bulk rewrite -------------------------------
            cutoff = now - RANSOMWARE_BULK_WINDOW_SECONDS
            recent_rewrites = [item for item in recent_rewrites if item[0] >= cutoff]
            if now - last_bulk_sweep_at < RANSOMWARE_BULK_SWEEP_INTERVAL_SECONDS:
                expected = ensure_ransomware_canaries()
                alerted_canaries &= set(expected)
                continue
            last_bulk_sweep_at = now
            # Each sweep is bounded, but successive sweeps see different files
            # as directories change, so the baseline grows without a cap in a
            # watcher that runs for weeks. Dropping it costs one sweep with no
            # comparisons, not a missed detection window.
            if len(seen) > 4 * RANSOMWARE_BULK_SWEEP_FILE_LIMIT:
                seen.clear()
            exclusions = load_exclusion_set()
            for file_path in iter_files(targets, RANSOMWARE_BULK_SWEEP_FILE_LIMIT,
                                        exclusions, maximum_depth=4):
                try:
                    stat = file_path.stat()
                except OSError:
                    continue
                key = str(file_path)
                previous = seen.get(key)
                seen[key] = (stat.st_mtime, stat.st_size)
                if previous is None or previous == (stat.st_mtime, stat.st_size):
                    continue
                if stat.st_size == 0 or stat.st_size > 32 * 1024 * 1024:
                    continue
                try:
                    with file_path.open("rb") as handle:
                        sample = handle.read(65536)
                except OSError:
                    continue
                if not sample or shannon_entropy(sample) < RANSOMWARE_BULK_MIN_ENTROPY:
                    continue
                recent_rewrites.append((now, key))

            if (
                len(recent_rewrites) >= RANSOMWARE_BULK_FILE_COUNT
                and now - bulk_alerted_at > RANSOMWARE_BULK_WINDOW_SECONDS
            ):
                bulk_alerted_at = now
                sample_paths = [path for _seen_at, path in recent_rewrites[-5:]]
                finding = Finding(
                    path=sample_paths[-1] if sample_paths else str(targets[0]),
                    kind="ransomware-bulk", severity="high",
                    reason=f"Son {RANSOMWARE_BULK_WINDOW_SECONDS} saniyede {len(recent_rewrites)} dosya "
                           "yüksek entropili içerikle yeniden yazıldı; toplu şifreleme olabilir",
                )
                try:
                    event_id = save_protection_event("ransomware", finding)
                except (OSError, sqlite3.Error):
                    event_id = None
                emit("ransomware-finding", event_id=event_id, signal="bulk",
                     file_count=len(recent_rewrites), samples=sample_paths,
                     finding=asdict(finding))

            # Rewriting a canary is a one-shot signal; re-arm it once the
            # decoy is intact again so a restored folder resumes protection.
            expected = ensure_ransomware_canaries()
            alerted_canaries &= set(expected)
    except KeyboardInterrupt:
        emit("ransomware-stopped")
        return 0


def watch_usb() -> int:
    """Poll-based (no WM_DEVICECHANGE window needed) removable-media
    watcher: on each newly-attached drive, flags an autorun.inf (the
    classic USB-autorun malware vector -- Windows itself has ignored
    autorun.inf on non-optical media by default since Vista/7, this is
    defense in depth / visibility, not reliance on autorun actually
    firing) and runs a bounded scan of the drive's root-level files
    through the same inspect_file_cached pipeline as everything else."""
    if os.name != "nt":
        emit("usb-error", code="UNSUPPORTED_PLATFORM", message="USB izleme yalnız Windows'ta kullanılabilir.")
        return 2

    signatures = load_signatures()
    yara_rules, yara_status = load_yara_rules()
    exclusions = load_exclusion_set()
    cache_session = open_analysis_cache_session(str(yara_status.get("fingerprint", "none")))
    known_drives = removable_drive_letters()
    emit("usb-ready", backend="windows-native", attached=len(known_drives))

    try:
        while True:
            time.sleep(USB_POLL_INTERVAL_SECONDS)
            current_drives = removable_drive_letters()
            for drive in current_drives - known_drives:
                root = Path(drive)
                emit("usb-attached", drive=drive)
                autorun_path = root / "autorun.inf"
                if autorun_path.exists():
                    finding = Finding(
                        path=str(autorun_path), kind="usb-autorun", severity="high",
                        reason="Çıkarılabilir medyada autorun.inf bulundu (bilinen USB yayılma vektörü)",
                        sha256=sha256_for(autorun_path, autorun_path.stat().st_size) if autorun_path.is_file() else None,
                    )
                    try:
                        event_id = save_protection_event("usb-autorun", finding)
                    except (OSError, sqlite3.Error):
                        event_id = None
                    emit("usb-finding", event_id=event_id, drive=drive, finding=asdict(finding))

                scanned = 0
                for file_path in iter_files([root], 500, exclusions, maximum_depth=2):
                    scanned += 1
                    findings = inspect_file_cached(file_path, signatures, yara_rules, exclusions, cache_session)
                    for finding in findings:
                        try:
                            event_id = save_protection_event("usb-scan", finding)
                            quarantine_item_id = auto_quarantine_confirmed_finding(event_id, finding)
                        except (OSError, sqlite3.Error):
                            event_id = None
                            quarantine_item_id = None
                        emit(
                            "usb-finding", event_id=event_id, drive=drive, finding=asdict(finding),
                            action="quarantined" if quarantine_item_id is not None else "pending",
                        )
                flush_analysis_cache(cache_session)
                emit("usb-scan-complete", drive=drive, scanned=scanned)
            for drive in known_drives - current_drives:
                emit("usb-detached", drive=drive)
            known_drives = current_drives
    except KeyboardInterrupt:
        emit("usb-stopped")
        return 0


class _SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("nLength", ctypes.c_ulong),
        ("lpSecurityDescriptor", ctypes.c_void_p),
        ("bInheritHandle", ctypes.c_int),
    ]


def _pipe_security_from_sddl(sddl: str) -> tuple[_SECURITY_ATTRIBUTES | None, ctypes.c_void_p | None]:
    if os.name != "nt":
        return None, None
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    convert = advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.restype = wintypes.BOOL
    convert.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.DWORD)]
    descriptor = ctypes.c_void_p()
    descriptor_size = wintypes.DWORD(0)
    if not convert(sddl, 1, ctypes.byref(descriptor), ctypes.byref(descriptor_size)):
        return None, None
    attributes = _SECURITY_ATTRIBUTES(
        ctypes.sizeof(_SECURITY_ATTRIBUTES), descriptor.value, False,
    )
    return attributes, descriptor


def authenticated_user_pipe_security() -> tuple[_SECURITY_ATTRIBUTES | None, ctypes.c_void_p | None]:
    """DACL for the AMSI scan pipe: SYSTEM/admins full, authenticated users
    read/write.

    This pipe is deliberately reachable by any signed-in account, because the
    processes that use it are not ours: Windows loads the AMSI provider into
    whatever script host is running (powershell.exe, wscript.exe, Office), and
    those may belong to any logged-in user. Broad access is safe *here* because
    the protocol is scan-only -- a buffer goes in, a verdict comes back, and no
    command on this pipe changes any state. The control pipe is a completely
    different proposition; see service_pipe_security().
    """
    return _pipe_security_from_sddl("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)")


def service_pipe_security() -> tuple[_SECURITY_ATTRIBUTES | None, ctypes.c_void_p | None]:
    """DACL for the service *control* pipe (plan.md item 9, "IPC yetkisi").

    This pipe previously shared the AMSI pipe's DACL, which granted
    Authenticated Users read/write. Because the service runs as LocalSystem
    and the command handler dispatched purely on the "cmd" field with no idea
    who was calling, any signed-in non-admin account -- or any malware running
    as that account -- could send update_setting and turn protection off,
    bypassing the tamper-confirmation dialogs entirely, or drive full-disk
    scans as SYSTEM at will.

    INTERACTIVE (IU) replaces Authenticated Users: the desktop UI runs in the
    user's interactive session and still connects, while service accounts,
    network logons and scheduled-task identities no longer can.

    A DACL alone cannot finish the job, because every interactive user still
    qualifies. It is the coarse first layer; service_client_authorized()
    below is the one that actually decides.
    """
    return _pipe_security_from_sddl("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)")


def named_pipe_client_process_id(pipe: Any) -> int | None:
    if os.name != "nt":
        return None
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetNamedPipeClientProcessId.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.ULONG)]
    kernel32.GetNamedPipeClientProcessId.restype = wintypes.BOOL
    client_id = wintypes.ULONG(0)
    if not kernel32.GetNamedPipeClientProcessId(pipe, ctypes.byref(client_id)):
        return None
    return int(client_id.value) or None


# Rejected connections are recorded, not just dropped: a process trying to
# drive the antivirus service is exactly the kind of thing the user should be
# able to see afterwards. It is rate-limited because the trigger is entirely
# attacker-controlled -- an unauthorized caller can reconnect in a tight loop,
# and a detector that writes a database row per attempt is a way to fill the
# disk, not a way to report an intrusion.
SERVICE_REJECTION_REPORT_INTERVAL_SECONDS = 300
_last_service_rejection_report = 0.0
_suppressed_service_rejections = 0


def report_rejected_service_client(client_id: int | None) -> None:
    global _last_service_rejection_report, _suppressed_service_rejections
    now = time.monotonic()
    if now - _last_service_rejection_report < SERVICE_REJECTION_REPORT_INTERVAL_SECONDS:
        _suppressed_service_rejections += 1
        return
    suppressed = _suppressed_service_rejections
    _suppressed_service_rejections = 0
    _last_service_rejection_report = now
    image_path = windows_process_image_path(client_id) if client_id else None
    extra = f" Son {SERVICE_REJECTION_REPORT_INTERVAL_SECONDS // 60} dakikada {suppressed} benzer deneme daha engellendi." if suppressed else ""
    try:
        save_protection_event("service-client-rejected", Finding(
            path=image_path or f"pid://{client_id or 0}",
            kind="service-tamper",
            severity="high",
            reason=(
                "Yetkisiz bir süreç Neutron servis denetim kanalına bağlanmayı denedi ve reddedildi."
                f"{extra}"
            ),
            sha256=None,
            risk_score=70,
        ))
    except (OSError, sqlite3.Error):
        # Reporting must never take the pipe server down; the connection has
        # already been refused, which is the part that matters.
        pass


def service_client_authorized(pipe: Any) -> bool:
    """True only when the control-pipe client is a Neutron process.

    Identity comes from the pipe itself (GetNamedPipeClientProcessId), not
    from anything the caller sends, so it cannot be spoofed by the protocol.
    The image path is then required to sit inside this build's own install
    root -- the same anchor the watchers already use to recognise Neutron
    helpers, and a meaningful one because an unprivileged user cannot write a
    binary into that directory.

    Fails closed: an unresolvable PID or image path is refused. The honest
    limit, identical to the one documented for self-protection: this does not
    stop malware that has already compromised a genuine Neutron process, since
    that process *is* the legitimate client by any measure available here.
    """
    if os.name != "nt":
        return True
    client_id = named_pipe_client_process_id(pipe)
    if client_id is None:
        return False
    image_path = windows_process_image_path(client_id)
    if not image_path:
        return False
    return is_neutron_owned_process_path(image_path)


SERVICE_PIPE_NAME = r"\\.\pipe\neutron-service"


def service_host() -> int:
    """Runs as LocalSystem under NeutronServiceHost.exe (see tools/service/).
    Consolidates the watch_* loops into daemon threads of one process
    instead of five separate subprocesses, and hosts a named pipe
    (SERVICE_PIPE_NAME) the Electron UI connects to for live events and
    control commands. Each watch_*() function is used completely
    unmodified -- they already call the module-level emit(), which this
    function retargets (via _emit_sink) to the pipe instead of stdout.

    Known v1 limitation, documented rather than silently accepted: which
    optional watchers (web/network/amsi) start is decided once at service
    startup from the persisted settings. Toggling those settings from the
    UI while the service is already running updates the database (so it
    takes effect on the next service restart) but does not hot-start/stop
    the corresponding thread -- the existing watch_*() functions have no
    cooperative-cancellation support, and adding it to five functions
    already built this session was out of scope for an already-large
    architecture change. protection_enabled/behavior_protection_enabled
    (the always-on-by-default core) start unconditionally.
    """
    if os.name != "nt":
        return 2

    global _pipe_handle
    _pipe_handle = None
    pipe_lock = threading.Lock()

    def broadcast(message: dict[str, Any]) -> None:
        global _pipe_handle
        with pipe_lock:
            handle = _pipe_handle
            if handle is None:
                return
            data = (json.dumps(message, ensure_ascii=False) + "\n").encode("utf-8")
            written = wintypes.DWORD(0)
            ok = kernel32.WriteFile(handle, data, len(data), ctypes.byref(written), None)
            if not ok:
                _pipe_handle = None

    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    PIPE_ACCESS_DUPLEX = 0x3
    PIPE_TYPE_BYTE = 0x0
    PIPE_READMODE_BYTE = 0x0
    PIPE_WAIT = 0x0
    PIPE_REJECT_REMOTE_CLIENTS = 0x8
    PIPE_UNLIMITED_INSTANCES = 255
    INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value
    ERROR_PIPE_CONNECTED = 535

    kernel32.CreateNamedPipeW.restype = wintypes.HANDLE
    kernel32.CreateNamedPipeW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
        wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
    ]
    kernel32.ConnectNamedPipe.restype = wintypes.BOOL
    kernel32.ConnectNamedPipe.argtypes = [wintypes.HANDLE, wintypes.LPVOID]
    kernel32.ReadFile.restype = wintypes.BOOL
    kernel32.ReadFile.argtypes = [
        wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID,
    ]
    kernel32.WriteFile.restype = wintypes.BOOL
    kernel32.WriteFile.argtypes = [
        wintypes.HANDLE, wintypes.LPCVOID, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID,
    ]
    kernel32.DisconnectNamedPipe.restype = wintypes.BOOL
    kernel32.DisconnectNamedPipe.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    pipe_security, _pipe_security_descriptor = service_pipe_security()
    pipe_security_pointer = ctypes.byref(pipe_security) if pipe_security is not None else None

    global _emit_sink
    _emit_sink = broadcast

    def handle_command(command: dict[str, Any]) -> dict[str, Any]:
        action = command.get("cmd")
        try:
            if action == "get_settings":
                return {"type": "settings", "settings": read_app_settings()}
            if action == "update_setting":
                settings = write_app_setting(str(command.get("key")), command.get("value"))
                return {"type": "settings-updated", "settings": settings, "changed_key": command.get("key")}
            if action == "install_proton_archive":
                package_path = Path(str(command.get("package_path") or "")).resolve(strict=True)
                signature_path = Path(str(command.get("signature_path") or "")).resolve(strict=True)
                version = str(command.get("version") or "")
                proton_version_tuple(version)
                if package_path.suffix.casefold() != ".pdbx" or signature_path.name != f"{package_path.name}.sig":
                    raise ValueError("Proton arşiv yolları geçersiz")
                app_executable = Path(sys.executable).resolve().parents[5] / "Neutron.exe"
                if not app_executable.is_file():
                    raise ValueError("Neutron bakım yürütülebiliri bulunamadı")
                completed = subprocess.run(
                    [str(app_executable), "--install-proton-archive", str(package_path), str(signature_path), version],
                    timeout=180, check=False, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                if completed.returncode != 0:
                    raise ValueError(f"Proton servis veritabanına kurulamadı (kod {completed.returncode})")
                threading.Thread(target=lambda: (time.sleep(0.5), os._exit(0)), daemon=True).start()
                return {"type": "service-signature-updated", "version": version}
            if action == "run_scan":
                mode = str(command.get("mode") or "quick")
                if mode == "full" and command.get("drive"):
                    return {"type": "scan-result", "code": full_scan(str(command["drive"]))}
                if mode == "custom" and command.get("path"):
                    return {"type": "scan-result", "code": scan_targets([Path(str(command["path"]))], "custom")}
                if mode == "scheduled":
                    return {"type": "scan-result", "code": scheduled_quick_scan()}
                return {"type": "scan-result", "code": quick_scan()}
            return {"type": "error", "code": "UNKNOWN_COMMAND", "message": f"Bilinmeyen komut: {action}"}
        except Exception as error:  # noqa: BLE001 -- a bad command must never take the service down
            return {"type": "error", "code": "COMMAND_FAILED", "message": str(error)}

    def pipe_server() -> None:
        global _pipe_handle
        first_instance = True
        while True:
            open_mode = PIPE_ACCESS_DUPLEX | (0x00080000 if first_instance else 0)
            pipe = kernel32.CreateNamedPipeW(
                SERVICE_PIPE_NAME, open_mode,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_UNLIMITED_INSTANCES, 1 << 16, 1 << 16, 0, pipe_security_pointer,
            )
            first_instance = False
            if pipe == INVALID_HANDLE_VALUE:
                time.sleep(1)
                continue
            connected = kernel32.ConnectNamedPipe(pipe, None)
            if not connected and ctypes.get_last_error() != ERROR_PIPE_CONNECTED:
                kernel32.CloseHandle(pipe)
                continue
            # Authorize once per connection, before a single byte is read and
            # before this handle is published as the broadcast target. Checking
            # per command would be both slower and weaker: an unauthorized
            # client would still be receiving every protection event this
            # service emits while its commands were being rejected.
            if not service_client_authorized(pipe):
                report_rejected_service_client(named_pipe_client_process_id(pipe))
                kernel32.DisconnectNamedPipe(pipe)
                kernel32.CloseHandle(pipe)
                continue
            with pipe_lock:
                _pipe_handle = pipe
            pending = b""
            try:
                while True:
                    buffer = ctypes.create_string_buffer(1 << 16)
                    read = wintypes.DWORD(0)
                    ok = kernel32.ReadFile(pipe, buffer, len(buffer), ctypes.byref(read), None)
                    if not ok or read.value == 0:
                        break
                    pending += buffer.raw[: read.value]
                    if len(pending) > MAX_PROTON_PAYLOAD_BYTES + (2 * 1024 * 1024):
                        break
                    while b"\n" in pending:
                        line, pending = pending.split(b"\n", 1)
                        if not line.strip():
                            continue
                        try:
                            command = json.loads(line.decode("utf-8"))
                        except (ValueError, UnicodeDecodeError):
                            continue
                        response = handle_command(command)
                        broadcast(response)
            finally:
                with pipe_lock:
                    if _pipe_handle == pipe:
                        _pipe_handle = None
                kernel32.DisconnectNamedPipe(pipe)
                kernel32.CloseHandle(pipe)

    settings = read_app_settings()
    watchers = [("watch", watch_targets, True)]
    watchers.append(("watch-behavior", watch_behavior, bool(settings.get("behavior_protection_enabled"))))
    watchers.append(("watch-web", watch_web, bool(settings.get("web_protection_enabled"))))
    watchers.append(("watch-network", watch_network, bool(settings.get("network_protection_enabled"))))
    watchers.append(("amsi-service", amsi_service, bool(settings.get("amsi_protection_enabled"))))
    watchers.append(("watch-memory", watch_memory, bool(settings.get("memory_scan_enabled"))))
    watchers.append(("watch-usb", watch_usb, bool(settings.get("usb_protection_enabled"))))
    watchers.append(("watch-ransomware", watch_ransomware, bool(settings.get("ransomware_protection_enabled"))))

    # A watcher thread that raised used to die silently: no event, nothing in
    # the UI, and service-ready still listed it as active, so protection was
    # off while the product said it was on. A transient OSError -- a removable
    # drive pulled mid-scan, a denied handle, a network table read failing --
    # must not permanently disable a module.
    def supervise(name: str, target: Any) -> Any:
        def run() -> None:
            delay = 5
            while True:
                try:
                    target()
                    return  # clean, intentional stop
                except KeyboardInterrupt:
                    return
                except Exception as error:  # noqa: BLE001 - deliberately broad
                    emit("watcher-restarting", watcher=name, error=str(error), retry_in=delay)
                    time.sleep(delay)
                    delay = min(300, delay * 2)
        return run

    for name, target, enabled in watchers:
        if not enabled:
            continue
        thread = threading.Thread(target=supervise(name, target), name=name, daemon=True)
        thread.start()

    threading.Thread(target=pipe_server, name="service-pipe", daemon=True).start()
    emit("service-ready", pipe=SERVICE_PIPE_NAME, active_watchers=[n for n, _, e in watchers if e])

    # The process stays alive purely to host the threads above; it is
    # stopped externally by NeutronServiceHost.exe (TerminateProcess) on
    # SERVICE_CONTROL_STOP, not by anything in this loop.
    while True:
        time.sleep(3600)


def web_reputation(raw_url: str) -> dict[str, Any]:
    try:
        parsed = urlsplit(raw_url.strip())
    except ValueError:
        parsed = None
    if parsed is None or parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Geçerli bir HTTP veya HTTPS adresi gerekli")
    normalized_url = raw_url.strip().lower()
    host = parsed.hostname.rstrip(".").lower()
    with open_database() as connection:
        url_match = connection.execute(
            "SELECT name, severity FROM proton_web_indicators WHERE indicator_type = 'url' AND value = ?",
            (normalized_url,),
        ).fetchone()
        domain_rows = connection.execute(
            "SELECT value, name, severity FROM proton_web_indicators WHERE indicator_type = 'domain'"
        ).fetchall()
    match = url_match
    matched_value = normalized_url if url_match else None
    if match is None:
        for domain, name, severity in domain_rows:
            if host == domain or host.endswith(f".{domain}"):
                match = (name, severity)
                matched_value = domain
                break
    return {
        "safe": match is None,
        "url": raw_url,
        "host": host,
        "matched_value": matched_value,
        "name": str(match[0]) if match else None,
        "severity": str(match[1]) if match else None,
    }


def download_source_urls(path: Path) -> list[str]:
    if os.name != "nt":
        return []
    try:
        content = Path(f"{path}:Zone.Identifier").read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    return [value.strip() for key, value in re.findall(r"(?mi)^(HostUrl|ReferrerUrl)=(.+)$", content) if value.strip()]


def watch_web() -> int:
    downloads = Path.home() / "Downloads"
    downloads.mkdir(parents=True, exist_ok=True)
    exclusions = load_exclusion_set()
    signatures = load_signatures()
    yara_rules, yara_status = load_yara_rules()
    cache_session = open_analysis_cache_session(str(yara_status.get("fingerprint", "none")))
    known = snapshot_targets([downloads], MAX_FULL_SCAN_FILES, exclusions)
    emit("web-ready", target=str(downloads), tracked=len(known))
    try:
        while True:
            time.sleep(WATCH_INTERVAL_SECONDS)
            current = snapshot_targets([downloads], MAX_FULL_SCAN_FILES, load_exclusion_set())
            for raw_path, signature in current.items():
                if known.get(raw_path) == signature:
                    continue
                path = Path(raw_path)
                file_findings = inspect_file_cached(path, signatures, yara_rules, exclusions, cache_session)
                blocked = None
                for source_url in download_source_urls(path):
                    result = web_reputation(source_url)
                    if not result["safe"]:
                        blocked = result
                        break
                if blocked:
                    finding = Finding(str(path), "web-reputation", blocked["severity"] or "high", f"Zararlı indirme kaynağı: {blocked['name']}")
                    event_id = save_protection_event("web-download-blocked", finding)
                    emit("web-finding", event_id=event_id, file_name=path.name, source_url=blocked["url"], finding=asdict(finding))
                elif file_findings:
                    for finding in file_findings:
                        event_id = save_protection_event("web-download-finding", finding)
                        emit("web-finding", event_id=event_id, file_name=path.name, source_url=None, finding=asdict(finding))
                else:
                    emit("web-checked", file_name=path.name, file_path=str(path))
            known = current
            flush_analysis_cache(cache_session)
    except KeyboardInterrupt:
        flush_analysis_cache(cache_session)
        emit("web-stopped")
        return 0


AMSI_PIPE_NAME = r"\\.\pipe\neutron-amsi"
AMSI_FIELD_SEPARATOR = "\x1f"
AMSI_MAX_BUFFER_BYTES = 8 * 1024 * 1024


def inspect_amsi_buffer(
    content_name: str,
    buffer: bytes,
    signatures: dict[int, dict[str, dict[str, Any]]],
    yara_rules: Any | None,
) -> Finding | None:
    """Score a script/macro buffer handed over by the AMSI provider DLL.

    Unlike inspect_file, there may be no file on disk to point at (inline
    -Command text, in-memory Office macros) -- content_name is whatever the
    host process reported (often a path, sometimes a synthetic label like
    "Inline PowerShell Script"), used only for display/logging.
    """
    display_path = content_name or "AMSI-arabellek"
    digest = hashlib.sha256(buffer).hexdigest()
    size = len(buffer)

    signature = signatures.get(size, {}).get(digest)
    if signature:
        return Finding(
            path=display_path,
            kind="test-signature" if signature["source"] == "builtin" else "signature",
            severity=str(signature["severity"]),
            reason=f'{signature["name"]} eşleşmesi AMSI arabelleğinde bulundu',
            sha256=digest,
            risk_score=100,
        )

    if buffer.strip() == EICAR_MARKER:
        return Finding(
            path=display_path, kind="test-signature", severity="high",
            reason="EICAR güvenli antivirüs test imzası AMSI arabelleğinde bulundu",
            sha256=digest, risk_score=100,
        )

    if yara_rules is not None and size <= MAX_YARA_BYTES:
        try:
            for match in yara_rules.match(data=buffer, timeout=2):
                metadata = match.meta or {}
                description = str(metadata.get("description") or match.rule)
                severity = str(metadata.get("severity") or "medium").casefold()
                if severity not in {"low", "medium", "high", "critical"}:
                    severity = "medium"
                return Finding(
                    path=display_path, kind="yara", severity=severity,
                    reason=f"YARA kuralı eşleşti: {description}",
                    sha256=digest, risk_score=80,
                )
        except Exception:
            pass

    return None


def _amsi_decode_request(line: str) -> tuple[str, str, bytes] | None:
    parts = line.split(AMSI_FIELD_SEPARATOR)
    if len(parts) != 4 or parts[0] != "SCAN":
        return None
    _, content_name, app_name, encoded_buffer = parts
    try:
        buffer = base64.b64decode(encoded_buffer, validate=False)
    except (ValueError, TypeError):
        return None
    if len(buffer) > AMSI_MAX_BUFFER_BYTES:
        buffer = buffer[:AMSI_MAX_BUFFER_BYTES]
    return content_name, app_name, buffer


def amsi_service() -> int:
    """Pre-execution protection: serve verdicts to the native AMSI provider
    DLL (tools/amsi) over a named pipe so PowerShell/VBScript/JScript/Office
    macro content can be scored before it runs, not just after it lands on
    disk. See tools/amsi/PipeClient.cpp for the client side of this
    protocol and its fail-open timeout behaviour.

    The pipe uses an explicit DACL so LocalSystem can host it while signed-in
    user processes can submit scans. FILE_FLAG_FIRST_PIPE_INSTANCE prevents
    another local process from squatting on the name before Neutron starts.
    """
    if os.name != "nt":
        emit("amsi-error", code="UNSUPPORTED_PLATFORM", message="AMSI koruması yalnızca Windows üzerinde çalışır.")
        return 2

    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    PIPE_ACCESS_DUPLEX = 0x3
    FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000
    PIPE_TYPE_BYTE = 0x0
    PIPE_READMODE_BYTE = 0x0
    PIPE_WAIT = 0x0
    PIPE_REJECT_REMOTE_CLIENTS = 0x8
    PIPE_UNLIMITED_INSTANCES = 255
    INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value
    ERROR_PIPE_CONNECTED = 535

    # Explicit argtypes/restype on every kernel32 call: without them ctypes
    # guesses a C int (32-bit) for bare Python int arguments, which would
    # silently truncate 64-bit HANDLE values on 64-bit Python and corrupt
    # every call below. Matches the ctypes style already used for
    # verify_authenticode's WinVerifyTrust call.
    kernel32.CreateNamedPipeW.restype = wintypes.HANDLE
    kernel32.CreateNamedPipeW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
        wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
    ]
    kernel32.ConnectNamedPipe.restype = wintypes.BOOL
    kernel32.ConnectNamedPipe.argtypes = [wintypes.HANDLE, wintypes.LPVOID]
    kernel32.ReadFile.restype = wintypes.BOOL
    kernel32.ReadFile.argtypes = [
        wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID,
    ]
    kernel32.WriteFile.restype = wintypes.BOOL
    kernel32.WriteFile.argtypes = [
        wintypes.HANDLE, wintypes.LPCVOID, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID,
    ]
    kernel32.FlushFileBuffers.restype = wintypes.BOOL
    kernel32.FlushFileBuffers.argtypes = [wintypes.HANDLE]
    kernel32.DisconnectNamedPipe.restype = wintypes.BOOL
    kernel32.DisconnectNamedPipe.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    pipe_security, _pipe_security_descriptor = authenticated_user_pipe_security()
    pipe_security_pointer = ctypes.byref(pipe_security) if pipe_security is not None else None

    signatures = load_signatures()
    yara_rules, yara_status = load_yara_rules()
    emit("amsi-ready", pipe=AMSI_PIPE_NAME, yara=yara_status)

    # Only the very first instance needs FILE_FLAG_FIRST_PIPE_INSTANCE (it
    # rejects creation if some other local process already squats on this
    # pipe name). Re-requesting it on every loop iteration is unnecessary
    # once Neutron owns the name and risks a spurious ERROR_ACCESS_DENIED
    # if the previous handle hasn't finished tearing down yet.
    first_instance = True
    try:
        while True:
            open_mode = PIPE_ACCESS_DUPLEX | (FILE_FLAG_FIRST_PIPE_INSTANCE if first_instance else 0)
            pipe = kernel32.CreateNamedPipeW(
                AMSI_PIPE_NAME,
                open_mode,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_UNLIMITED_INSTANCES,
                1 << 16,
                1 << 16,
                0,
                pipe_security_pointer,
            )
            first_instance = False
            if pipe == INVALID_HANDLE_VALUE:
                emit("amsi-error", code="PIPE_CREATE_FAILED", message=f"Boru hattı oluşturulamadı: {ctypes.get_last_error()}")
                return 2
            try:
                connected = kernel32.ConnectNamedPipe(pipe, None)
                if not connected and ctypes.get_last_error() != ERROR_PIPE_CONNECTED:
                    continue

                chunks: list[bytes] = []
                while True:
                    buffer = ctypes.create_string_buffer(1 << 16)
                    read = wintypes.DWORD(0)
                    ok = kernel32.ReadFile(pipe, buffer, len(buffer), ctypes.byref(read), None)
                    if not ok or read.value == 0:
                        break
                    chunk = buffer.raw[: read.value]
                    chunks.append(chunk)
                    if b"\n" in chunk:
                        break

                raw = b"".join(chunks)
                newline = raw.find(b"\n")
                if newline == -1:
                    continue
                request_line = raw[:newline].decode("utf-8", errors="replace")
                decoded = _amsi_decode_request(request_line)

                if decoded is None:
                    response = f"VERDICT{AMSI_FIELD_SEPARATOR}clean{AMSI_FIELD_SEPARATOR}\n".encode("utf-8")
                else:
                    content_name, app_name, script_buffer = decoded
                    finding = inspect_amsi_buffer(content_name, script_buffer, signatures, yara_rules)
                    if finding is not None:
                        event_id = save_protection_event("amsi-block", finding)
                        emit(
                            "amsi-finding",
                            event_id=event_id,
                            app_name=app_name,
                            content_name=content_name,
                            finding=asdict(finding),
                        )
                        response = f"VERDICT{AMSI_FIELD_SEPARATOR}detected{AMSI_FIELD_SEPARATOR}{finding.reason}\n".encode("utf-8")
                    else:
                        response = f"VERDICT{AMSI_FIELD_SEPARATOR}clean{AMSI_FIELD_SEPARATOR}\n".encode("utf-8")

                written = wintypes.DWORD(0)
                kernel32.WriteFile(pipe, response, len(response), ctypes.byref(written), None)
                kernel32.FlushFileBuffers(pipe)
            finally:
                kernel32.DisconnectNamedPipe(pipe)
                kernel32.CloseHandle(pipe)
    except KeyboardInterrupt:
        emit("amsi-stopped")
        return 0


def watch_targets_polling_fallback() -> int:
    """Poll the user's common download locations without changing any files."""
    settings = read_app_settings()
    targets = configured_scan_targets(settings)
    max_files = resolved_max_files(settings["scan_max_files"])
    if not targets:
        emit("watch-error", code="NO_TARGETS", message="İzlenecek klasör bulunamadı.")
        return 2

    signatures = load_signatures()
    yara_rules, yara_status = load_yara_rules()
    exclusions = load_exclusion_set()
    cache_session = open_analysis_cache_session(str(yara_status.get("fingerprint", "none")))
    previous = snapshot_targets(targets, max_files, exclusions)
    emit(
        "watch-ready",
        targets=[str(target) for target in targets],
        tracked=len(previous),
        max_files=max_files,
        backend="polling-fallback",
        interval_seconds=WATCH_INTERVAL_SECONDS,
        yara=yara_status,
    )

    try:
        while True:
            time.sleep(WATCH_INTERVAL_SECONDS)
            current = snapshot_targets(targets, max_files, exclusions)

            for raw_path, signature in current.items():
                prior_signature = previous.get(raw_path)
                if prior_signature == signature:
                    continue

                event_kind = "created" if prior_signature is None else "changed"
                path = Path(raw_path)
                findings = inspect_file_cached(
                    path, signatures, yara_rules, exclusions, cache_session
                )
                if not findings:
                    emit(
                        "watch-checked",
                        event_kind=event_kind,
                        file_path=raw_path,
                        file_name=path.name,
                    )
                    continue

                for finding in findings:
                    try:
                        event_id = save_protection_event(event_kind, finding)
                        quarantine_item_id = auto_quarantine_confirmed_finding(event_id, finding)
                    except (OSError, sqlite3.Error):
                        event_id = None
                        quarantine_item_id = None
                    emit(
                        "watch-finding",
                        event_kind=event_kind,
                        event_id=event_id,
                        file_name=path.name,
                        finding=asdict(finding),
                        action="quarantined" if quarantine_item_id is not None else "pending",
                        quarantine_item_id=quarantine_item_id,
                    )

            previous = current
            flush_analysis_cache(cache_session)
    except KeyboardInterrupt:
        flush_analysis_cache(cache_session)
        emit("watch-stopped")
        return 0


def temp_directories() -> tuple[str, ...]:
    """%TEMP%/%TMP% normally live under AppData -- which SKIP_DIRECTORIES
    below would otherwise blanket-exclude -- but TEMP is an explicit,
    deliberate watch target (home_scan_targets), so it needs a carve-out
    rather than being silently dropped."""
    values = []
    for raw in (os.environ.get("TEMP"), os.environ.get("TMP")):
        if not raw:
            continue
        try:
            values.append(canonical_path(Path(raw)))
        except (OSError, RuntimeError):
            continue
    return tuple(values)


def should_ignore_watch_path(path: Path, exclusions: ExclusionSet | None = None) -> bool:
    if path.is_symlink() or is_engine_data_file(path):
        return True
    try:
        normalized = canonical_path(path)
    except (OSError, RuntimeError):
        normalized = None
    in_temp = normalized is not None and any(
        path_is_within(normalized, temp_dir) for temp_dir in temp_directories()
    )
    if not in_temp and any(part.casefold() in SKIP_DIRECTORIES for part in path.parts):
        return True
    if exclusions is not None and is_path_excluded(path, exclusions):
        return True
    return path.suffix.casefold() in {".crdownload", ".download", ".part", ".partial", ".tmp"}


def emit_watch_result(
    path: Path,
    event_kind: str,
    signatures: dict[int, dict[str, dict[str, Any]]],
    yara_rules: Any | None,
    exclusions: ExclusionSet,
    cache_session: AnalysisCacheSession,
) -> None:
    findings = inspect_file_cached(path, signatures, yara_rules, exclusions, cache_session)
    if not findings:
        emit("watch-checked", event_kind=event_kind, file_path=str(path), file_name=path.name)
        return
    for finding in findings:
        try:
            event_id = save_protection_event(event_kind, finding)
            quarantine_item_id = auto_quarantine_confirmed_finding(event_id, finding)
        except (OSError, sqlite3.Error):
            event_id = None
            quarantine_item_id = None
        emit(
            "watch-finding",
            event_kind=event_kind,
            event_id=event_id,
            file_name=path.name,
            finding=asdict(finding),
            action="quarantined" if quarantine_item_id is not None else "pending",
            quarantine_item_id=quarantine_item_id,
        )


def watch_targets() -> int:
    """Use native filesystem events, falling back to the bounded poller."""
    if Observer is None or FileSystemEventHandler is None:
        return watch_targets_polling_fallback()

    settings = read_app_settings()
    targets = configured_scan_targets(settings)
    max_files = resolved_max_files(settings["scan_max_files"])
    if not targets:
        emit("watch-error", code="NO_TARGETS", message="İzlenecek klasör bulunamadı.")
        return 2

    signatures = load_signatures()
    yara_rules, yara_status = load_yara_rules()
    exclusions = load_exclusion_set()
    cache_session = open_analysis_cache_session(str(yara_status.get("fingerprint", "none")))
    pending: dict[str, dict[str, Any]] = {}
    event_queue: queue.SimpleQueue[tuple[str, str, tuple[int, int] | None]] = queue.SimpleQueue()
    processed_signatures: dict[str, tuple[int, int]] = {}

    class NeutronEventHandler(FileSystemEventHandler):
        def queue(self, raw_path: str, event_kind: str) -> None:
            path = Path(raw_path)
            if should_ignore_watch_path(path, exclusions):
                return
            event_queue.put((str(path), event_kind, file_signature(path)))

        def on_created(self, event: Any) -> None:
            if not event.is_directory:
                self.queue(event.src_path, "created")

        def on_modified(self, event: Any) -> None:
            if not event.is_directory:
                self.queue(event.src_path, "changed")

        def on_moved(self, event: Any) -> None:
            if not event.is_directory:
                self.queue(event.dest_path, "moved")

    observer = Observer()
    handler = NeutronEventHandler()
    try:
        for target in targets:
            observer.schedule(handler, str(target), recursive=True)
        observer.start()
    except (OSError, RuntimeError) as error:
        try:
            observer.stop()
            observer.join(timeout=2)
        except RuntimeError:
            pass
        emit("watch-fallback", reason=str(error), backend="polling")
        return watch_targets_polling_fallback()

    emit(
        "watch-ready",
        targets=[str(target) for target in targets],
        tracked=0,
        max_files=max_files,
        backend="watchdog",
        debounce_ms=round(WATCH_DEBOUNCE_SECONDS * 1000),
        yara=yara_status,
    )

    # Native file events only arrive after the watcher starts. Perform one
    # bounded initial pass so an already-downloaded known threat is not left
    # untouched until it changes again.
    initial_scanned = 0
    for initial_path in iter_files(targets, max_files, exclusions):
        if should_ignore_watch_path(initial_path, exclusions):
            continue
        initial_scanned += 1
        emit_watch_result(
            initial_path, "startup-scan", signatures, yara_rules, exclusions, cache_session
        )
    flush_analysis_cache(cache_session)
    emit("watch-initial-scan-complete", scanned=initial_scanned)

    try:
        while True:
            time.sleep(0.2)
            now = time.monotonic()
            while True:
                try:
                    raw_path, event_kind, signature = event_queue.get_nowait()
                except queue.Empty:
                    break
                pending[raw_path] = {
                    "path": Path(raw_path),
                    "event_kind": event_kind,
                    "due_at": now + WATCH_DEBOUNCE_SECONDS,
                    "signature": signature,
                }
            due_paths = [raw_path for raw_path, item in pending.items() if item["due_at"] <= now]
            for raw_path in due_paths:
                item = pending.get(raw_path)
                if item is None:
                    continue
                path = item["path"]
                current_signature = file_signature(path)
                if current_signature is None:
                    pending.pop(raw_path, None)
                    continue
                if current_signature != item["signature"]:
                    item["signature"] = current_signature
                    item["due_at"] = now + WATCH_SETTLE_SECONDS
                    continue
                if processed_signatures.get(raw_path) == current_signature:
                    pending.pop(raw_path, None)
                    continue
                pending.pop(raw_path, None)
                processed_signatures[raw_path] = current_signature
                if len(processed_signatures) > max_files:
                    processed_signatures.pop(next(iter(processed_signatures)))
                emit_watch_result(
                    path, item["event_kind"], signatures, yara_rules, exclusions, cache_session
                )
                flush_analysis_cache(cache_session)
    except KeyboardInterrupt:
        flush_analysis_cache(cache_session)
        emit("watch-stopped")
        return 0
    finally:
        observer.stop()
        observer.join(timeout=5)


def protection_history(limit: int) -> int:
    try:
        emit("protection-history", events=read_protection_history(limit))
        return 0
    except (OSError, sqlite3.Error):
        emit("error", code="PROTECTION_HISTORY_UNAVAILABLE", message="Koruma geçmişi okunamadı.")
        return 2


def signature_status() -> int:
    try:
        emit("signature-status", **signature_status_payload())
        return 0
    except (OSError, sqlite3.Error):
        emit("error", code="SIGNATURE_STATUS_UNAVAILABLE", message="İmza veritabanı okunamadı.")
        return 2


def settings_status() -> int:
    try:
        emit("settings", settings=read_app_settings())
        return 0
    except (OSError, sqlite3.Error, ValueError):
        emit("error", code="SETTINGS_UNAVAILABLE", message="Ayarlar okunamadı.")
        return 2


def setting_update(key: str, raw_value: str) -> int:
    try:
        value = json.loads(raw_value)
        emit("settings-updated", settings=write_app_setting(key, value), changed_key=key)
        return 0
    except (OSError, sqlite3.Error, ValueError, TypeError, json.JSONDecodeError) as error:
        emit("error", code="SETTING_UPDATE_FAILED", message=f"Ayar kaydedilemedi: {error}")
        return 2


def exclusions_status() -> int:
    try:
        emit("exclusions", **exclusions_payload())
        return 0
    except (OSError, sqlite3.Error):
        emit("error", code="EXCLUSIONS_UNAVAILABLE", message="İstisnalar okunamadı.")
        return 2


def exclusion_add(kind: str, value: str, label: str | None = None) -> int:
    try:
        emit("exclusions-updated", **add_exclusion(kind, value, label))
        return 0
    except (OSError, sqlite3.Error, ValueError) as error:
        emit("error", code="EXCLUSION_ADD_FAILED", message=f"İstisna eklenemedi: {error}")
        return 2


def exclusion_remove(item_id: int) -> int:
    try:
        emit("exclusions-updated", **remove_exclusion(item_id))
        return 0
    except (OSError, sqlite3.Error, ValueError) as error:
        emit("error", code="EXCLUSION_REMOVE_FAILED", message=f"İstisna kaldırılamadı: {error}")
        return 2


def proton_version_tuple(value: str) -> tuple[int, int, int]:
    if not PROTON_VERSION_PATTERN.fullmatch(value):
        raise ValueError("Proton sürümü x.xx.xxx biçiminde değil")
    parts = tuple(int(part) for part in value.split("."))
    return parts[0], parts[1], parts[2]


def validate_proton_payload(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict) or payload.get("schema") != "neutron.proton.payload/v1":
        raise ValueError("Proton paket şeması geçersiz")
    if payload.get("database_name") != SIGNATURE_DATABASE_NAME:
        raise ValueError("Proton veritabanı adı geçersiz")
    version = str(payload.get("version", ""))
    proton_version_tuple(version)
    created_at = str(payload.get("created_at", ""))
    if not created_at or len(created_at) > 64:
        raise ValueError("Proton oluşturma zamanı geçersiz")

    raw_provenance = payload.get("provenance")
    if not isinstance(raw_provenance, dict):
        raise ValueError("Proton provenance is invalid")
    provenance = {key: str(raw_provenance.get(key, "")).strip() for key in (
        "source_name", "source_url", "collected_at", "license", "review_policy"
    )}
    if (not all(provenance.values()) or len(provenance["source_name"]) > 120
            or len(provenance["source_url"]) > 1024 or not provenance["source_url"].startswith("https://")
            or len(provenance["license"]) > 160 or len(provenance["review_policy"]) > 240):
        raise ValueError("Proton provenance is incomplete or invalid")
    try:
        datetime.fromisoformat(provenance["collected_at"].replace("Z", "+00:00"))
    except ValueError:
        raise ValueError("Proton provenance timestamp is invalid") from None

    raw_web_indicators = payload.get("web_indicators", [])
    if not isinstance(raw_web_indicators, list) or len(raw_web_indicators) > MAX_PROTON_WEB_INDICATORS:
        raise ValueError("Proton web göstergesi listesi geçersiz")
    web_indicators: list[dict[str, str]] = []
    seen_web: set[tuple[str, str]] = set()
    for index, entry in enumerate(raw_web_indicators):
        if not isinstance(entry, dict):
            raise ValueError(f"Proton web göstergesi {index} geçersiz")
        indicator_type = str(entry.get("type", "")).lower()
        value = str(entry.get("value", "")).strip().lower()
        name = str(entry.get("name", "")).strip()
        severity = str(entry.get("severity", "")).lower()
        identity = (indicator_type, value)
        if (indicator_type not in {"domain", "url"} or not value or len(value) > 2048 or identity in seen_web
                or not name or len(name) > 160 or severity not in {"low", "medium", "high", "critical"}):
            raise ValueError(f"Proton web göstergesi {index} alanları geçersiz")
        if indicator_type == "domain" and not re.fullmatch(r"[a-z0-9.-]+", value):
            raise ValueError(f"Proton domain göstergesi {index} geçersiz")
        if indicator_type == "url" and urlsplit(value).scheme not in {"http", "https"}:
            raise ValueError(f"Proton URL göstergesi {index} geçersiz")
        seen_web.add(identity)
        web_indicators.append({"type": indicator_type, "value": value, "name": name, "severity": severity})

    raw_signatures = payload.get("signatures")
    if not isinstance(raw_signatures, list) or len(raw_signatures) > MAX_PROTON_SIGNATURES:
        raise ValueError("Proton hash imzası listesi geçersiz")
    seen_hashes: set[str] = set()
    signatures: list[dict[str, Any]] = []
    for index, raw_signature in enumerate(raw_signatures):
        if not isinstance(raw_signature, dict):
            raise ValueError(f"Proton hash imzası {index} geçersiz")
        digest = str(raw_signature.get("sha256", "")).lower()
        if not PROTON_SHA256_PATTERN.fullmatch(digest) or digest in seen_hashes:
            raise ValueError(f"Proton SHA-256 girdisi {index} geçersiz veya yinelenmiş")
        seen_hashes.add(digest)
        file_size = raw_signature.get("file_size")
        if isinstance(file_size, bool) or not isinstance(file_size, int) or file_size < 0:
            raise ValueError(f"Proton dosya boyutu {index} geçersiz")
        name = str(raw_signature.get("name", "")).strip()
        severity = str(raw_signature.get("severity", "")).lower()
        if not name or len(name) > 160 or severity not in {"low", "medium", "high", "critical"}:
            raise ValueError(f"Proton hash imzası {index} alanları geçersiz")
        signatures.append({
            "sha256": digest,
            "file_size": file_size,
            "name": name,
            "severity": severity,
        })

    raw_rules = payload.get("yara_rules")
    if not isinstance(raw_rules, list) or len(raw_rules) > MAX_PROTON_RULES:
        raise ValueError("Proton YARA listesi geçersiz")
    seen_rule_names: set[str] = set()
    total_rule_bytes = 0
    rules: list[dict[str, str]] = []
    for index, raw_rule in enumerate(raw_rules):
        if not isinstance(raw_rule, dict):
            raise ValueError(f"Proton YARA girdisi {index} geçersiz")
        name = str(raw_rule.get("name", ""))
        normalized_name = name.lower()
        if not PROTON_RULE_NAME_PATTERN.fullmatch(name) or normalized_name in seen_rule_names:
            raise ValueError(f"Proton YARA dosya adı {index} geçersiz veya yinelenmiş")
        seen_rule_names.add(normalized_name)
        content = raw_rule.get("content")
        if not isinstance(content, str) or "\x00" in content:
            raise ValueError(f"Proton YARA içeriği {index} geçersiz")
        content_bytes = content.encode("utf-8")
        total_rule_bytes += len(content_bytes)
        if len(content_bytes) > MAX_PROTON_RULE_BYTES or total_rule_bytes > MAX_PROTON_TOTAL_RULE_BYTES:
            raise ValueError("Proton YARA içeriği izin verilen boyutu aşıyor")
        digest = str(raw_rule.get("sha256", "")).lower()
        if not PROTON_SHA256_PATTERN.fullmatch(digest) or hashlib.sha256(content_bytes).hexdigest() != digest:
            raise ValueError(f"Proton YARA özeti {index} uyuşmuyor")
        rules.append({"name": name, "sha256": digest, "content": content})

    if not signatures and not rules and not web_indicators:
        raise ValueError("Proton paketi boş")
    return {
        "version": version,
        "created_at": created_at,
        "provenance": provenance,
        "web_indicators": web_indicators,
        "signatures": signatures,
        "rules": rules,
    }


def activate_proton_payload(payload: dict[str, Any], *, allow_downgrade: bool, action: str) -> None:
    """Validate and activate one definition set in a single SQLite transaction.

    Every successfully activated payload is retained as a bounded last-known-good
    snapshot. A rollback therefore restores the exact validated payload, not a
    partly copied collection of definition tables.
    """
    compiled, yara_result = load_yara_rules(payload["rules"])
    if yara is None or compiled is None:
        raise ValueError(yara_result.get("message", "YARA kuralları doğrulanamadı"))

    activated_at = datetime.now(timezone.utc).isoformat()
    payload_json = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    with open_database() as connection:
        metadata = dict(connection.execute("SELECT key, value FROM signature_metadata").fetchall())
        current_version = metadata.get("version", BUILTIN_SIGNATURE_VERSION)
        if not allow_downgrade and proton_version_tuple(payload["version"]) < proton_version_tuple(current_version):
            raise ValueError("Eski Proton sürümüne dönüş yalnızca doğrulanmış geri alma akışıyla yapılabilir")

        connection.execute("BEGIN IMMEDIATE")
        connection.execute("DELETE FROM signatures WHERE source = 'proton'")
        connection.executemany(
            """
            INSERT OR IGNORE INTO signatures (
              sha256, file_size, name, severity, source, enabled, added_at
            ) VALUES (?, ?, ?, ?, 'proton', 1, ?)
            """,
            [(item["sha256"], item["file_size"], item["name"], item["severity"], payload["created_at"])
             for item in payload["signatures"]],
        )
        connection.execute("DELETE FROM proton_yara_rules")
        connection.executemany(
            "INSERT INTO proton_yara_rules (name, sha256, source_text, installed_at) VALUES (?, ?, ?, ?)",
            [(rule["name"], rule["sha256"], rule["content"], payload["created_at"])
             for rule in payload["rules"]],
        )
        connection.execute(
            """
            INSERT INTO proton_provenance (
              id, source_name, source_url, collected_at, license, review_policy, installed_at
            ) VALUES (1, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
              source_name=excluded.source_name, source_url=excluded.source_url,
              collected_at=excluded.collected_at, license=excluded.license,
              review_policy=excluded.review_policy, installed_at=excluded.installed_at
            """,
            (payload["provenance"]["source_name"], payload["provenance"]["source_url"],
             payload["provenance"]["collected_at"], payload["provenance"]["license"],
             payload["provenance"]["review_policy"], activated_at),
        )
        connection.execute("DELETE FROM proton_web_indicators")
        connection.executemany(
            "INSERT INTO proton_web_indicators (indicator_type, value, name, severity, installed_at) VALUES (?, ?, ?, ?, ?)",
            [(item["type"], item["value"], item["name"], item["severity"], payload["created_at"])
             for item in payload["web_indicators"]],
        )
        for key, value in {
            "version": payload["version"], "database_name": SIGNATURE_DATABASE_NAME,
            "updated_at": activated_at, "source": "github-release",
        }.items():
            connection.execute(
                "INSERT INTO signature_metadata (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )
        connection.execute("UPDATE proton_snapshots SET active = 0")
        connection.execute(
            """
            INSERT INTO proton_snapshots (version, payload_json, installed_at, last_activated_at, active)
            VALUES (?, ?, ?, ?, 1)
            ON CONFLICT(version) DO UPDATE SET payload_json=excluded.payload_json,
              last_activated_at=excluded.last_activated_at, active=1
            """,
            (payload["version"], payload_json, activated_at, activated_at),
        )
        connection.execute(
            "INSERT INTO proton_update_history (occurred_at, action, version, status, detail) VALUES (?, ?, ?, 'success', ?)",
            (activated_at, action, payload["version"], f"{len(payload['signatures'])} imza, {len(payload['rules'])} YARA"),
        )
        connection.execute(
            "DELETE FROM proton_snapshots WHERE version IN (SELECT version FROM proton_snapshots WHERE active = 0 ORDER BY last_activated_at DESC LIMIT -1 OFFSET 4)"
        )


def validate_proton_snapshot(snapshot: Any) -> dict[str, Any]:
    if not isinstance(snapshot, dict):
        raise ValueError("Proton geri dönüş anlık görüntüsü geçersiz")
    return validate_proton_payload({
        "schema": "neutron.proton.payload/v1",
        "database_name": SIGNATURE_DATABASE_NAME,
        "version": snapshot.get("version"),
        "created_at": snapshot.get("created_at"),
        "provenance": snapshot.get("provenance"),
        "web_indicators": snapshot.get("web_indicators", []),
        "signatures": snapshot.get("signatures", []),
        "yara_rules": snapshot.get("rules", []),
    })


def install_proton_from_stdin() -> int:
    try:
        raw_payload = sys.stdin.buffer.read(MAX_PROTON_PAYLOAD_BYTES + 1)
        if len(raw_payload) > MAX_PROTON_PAYLOAD_BYTES:
            raise ValueError("Proton yükü izin verilen boyutu aşıyor")
        payload = validate_proton_payload(json.loads(raw_payload.decode("utf-8")))
        activate_proton_payload(payload, allow_downgrade=False, action="install")
        emit("signature-updated", **signature_status_payload(), installed=True, yara_rule_files=len(payload["rules"]))
        return 0
    except (UnicodeError, json.JSONDecodeError, ValueError, OSError, sqlite3.Error) as error:
        emit("error", code="PROTON_INSTALL_FAILED", message=f"Proton kurulamadı: {error}")
        return 2


def rollback_proton(version: str | None = None) -> int:
    try:
        with open_database() as connection:
            if version:
                row = connection.execute(
                    "SELECT version, payload_json FROM proton_snapshots WHERE version = ? AND active = 0", (version,)
                ).fetchone()
            else:
                row = connection.execute(
                    "SELECT version, payload_json FROM proton_snapshots WHERE active = 0 ORDER BY last_activated_at DESC LIMIT 1"
                ).fetchone()
        if row is None:
            raise ValueError("Geri dönülebilecek doğrulanmış Proton sürümü yok")
        payload = validate_proton_snapshot(json.loads(str(row[1])))
        activate_proton_payload(payload, allow_downgrade=True, action="rollback")
        emit("signature-rolled-back", **signature_status_payload(), rolled_back=True)
        return 0
    except (json.JSONDecodeError, ValueError, OSError, sqlite3.Error) as error:
        emit("error", code="PROTON_ROLLBACK_FAILED", message=f"Proton geri alınamadı: {error}")
        return 2


def signature_update() -> int:
    """Install bundled definitions only; this command never uses the network."""
    try:
        now = datetime.now(timezone.utc).isoformat()
        with open_database() as connection:
            connection.execute(
                """
                INSERT INTO signature_metadata (key, value) VALUES ('version', ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (BUILTIN_SIGNATURE_VERSION,),
            )
            connection.execute(
                """
                INSERT INTO signature_metadata (key, value) VALUES ('database_name', ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (SIGNATURE_DATABASE_NAME,),
            )
            connection.execute(
                """
                INSERT INTO signature_metadata (key, value) VALUES ('updated_at', ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (now,),
            )
        emit("signature-updated", **signature_status_payload())
        return 0
    except (OSError, sqlite3.Error):
        emit("error", code="SIGNATURE_UPDATE_FAILED", message="Yerel imzalar güncellenemedi.")
        return 2


def yara_status() -> int:
    _compiled, status = load_yara_rules()
    emit("yara-status", **status)
    return 0 if status.get("available") and status.get("rule_files", 0) > 0 and _compiled else 2


def scan_targets(
    targets: list[Path], mode: str, maximum_files: int | None = None,
    maximum_depth: int = MAX_DEPTH,
) -> int:
    started_at = time.monotonic()
    completed_at = datetime.now(timezone.utc).isoformat()
    if not targets:
        emit("error", code="NO_TARGETS", message="Taranacak klasör bulunamadı.")
        return 2

    settings = read_app_settings()
    max_files = maximum_files or resolved_max_files(settings["scan_max_files"])
    # Cloud lookup only ever runs from explicit user-triggered scans, never
    # from --watch/--watch-web real-time protection -- see
    # cloud_reputation_lookup for why (avoids adding network latency to
    # every real-time file event).
    cloud_lookup = bool(settings.get("cloud_lookup_enabled"))
    malwarebazaar_api_key = str(settings.get("malwarebazaar_api_key") or "")
    virustotal_api_key = str(settings.get("virustotal_api_key") or "")
    emit("started", mode=mode, targets=[target.name for target in targets], max_files=max_files)
    scanned = 0
    findings: list[Finding] = []
    signatures = load_signatures()
    yara_rules, yara_status = load_yara_rules()
    exclusions = load_exclusion_set()
    cache_session = open_analysis_cache_session(str(yara_status.get("fingerprint", "none")))
    emit("engine-status", yara=yara_status)

    try:
        for file_path in iter_files(targets, max_files, exclusions, maximum_depth):
            scanned += 1
            findings.extend(inspect_file_cached(
                file_path, signatures, yara_rules, exclusions, cache_session,
                cloud_lookup, malwarebazaar_api_key, virustotal_api_key,
            ))
            if scanned % PROGRESS_INTERVAL == 0:
                emit(
                    "progress", scanned=scanned, max_files=max_files,
                    cache_hits=cache_session.hits, cache_misses=cache_session.misses,
                )
    finally:
        cache_hits = cache_session.hits
        cache_misses = cache_session.misses
        flush_analysis_cache(cache_session)

    confirmed = [finding for finding in findings if finding.kind in {"test-signature", "signature"}]
    review = [
        finding for finding in findings
        if finding.kind in {"review", "yara", "pe-analysis", "archive-warning", "archive-structure"}
    ]

    # Act on what was found, do not merely report it.
    #
    # Automatic quarantine used to live only in the real-time watchers, so a
    # scan could say "signature matched" while leaving the file exactly where
    # it was. That is indefensible for an antivirus: the user asked it to
    # scan, it identified known malware by exact hash, and then did nothing.
    #
    # The same gate the watchers use is reused rather than reimplemented, so
    # every existing safety rule still applies unchanged: nothing under a
    # protected system folder, nothing belonging to Neutron itself, nothing
    # excluded, and the burst brake that stops a bad signature batch sweeping
    # a directory. Findings it declines stay pending for the user, exactly as
    # before.
    quarantined: list[dict[str, Any]] = []
    for finding in confirmed:
        try:
            event_id = save_protection_event(f"{mode}-scan", finding)
            quarantine_item_id = auto_quarantine_confirmed_finding(event_id, finding)
        except (OSError, sqlite3.Error):
            continue
        if quarantine_item_id is not None:
            quarantined.append({"path": finding.path, "quarantine_item_id": quarantine_item_id})

    elapsed_ms = round((time.monotonic() - started_at) * 1000)
    limited = scanned >= max_files
    history_saved = False
    scan_run_id: int | None = None
    try:
        scan_run_id = save_scan_history(
            completed_at=completed_at,
            mode=mode,
            targets=targets,
            scanned=scanned,
            confirmed_count=len(confirmed),
            review_count=len(review),
            elapsed_ms=elapsed_ms,
            limited=limited,
            findings=findings,
        )
        history_saved = True
    except (OSError, sqlite3.Error):
        # Geçmişe yazılamaması taramayı başarısız saymaz; motor sonucu yine verir.
        history_saved = False

    emit(
        "complete",
        scanned=scanned,
        confirmed_count=len(confirmed),
        review_count=len(review),
        quarantined_count=len(quarantined),
        quarantined=quarantined[:25],
        findings=[asdict(finding) for finding in findings[:25]],
        elapsed_ms=elapsed_ms,
        limited=limited,
        history_saved=history_saved,
        scan_run_id=scan_run_id,
        cache_hits=cache_hits,
        cache_misses=cache_misses,
    )
    return 0


def quick_scan() -> int:
    return scan_targets(home_scan_targets(), "quick")


def scheduled_quick_scan() -> int:
    """Same as quick_scan(), tagged distinctly in scan history so the UI can
    show it was triggered automatically rather than by the user clicking
    Tara. Invoked by Electron's own daily timer (main.cjs), not by a Windows
    Scheduled Task -- Neutron is already tray-resident whenever protection is
    on, so no extra elevated task registration is needed for this."""
    return scan_targets(home_scan_targets(), "scheduled")


def custom_scan(raw_target: str) -> int:
    """Yalnızca Electron'un kullanıcıya seçtirdiği tek klasörü tarar."""
    try:
        target = Path(raw_target).expanduser().resolve(strict=True)
    except (OSError, RuntimeError):
        emit("error", code="INVALID_TARGET", message="Seçilen klasör kullanılamıyor.")
        return 2

    if not target.is_dir() and not target.is_file():
        emit("error", code="INVALID_TARGET", message="Seçilen dosya veya klasör kullanılamıyor.")
        return 2
    return scan_targets([target], "custom")


def full_scan(raw_target: str) -> int:
    try:
        target = Path(raw_target).resolve(strict=True)
    except (OSError, RuntimeError):
        emit("error", code="INVALID_TARGET", message="Seçilen sürücü kullanılamıyor.")
        return 2
    if not target.is_dir():
        emit("error", code="INVALID_TARGET", message="Tam tarama hedefi bir sürücü olmalı.")
        return 2
    return scan_targets([target], "full", MAX_FULL_SCAN_FILES, 64)


def history(limit: int) -> int:
    try:
        emit("history", scans=read_scan_history(limit))
        return 0
    except (OSError, sqlite3.Error):
        emit("error", code="HISTORY_UNAVAILABLE", message="Yerel tarama geçmişi okunamadı.")
        return 2


def start_parent_liveness_watch() -> None:
    """Exit as soon as the parent process goes away.

    The watchers are long-lived child processes with no window. If Electron is
    terminated without running its shutdown path -- Task Manager, a crash, or
    Windows tearing processes down at shutdown -- the children are orphaned and
    keep running. Windows then blocks shutdown on a process it can only
    describe as a nameless background task, and the data directory stays
    locked, which is also what makes an uninstall fail on in-use files.

    stdin is an anonymous pipe whose only writer is the parent, so read()
    returning EOF means the parent is gone. This is only armed when
    --exit-with-parent is passed, because with stdio 'ignore' stdin is the
    null device and would report EOF instantly.
    """
    def wait_for_parent() -> None:
        try:
            sys.stdin.buffer.read(1)
        except (OSError, ValueError):
            pass
        # os._exit, not sys.exit: this runs on a daemon thread and must take
        # the process down without waiting for the watcher loops.
        os._exit(0)

    threading.Thread(target=wait_for_parent, name="parent-liveness", daemon=True).start()


def main() -> int:
    parser = argparse.ArgumentParser(description="Neutron salt-okunur hızlı tarama motoru")
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--quick-scan", action="store_true", help="Aktif kullanıcı profili ve Temp klasörlerini tara")
    action.add_argument("--scheduled-quick-scan", action="store_true", help="Zamanlanmış otomatik hızlı tarama (Electron zamanlayıcısı tarafından çağrılır)")
    action.add_argument("--engine-version", action="store_true", help="Neutron motor sürümünü göster")
    action.add_argument("--scan-path", metavar="HEDEF", help="Kullanıcının seçtiği tek dosya veya klasörü tara")
    action.add_argument("--full-scan", metavar="SURUCU", help="Seçilen sürücüyü tam tara")
    action.add_argument("--history", action="store_true", help="Yerel tarama geçmişini oku")
    action.add_argument("--watch", action="store_true", help="Yeni ve değişen dosyaları izle")
    action.add_argument("--watch-behavior", action="store_true", help="Süreçleri ve kalıcılık noktalarını izle")
    action.add_argument("--watch-web", action="store_true", help="İndirilen dosyaları ve kaynak adreslerini izle")
    action.add_argument("--watch-network", action="store_true", help="Bilinen kötü amaçlı IP adreslerine giden bağlantıları izle")
    action.add_argument("--service-host", action="store_true", help="Tüm koruma bileşenlerini LocalSystem servisi olarak tek süreçte çalıştır")
    action.add_argument("--watch-memory", action="store_true", help="Yeni başlayan süreçlerin belleğini YARA ve RWX-özel-bölge sezgisiyle tara")
    action.add_argument("--watch-usb", action="store_true", help="Takılan çıkarılabilir medyayı autorun.inf ve dosyalar için tara")
    action.add_argument("--watch-ransomware", action="store_true", help="Tuzak dosyalarını ve toplu şifreleme belirtilerini izle")
    action.add_argument("--amsi-service", action="store_true", help="AMSI ön-çalıştırma koruma servisini başlat")
    action.add_argument("--check-url", metavar="URL", help="URL veya domain itibarını yerel Proton verisinde denetle")
    action.add_argument("--protection-history", action="store_true", help="Gerçek zamanlı koruma olaylarını oku")
    action.add_argument("--protection-action", metavar="ID", type=int, help="Gerçek zamanlı koruma olayına işlem uygula")
    action.add_argument("--incident-remediate", metavar="ID", type=int, help="Koruma olayına günlüklenmiş ve geri alınabilir müdahale uygula")
    action.add_argument("--incident-rollback", metavar="ID", type=int, help="Olay müdahalesini geri al")
    action.add_argument("--incident-status", metavar="ID", type=int, help="Olay müdahalesi ve eylemlerini oku")
    action.add_argument("--incident-record-firewall", metavar="ID", type=int, help="Uygulanan olay güvenlik duvarı kuralını günlüğe yaz")
    action.add_argument("--incident-finalize-external-rollback", metavar="ID", type=int, help="Harici güvenlik duvarı geri almasını tamamla")
    action.add_argument("--signature-status", action="store_true", help="Yerel imza veritabanı durumunu oku")
    action.add_argument("--signature-update", action="store_true", help="Paketle gelen yerel imzaları yükle")
    action.add_argument("--install-proton-stdin", action="store_true", help="Doğrulanmış Proton yükünü standart girdiden kur")
    action.add_argument("--rollback-proton", nargs="?", const="", metavar="SURUM", help="Son doğrulanmış Proton sürümüne veya belirtilen arşiv sürümüne dön")
    action.add_argument("--yara-status", action="store_true", help="YARA motorunu ve kurallarını doğrula")
    action.add_argument("--cache-status", action="store_true", help="Yerel analiz önbelleği durumunu oku")
    action.add_argument("--cache-clear", action="store_true", help="Yerel analiz önbelleğini temizle")
    action.add_argument("--settings", action="store_true", help="Uygulama ayarlarını oku")
    action.add_argument("--setting-set", metavar="ANAHTAR", help="Tek bir uygulama ayarını güncelle")
    action.add_argument("--exclusions", action="store_true", help="Etkin istisnaları ve değişiklik geçmişini oku")
    action.add_argument("--exclusion-add-folder", metavar="KLASOR", help="Klasör istisnası ekle")
    action.add_argument("--exclusion-add-extension", metavar="UZANTI", help="Dosya uzantısı istisnası ekle")
    action.add_argument("--exclusion-add-hash", metavar="SHA256", help="Güvenilir SHA-256 istisnası ekle")
    action.add_argument("--exclusion-remove", metavar="ID", type=int, help="İstisnayı kaldır")
    action.add_argument("--quarantine", metavar="DOSYA", help="Onaylanan dosyayı karantinaya taşı")
    action.add_argument("--quarantine-list", action="store_true", help="Etkin karantina kayıtlarını oku")
    action.add_argument("--restore", metavar="ID", type=int, help="Karantinadaki dosyayı geri yükle")
    action.add_argument("--delete-quarantine", metavar="ID", type=int, help="Karantinadaki dosyayı kalıcı sil")
    action.add_argument("--firewall-list", action="store_true", help="Neutron'un eklediği güvenlik duvarı kurallarını oku")
    action.add_argument("--firewall-recent-apps", action="store_true", help="Şu an ağ bağlantısı olan uygulamaları listele")
    action.add_argument("--firewall-add-rule", metavar="DOSYA", help="Uygulama için güvenlik duvarı kuralı kaydet")
    action.add_argument("--firewall-remove-rule", metavar="ID", type=int, help="Güvenlik duvarı kuralını kaldır")
    action.add_argument("--firewall-toggle-rule", metavar="ID", type=int, help="Güvenlik duvarı kuralını aç/kapat")
    action.add_argument("--startup-list", action="store_true", help="Başlangıç/otomatik çalışma öğelerini listele")
    action.add_argument("--startup-disable", action="store_true", help="Başlangıç öğesini devre dışı bırak (--value-json ile)")
    action.add_argument("--startup-restore", metavar="ID", type=int, help="Devre dışı bırakılan başlangıç öğesini geri yükle")
    action.add_argument("--startup-finalize-disable", metavar="ID", type=int, help="Elevated devre dışı bırakmayı onayla")
    action.add_argument("--startup-cancel-disable", metavar="ID", type=int, help="Başarısız elevated devre dışı bırakmayı geri al")
    action.add_argument("--startup-finalize-restore", metavar="ID", type=int, help="Elevated geri yüklemeyi onayla")
    action.add_argument("--check-vulnerable-software", action="store_true", help="Yüklü yazılımı bilinen zafiyetli sürümlere göre tara")
    action.add_argument("--system-audit", action="store_true", help="Windows güvenlik duruşunu salt okunur denetle")
    action.add_argument("--ml-shadow-report", action="store_true", help="Gölge modda kaydedilen model gözlemlerini raporla")
    action.add_argument("--temp-usage", action="store_true", help="Geçici dosya klasörlerinin kapladığı alanı hesapla")
    action.add_argument("--temp-clean", action="store_true", help="Geçici dosya klasörlerini temizle")
    action.add_argument("--memory-status", action="store_true", help="Bellek kullanımını ve en çok tüketen süreçleri oku")
    action.add_argument("--memory-trim", action="store_true", help="Erişilebilir süreçlerin çalışma kümesini küçült")
    parser.add_argument("--firewall-action", choices=("block", "allow"), default="block", help="Güvenlik duvarı kuralı eylemi")
    parser.add_argument("--firewall-direction", choices=("out", "in"), default="out", help="Güvenlik duvarı kuralı yönü")
    parser.add_argument("--reason", default="Kullanıcı onaylı tarama bulgusu", help="Karantina nedeni")
    parser.add_argument("--disposition", choices=("quarantine", "trust", "ignore"), help="Koruma olayı işlemi")
    parser.add_argument("--label", default=None, help="İstisna açıklaması")
    parser.add_argument("--limit", type=int, default=5, help="Döndürülecek en fazla geçmiş kaydı")
    parser.add_argument("--value-json", default="null", help="Ayar için JSON değeri")
    parser.add_argument("--json-lines", action="store_true", help="Electron IPC için JSON Lines çıktısı")
    parser.add_argument("--exit-with-parent", action="store_true",
                        help="Ana süreç kapandığında bu süreci de sonlandır (stdin borusu gerektirir)")
    args = parser.parse_args()

    if args.exit_with_parent:
        start_parent_liveness_watch()

    if args.engine_version:
        emit("engine-version", version=NEUTRON_ENGINE_VERSION, frozen=bool(getattr(sys, "frozen", False)))
        return 0
    if args.history:
        return history(args.limit)
    if args.full_scan:
        return full_scan(args.full_scan)
    if args.protection_history:
        return protection_history(args.limit)
    if args.protection_action is not None:
        if not args.disposition:
            parser.error("--protection-action ile --disposition gereklidir")
        return protection_event_action(args.protection_action, args.disposition)
    if args.incident_remediate is not None:
        return remediate_protection_event(args.incident_remediate)
    if args.incident_rollback is not None:
        return rollback_response_incident(args.incident_rollback)
    if args.incident_status is not None:
        return incident_status(args.incident_status)
    if args.incident_record_firewall is not None:
        return record_incident_firewall_action(args.incident_record_firewall, args.value_json)
    if args.incident_finalize_external_rollback is not None:
        return finalize_incident_external_rollback(args.incident_finalize_external_rollback)
    if args.signature_status:
        return signature_status()
    if args.signature_update:
        return signature_update()
    if args.install_proton_stdin:
        return install_proton_from_stdin()
    if args.rollback_proton is not None:
        return rollback_proton(args.rollback_proton or None)
    if args.yara_status:
        return yara_status()
    if args.cache_status:
        return analysis_cache_status()
    if args.cache_clear:
        return clear_analysis_cache()
    if args.settings:
        return settings_status()
    if args.setting_set:
        return setting_update(args.setting_set, args.value_json)
    if args.exclusions:
        return exclusions_status()
    if args.exclusion_add_folder:
        return exclusion_add("folder", args.exclusion_add_folder, args.label)
    if args.exclusion_add_extension:
        return exclusion_add("extension", args.exclusion_add_extension, args.label)
    if args.exclusion_add_hash:
        return exclusion_add("hash", args.exclusion_add_hash, args.label)
    if args.exclusion_remove is not None:
        return exclusion_remove(args.exclusion_remove)
    if args.watch:
        return watch_targets()
    if args.watch_behavior:
        return watch_behavior()
    if args.watch_network:
        return watch_network()
    if args.service_host:
        return service_host()
    if args.watch_memory:
        return watch_memory()
    if args.watch_usb:
        return watch_usb()
    if args.watch_ransomware:
        return watch_ransomware()
    if args.watch_web:
        return watch_web()
    if args.amsi_service:
        return amsi_service()
    if args.check_url:
        try:
            emit("url-reputation", **web_reputation(args.check_url))
            return 0
        except ValueError as error:
            emit("error", code="INVALID_URL", message=str(error))
            return 2
    if args.scan_path:
        return custom_scan(args.scan_path)
    if args.scheduled_quick_scan:
        return scheduled_quick_scan()
    if args.quarantine:
        return quarantine_file(args.quarantine, args.reason)
    if args.quarantine_list:
        return read_quarantine()
    if args.restore is not None:
        return update_quarantine_item(args.restore, "restore")
    if args.delete_quarantine is not None:
        return update_quarantine_item(args.delete_quarantine, "delete")
    if args.firewall_list:
        return firewall_list_rules()
    if args.firewall_recent_apps:
        return firewall_recent_apps()
    if args.firewall_add_rule:
        return firewall_add_rule(args.firewall_add_rule, args.firewall_action, args.firewall_direction)
    if args.firewall_remove_rule is not None:
        return firewall_remove_rule(args.firewall_remove_rule)
    if args.firewall_toggle_rule is not None:
        try:
            enabled = bool(json.loads(args.value_json))
        except json.JSONDecodeError:
            emit("error", code="FIREWALL_TOGGLE_INVALID", message="Geçersiz açık/kapalı değeri.")
            return 2
        return firewall_toggle_rule(args.firewall_toggle_rule, enabled)
    if args.startup_list:
        return startup_list_items()
    if args.startup_disable:
        try:
            payload = json.loads(args.value_json)
        except json.JSONDecodeError:
            emit("error", code="STARTUP_INVALID", message="Geçersiz başlangıç öğesi verisi.")
            return 2
        return startup_disable_entry(
            str(payload.get("source", "")), payload.get("hive"), str(payload.get("key_path", "")),
            int(payload.get("view", 0)), str(payload.get("value_name", "")), str(payload.get("command", "")),
        )
    if args.startup_restore is not None:
        return startup_restore_entry(args.startup_restore)
    if args.startup_finalize_disable is not None:
        return startup_finalize_disable(args.startup_finalize_disable)
    if args.startup_cancel_disable is not None:
        return startup_cancel_disable(args.startup_cancel_disable)
    if args.startup_finalize_restore is not None:
        return startup_finalize_restore(args.startup_finalize_restore)
    if args.check_vulnerable_software:
        return check_vulnerable_software()
    if args.system_audit:
        return system_audit()
    if args.ml_shadow_report:
        return ml_shadow_report(args.limit or 25)
    if args.temp_usage:
        return temp_usage()
    if args.temp_clean:
        return temp_clean()
    if args.memory_status:
        return memory_status()
    if args.memory_trim:
        return memory_trim()
    return quick_scan()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        emit("error", code="CANCELLED", message="Tarama iptal edildi.")
        raise SystemExit(130)
