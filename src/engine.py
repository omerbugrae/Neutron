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
import os
import queue
import re
import secrets
import shutil
import socket
import sqlite3
import struct
import subprocess
import sys
import threading
import time
from urllib.parse import urlsplit
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from datetime import datetime, timedelta, timezone

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
ANALYSIS_CACHE_REVISION = "static-analysis-v2-archive"
PROGRESS_INTERVAL = 25
WATCH_INTERVAL_SECONDS = 5.0
BEHAVIOR_INTERVAL_SECONDS = 3.0
NETWORK_INTERVAL_SECONDS = 10.0
WATCH_DEBOUNCE_SECONDS = 0.9
WATCH_SETTLE_SECONDS = 0.65
SIGNATURE_DATABASE_NAME = "Proton"
NEUTRON_ENGINE_VERSION = "0.1.0"
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
    "cloud_lookup_enabled": False,
    "malwarebazaar_api_key": "",
    "virustotal_api_key": "",
    "notifications_enabled": True,
    "watch_paths": [],
    "scan_max_files": MAX_FILES,
}

# EICAR, antivirüs ürünlerini güvenli şekilde denemek için kullanılan zararsız
# standart test dizgesidir. Bu motor yalnızca bu test imzasını kesin bulgu sayar.
EICAR_MARKER = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
# A Neutron-only benign fixture for validating the full quarantine workflow on
# machines where another antivirus locks the industry-standard EICAR file first.
NEUTRON_QUARANTINE_TEST_MARKER = b"NEUTRON_QUARANTINE_SAFE_TEST_V1"
EXECUTABLE_EXTENSIONS = {
    ".bat", ".cmd", ".com", ".dll", ".exe", ".jar", ".js", ".lnk",
    ".msi", ".ps1", ".scr", ".vbe", ".vbs",
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
    risk_score: int
    reasons: tuple[str, ...]


@dataclass
class AnalysisCacheEntry:
    file_size: int
    modified_ns: int
    changed_ns: int
    findings_json: str
    analyzed_at: str


@dataclass
class AnalysisCacheSession:
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
    return {
        "database_name": metadata.get("database_name", SIGNATURE_DATABASE_NAME),
        "version": metadata.get("version", BUILTIN_SIGNATURE_VERSION),
        "updated_at": metadata.get("updated_at"),
        "signature_count": count,
        "web_indicator_count": web_count,
        "source": metadata.get("source", "builtin"),
        "network_used": metadata.get("source") == "github-release",
        "provenance": dict(provenance) if provenance else None,
    }


def normalize_app_setting(key: str, value: Any) -> Any:
    if key not in DEFAULT_APP_SETTINGS:
        raise ValueError("Bilinmeyen ayar")
    if key in {
        "start_with_windows", "protection_enabled", "behavior_protection_enabled", "web_protection_enabled",
        "amsi_protection_enabled", "watchdog_protection_enabled", "wsc_registration_enabled",
        "network_protection_enabled", "service_mode_enabled", "memory_scan_enabled", "usb_protection_enabled",
        "cloud_lookup_enabled", "notifications_enabled",
    }:
        if not isinstance(value, bool):
            raise ValueError("Ayar true veya false olmalı")
        return value
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


def write_app_setting(key: str, value: Any) -> dict[str, Any]:
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
    session = AnalysisCacheSession(proton_version=proton_version, yara_fingerprint=yara_fingerprint)
    cutoff = (datetime.now(timezone.utc) - timedelta(days=ANALYSIS_CACHE_RETENTION_DAYS)).isoformat()
    try:
        with open_database() as connection:
            connection.execute(
                """
                DELETE FROM analysis_cache
                WHERE engine_revision != ? OR proton_version != ? OR yara_fingerprint != ?
                   OR last_used_at < ?
                """,
                (ANALYSIS_CACHE_REVISION, proton_version, yara_fingerprint, cutoff),
            )
            rows = connection.execute(
                """
                SELECT path_key, file_size, modified_ns, changed_ns, findings_json, analyzed_at
                FROM analysis_cache
                WHERE engine_revision = ? AND proton_version = ? AND yara_fingerprint = ?
                ORDER BY last_used_at DESC
                LIMIT ?
                """,
                (ANALYSIS_CACHE_REVISION, proton_version, yara_fingerprint, MAX_ANALYSIS_CACHE_ENTRIES),
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
                container_path=item.get("container_path"),
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
                     ANALYSIS_CACHE_REVISION, session.proton_version, session.yara_fingerprint,
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
            (ANALYSIS_CACHE_REVISION, proton_version, yara_fingerprint),
        ).fetchone()
        hits, misses, stores, updated_at = connection.execute(
            "SELECT hits, misses, stores, updated_at FROM analysis_cache_metrics WHERE id = 1"
        ).fetchone()
    attempts = int(hits) + int(misses)
    return {
        "entries": int(entries), "result_bytes": int(result_bytes), "hits": int(hits),
        "misses": int(misses), "stores": int(stores),
        "hit_rate": round((int(hits) / attempts) * 100, 1) if attempts else 0.0,
        "engine_revision": ANALYSIS_CACHE_REVISION, "updated_at": updated_at,
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


def quarantine_directory() -> Path:
    directory = data_directory() / "quarantine"
    directory.mkdir(parents=True, exist_ok=True)
    return directory.resolve()


def path_is_inside(candidate: Path, parent: Path) -> bool:
    try:
        candidate.resolve().relative_to(parent.resolve())
        return True
    except (OSError, ValueError):
        return False


def quarantine_file(raw_path: str, reason: str) -> int:
    """Move a detected file to a recoverable local quarantine, retrying transient locks."""
    try:
        original = Path(raw_path).resolve(strict=True)
    except (OSError, RuntimeError):
        emit("error", code="QUARANTINE_SOURCE_MISSING", message="Dosya artık bulunamıyor.")
        return 2
    if not original.is_file() or original.is_symlink():
        emit("error", code="QUARANTINE_SOURCE_INVALID", message="Yalnız normal dosyalar karantinaya alınabilir.")
        return 2
    if path_is_inside(original, data_directory()):
        emit("error", code="QUARANTINE_SOURCE_INVALID", message="Neutron veri alanındaki dosyalar karantinaya alınamaz.")
        return 2

    destination_directory = quarantine_directory()
    safe_name = "".join(character if character.isalnum() or character in ".-_" else "_" for character in original.name)
    destination = destination_directory / f"{int(time.time())}-{secrets.token_hex(6)}-{safe_name}"
    digest = sha256_for(original, original.stat().st_size)
    moved = False
    last_error: OSError | sqlite3.Error | None = None
    for attempt in range(5):
        try:
            shutil.move(str(original), str(destination))
            moved = True
            with open_database() as connection:
                cursor = connection.execute(
                """
                INSERT INTO quarantine_items (
                  original_path, stored_path, file_name, sha256, reason, quarantined_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (str(original), str(destination), original.name, digest, reason[:500], datetime.now(timezone.utc).isoformat()),
                )
            emit("quarantined", item_id=int(cursor.lastrowid), file_name=original.name)
            return 0
        except (OSError, sqlite3.Error) as error:
            last_error = error
            if moved and destination.exists() and not original.exists():
                try:
                    shutil.move(str(destination), str(original))
                except OSError:
                    pass
                moved = False
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
                "SELECT original_path, stored_path, file_name FROM quarantine_items WHERE id = ? AND state = 'active'",
                (item_id,),
            ).fetchone()
            if not row:
                emit("error", code="QUARANTINE_ITEM_MISSING", message="Karantina kaydı bulunamadı.")
                return 2
            original, stored, file_name = (Path(row[0]), Path(row[1]), row[2])
            if not path_is_inside(stored, quarantine_directory()) or not stored.is_file():
                emit("error", code="QUARANTINE_FILE_MISSING", message="Karantina dosyası bulunamadı.")
                return 2
            if action == "restore":
                if original.exists():
                    emit("error", code="RESTORE_DESTINATION_EXISTS", message="Orijinal konumda aynı adlı bir dosya var; üzerine yazılmadı.")
                    return 2
                original.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(stored), str(original))
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
              reason, sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.now(timezone.utc).isoformat(),
                event_kind,
                stored_path,
                finding.kind,
                finding.severity,
                stored_reason,
                finding.sha256,
            ),
        )
        return int(cursor.lastrowid)


def auto_quarantine_confirmed_finding(event_id: int | None, finding: Finding) -> int | None:
    """Quarantine only exact known-file signatures; heuristic findings remain user-reviewed."""
    if event_id is None or finding.kind not in {"test-signature", "signature"}:
        return None
    result = quarantine_file(finding.path, finding.reason)
    if result != 0:
        return None
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
                   quarantine_item_id
            FROM protection_events
            ORDER BY CASE WHEN disposition = 'pending' THEN 0 ELSE 1 END,
                     occurred_at DESC, id DESC
            LIMIT ?
            """,
            (max(1, min(limit, 100)),),
        ).fetchall()
    return [dict(row) for row in rows]


def protection_event_action(item_id: int, action: str) -> int:
    if action not in {"quarantine", "trust", "ignore"}:
        emit("error", code="PROTECTION_ACTION_INVALID", message="Desteklenmeyen tehdit işlemi.")
        return 2
    try:
        with open_database() as connection:
            connection.row_factory = sqlite3.Row
            event = connection.execute(
                """
                SELECT id, file_path, reason, sha256, disposition
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

        disposition = {"quarantine": "quarantined", "trust": "trusted", "ignore": "ignored"}[action]
        quarantine_item_id: int | None = None
        if action == "trust":
            digest = str(event["sha256"] or "")
            if not PROTON_SHA256_PATTERN.fullmatch(digest):
                raise ValueError("Bu bulgunun güvenilir olarak kaydedilebilecek SHA-256 özeti yok")
            current = load_exclusion_set()
            if digest not in current.hashes:
                add_exclusion("hash", digest, str(event["file_path"]))
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


def verify_windows_catalog_signature(path: Path) -> str:
    """Ask Windows for embedded or catalog Authenticode status only on risky files."""
    if os.name != "nt":
        return "not-embedded"
    script = (
        "$signature = Get-AuthenticodeSignature -LiteralPath $args[0]; "
        "[Console]::Out.Write($signature.Status.ToString())"
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
        return "present-unverified"
    status = result.stdout.strip().casefold()
    if result.returncode == 0 and status == "valid":
        return "trusted"
    if status == "notsigned":
        return "unsigned"
    return "invalid" if status else "present-unverified"


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
        for section in sections:
            flags = int(section.Characteristics)
            executable = bool(flags & 0x20000000)
            writable = bool(flags & 0x80000000)
            raw_size = int(section.SizeOfRawData)
            name = section.Name.rstrip(b"\0").decode("ascii", errors="replace") or "isimsiz"
            entropy = float(section.get_entropy()) if raw_size else 0.0
            if executable and writable:
                writable_executable.append(name)
            if executable and raw_size >= 4096 and entropy >= 7.35:
                executable_high_entropy.append(f"{name} ({entropy:.2f})")
        if writable_executable:
            reasons.append((32, f"yazılabilir ve çalıştırılabilir bölüm: {', '.join(writable_executable[:3])}"))
        if executable_high_entropy:
            reasons.append((22, f"yüksek entropili çalıştırılabilir bölüm: {', '.join(executable_high_entropy[:3])}"))

        entry_section = pe.get_section_by_rva(entry_point) if entry_point else None
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
        for points, description, names, threshold in api_groups:
            matches = sorted(import_names.intersection(names))
            if len(matches) >= threshold:
                reasons.append((points, f"{description}: {', '.join(matches[:4])}"))

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
        if payload is None:
            signature_status = verify_authenticode(path, has_signature)
            if not has_signature and preliminary_score >= 20:
                signature_status = verify_windows_catalog_signature(path)
        else:
            # Arşiv üyeleri diske çıkarılmaz; Windows güven zinciri yalnız dosya yolu
            # üzerinden doğrulanabildiğinden gömülü imzanın varlığı raporlanır.
            signature_status = "present-unverified" if has_signature else "not-embedded"
        if signature_status == "invalid":
            reasons.append((25, "gömülü dijital imza Windows doğrulamasından geçmedi"))

        risk_score = min(100, sum(points for points, _reason in reasons))
        if signature_status == "trusted" and risk_score:
            risk_score = max(0, risk_score - 18)
        ordered_reasons = tuple(reason for _points, reason in sorted(reasons, reverse=True))
        return PEAnalysis(
            architecture=architecture,
            image_kind=image_kind,
            entry_point=entry_point,
            section_count=len(sections),
            import_count=import_count,
            signature_status=signature_status,
            risk_score=risk_score,
            reasons=ordered_reasons,
        )
    except (AttributeError, IndexError, MemoryError, OSError, OverflowError, ValueError, pefile.PEFormatError):
        return None
    finally:
        pe.close()


def pe_finding(path: Path, size: int, digest: str | None, payload: bytes | None = None) -> Finding | None:
    analysis = analyze_pe(path, size, payload)
    if analysis is None or analysis.risk_score < 20 or not analysis.reasons:
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
    )


def severity_for_risk(score: int) -> str:
    return "critical" if score >= 85 else "high" if score >= 60 else "medium" if score >= 35 else "low"


def combine_static_risk(findings: list[Finding]) -> None:
    analytical = [
        finding for finding in findings
        if finding.kind in {"review", "yara", "pe-analysis"} and finding.risk_score is not None
    ]
    if len({finding.kind for finding in analytical}) < 2:
        return
    primary = next(
        (finding for finding in analytical if finding.kind == "pe-analysis"),
        max(analytical, key=lambda finding: finding.risk_score or 0),
    )
    scores = sorted((finding.risk_score or 0 for finding in analytical), reverse=True)
    combined = min(100, round(scores[0] + sum(scores[1:]) * 0.35))
    primary.risk_score = combined
    primary.severity = severity_for_risk(combined)
    primary.reason = f"Birleşik statik risk {combined}/100 · {primary.reason}"


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
    if malicious == 0:
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
        structural_finding = pe_finding(path, size, None)
        if structural_finding is not None:
            structural_finding.sha256 = file_digest()
            findings.append(structural_finding)

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
    processes = windows_process_snapshot()
    emit("memory-ready", backend="windows-native", process_count=len(processes), yara=yara_status)

    try:
        while True:
            time.sleep(BEHAVIOR_INTERVAL_SECONDS)
            current_processes = windows_process_snapshot()
            for pid, raw_path in current_processes.items():
                if pid in processes:
                    continue
                image_path = Path(raw_path)
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

                rwx_count = rwx_private_region_count(pid)
                if not yara_hits and rwx_count < 3:
                    continue

                severity = "critical" if yara_hits else "medium"
                reason_parts = []
                if yara_hits:
                    reason_parts.append(f"YARA belleği eşleşmesi: {', '.join(yara_hits[:3])}")
                if rwx_count >= 3:
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
    except KeyboardInterrupt:
        emit("memory-stopped")
        return 0


def persistence_snapshot() -> dict[str, str]:
    """Read common Windows Run keys and Startup folders without modifying them."""
    if os.name != "nt":
        return {}
    snapshot: dict[str, str] = {}
    if winreg is not None:
        registry_locations = (
            (winreg.HKEY_CURRENT_USER, "HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, "HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, "HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, "HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        )
        views = [0]
        for view_name in ("KEY_WOW64_64KEY", "KEY_WOW64_32KEY"):
            view = getattr(winreg, view_name, 0)
            if view and view not in views:
                views.append(view)
        for hive, hive_name, key_path in registry_locations:
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

    startup_directories = []
    app_data = os.environ.get("APPDATA")
    program_data = os.environ.get("ProgramData")
    if app_data:
        startup_directories.append(Path(app_data) / "Microsoft/Windows/Start Menu/Programs/Startup")
    if program_data:
        startup_directories.append(Path(program_data) / "Microsoft/Windows/Start Menu/Programs/StartUp")
    for directory in startup_directories:
        try:
            for entry in directory.iterdir():
                if not entry.is_file() or entry.is_symlink():
                    continue
                stat = entry.stat()
                snapshot[f"startup://{entry}"] = f"{stat.st_mtime_ns}:{stat.st_size}"
        except (OSError, PermissionError):
            continue
    return snapshot


def suspicious_process_finding(path: Path) -> Finding | None:
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
    if location is None:
        return None
    executable_suffixes = {".exe", ".com", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js"}
    if resolved.suffix.casefold() not in executable_suffixes:
        return None
    parts = resolved.name.casefold().split(".")
    double_extension = len(parts) >= 3 and f".{parts[-2]}" in DOCUMENT_EXTENSIONS
    severity = "high" if double_extension else "medium"
    reason = (
        "Belge uzantısını taklit eden yeni süreç çalıştırıldı"
        if double_extension
        else f"{location} içinden yeni bir çalıştırılabilir süreç başlatıldı"
    )
    size = resolved.stat().st_size
    return Finding(
        path=str(resolved),
        kind="behavior",
        severity=severity,
        reason=reason,
        sha256=sha256_for(resolved, size),
    )


def watch_behavior() -> int:
    """Monitor process starts and common persistence points in read-only mode."""
    if os.name != "nt":
        emit("behavior-error", code="UNSUPPORTED_PLATFORM", message="Davranış izleme yalnız Windows'ta kullanılabilir.")
        return 2
    processes = windows_process_snapshot()
    persistence = persistence_snapshot()
    exclusions = load_exclusion_set()
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
            for process_id, raw_path in current_processes.items():
                if process_id in processes:
                    continue
                finding = suspicious_process_finding(Path(raw_path))
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

            current_persistence = persistence_snapshot()
            for identity, value in current_persistence.items():
                if identity in persistence and persistence[identity] == value:
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
            if action == "run_scan":
                mode = str(command.get("mode") or "quick")
                if mode == "full" and command.get("drive"):
                    return {"type": "scan-result", "code": full_scan(str(command["drive"]))}
                if mode == "custom" and command.get("path"):
                    return {"type": "scan-result", "code": scan_targets([Path(str(command["path"]))], "custom")}
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
                PIPE_UNLIMITED_INSTANCES, 1 << 16, 1 << 16, 0, None,
            )
            first_instance = False
            if pipe == INVALID_HANDLE_VALUE:
                time.sleep(1)
                continue
            connected = kernel32.ConnectNamedPipe(pipe, None)
            if not connected and ctypes.get_last_error() != ERROR_PIPE_CONNECTED:
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

    for name, target, enabled in watchers:
        if not enabled:
            continue
        thread = threading.Thread(target=target, name=name, daemon=True)
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

    Known hardening gaps (acceptable for a first pass, not for the long
    term): the pipe uses the default DACL (same-user + admins only, so
    SYSTEM-context hosts cannot reach it yet) and nothing stops another
    local process from squatting on the pipe name before this service
    starts. Both should be addressed with an explicit security descriptor
    and a startup ordering/health-check story before this is relied on.
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
                None,
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


def install_proton_from_stdin() -> int:
    try:
        raw_payload = sys.stdin.buffer.read(MAX_PROTON_PAYLOAD_BYTES + 1)
        if len(raw_payload) > MAX_PROTON_PAYLOAD_BYTES:
            raise ValueError("Proton yükü izin verilen boyutu aşıyor")
        payload = validate_proton_payload(json.loads(raw_payload.decode("utf-8")))

        compiled, yara_result = load_yara_rules(payload["rules"])
        if yara is None or compiled is None:
            raise ValueError(yara_result.get("message", "YARA kuralları doğrulanamadı"))

        with open_database() as connection:
            metadata = dict(connection.execute(
                "SELECT key, value FROM signature_metadata"
            ).fetchall())
            current_version = metadata.get("version", BUILTIN_SIGNATURE_VERSION)
            if proton_version_tuple(payload["version"]) < proton_version_tuple(current_version):
                raise ValueError("Eski Proton sürümüne dönüş reddedildi")

            connection.execute("BEGIN IMMEDIATE")
            connection.execute("DELETE FROM signatures WHERE source = 'proton'")
            connection.executemany(
                """
                INSERT OR IGNORE INTO signatures (
                  sha256, file_size, name, severity, source, enabled, added_at
                ) VALUES (?, ?, ?, ?, 'proton', 1, ?)
                """,
                [
                    (
                        signature["sha256"],
                        signature["file_size"],
                        signature["name"],
                        signature["severity"],
                        payload["created_at"],
                    )
                    for signature in payload["signatures"]
                ],
            )
            connection.execute("DELETE FROM proton_yara_rules")
            connection.executemany(
                """
                INSERT INTO proton_yara_rules (name, sha256, source_text, installed_at)
                VALUES (?, ?, ?, ?)
                """,
                [
                    (rule["name"], rule["sha256"], rule["content"], payload["created_at"])
                    for rule in payload["rules"]
                ],
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
                (
                    payload["provenance"]["source_name"], payload["provenance"]["source_url"],
                    payload["provenance"]["collected_at"], payload["provenance"]["license"],
                    payload["provenance"]["review_policy"], datetime.now(timezone.utc).isoformat(),
                ),
            )
            connection.execute("DELETE FROM proton_web_indicators")
            connection.executemany(
                "INSERT INTO proton_web_indicators (indicator_type, value, name, severity, installed_at) VALUES (?, ?, ?, ?, ?)",
                [(item["type"], item["value"], item["name"], item["severity"], payload["created_at"])
                 for item in payload["web_indicators"]],
            )
            for key, value in {
                "version": payload["version"],
                "database_name": SIGNATURE_DATABASE_NAME,
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "source": "github-release",
            }.items():
                connection.execute(
                    """
                    INSERT INTO signature_metadata (key, value) VALUES (?, ?)
                    ON CONFLICT(key) DO UPDATE SET value = excluded.value
                    """,
                    (key, value),
                )

        emit(
            "signature-updated",
            **signature_status_payload(),
            installed=True,
            yara_rule_files=len(payload["rules"]),
        )
        return 0
    except (UnicodeError, json.JSONDecodeError, ValueError, OSError, sqlite3.Error) as error:
        emit("error", code="PROTON_INSTALL_FAILED", message=f"Proton kurulamadı: {error}")
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


def main() -> int:
    parser = argparse.ArgumentParser(description="Neutron salt-okunur hızlı tarama motoru")
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--quick-scan", action="store_true", help="Aktif kullanıcı profili ve Temp klasörlerini tara")
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
    action.add_argument("--amsi-service", action="store_true", help="AMSI ön-çalıştırma koruma servisini başlat")
    action.add_argument("--check-url", metavar="URL", help="URL veya domain itibarını yerel Proton verisinde denetle")
    action.add_argument("--protection-history", action="store_true", help="Gerçek zamanlı koruma olaylarını oku")
    action.add_argument("--protection-action", metavar="ID", type=int, help="Gerçek zamanlı koruma olayına işlem uygula")
    action.add_argument("--signature-status", action="store_true", help="Yerel imza veritabanı durumunu oku")
    action.add_argument("--signature-update", action="store_true", help="Paketle gelen yerel imzaları yükle")
    action.add_argument("--install-proton-stdin", action="store_true", help="Doğrulanmış Proton yükünü standart girdiden kur")
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
    parser.add_argument("--reason", default="Kullanıcı onaylı tarama bulgusu", help="Karantina nedeni")
    parser.add_argument("--disposition", choices=("quarantine", "trust", "ignore"), help="Koruma olayı işlemi")
    parser.add_argument("--label", default=None, help="İstisna açıklaması")
    parser.add_argument("--limit", type=int, default=5, help="Döndürülecek en fazla geçmiş kaydı")
    parser.add_argument("--value-json", default="null", help="Ayar için JSON değeri")
    parser.add_argument("--json-lines", action="store_true", help="Electron IPC için JSON Lines çıktısı")
    args = parser.parse_args()

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
    if args.signature_status:
        return signature_status()
    if args.signature_update:
        return signature_update()
    if args.install_proton_stdin:
        return install_proton_from_stdin()
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
    if args.quarantine:
        return quarantine_file(args.quarantine, args.reason)
    if args.quarantine_list:
        return read_quarantine()
    if args.restore is not None:
        return update_quarantine_item(args.restore, "restore")
    if args.delete_quarantine is not None:
        return update_quarantine_item(args.delete_quarantine, "delete")
    return quick_scan()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        emit("error", code="CANCELLED", message="Tarama iptal edildi.")
        raise SystemExit(130)
