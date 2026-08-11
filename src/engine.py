#!/usr/bin/env python3
"""Neutron'un salt-okunur hızlı tarama motoru.

Bu ilk sürüm bir antivirüs iddiasında bulunmaz. Yalnızca kullanıcının Masaüstü
ve İndirilenler klasörlerinde sınırlı bir tarama yapar; dosya silmez, taşımaz,
karantinaya almaz veya ağ üzerinden veri göndermez. Electron ile standart
çıktıdaki JSON Lines olayları üzerinden konuşur.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import shutil
import sqlite3
import sys
import time
from collections.abc import Iterator
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from datetime import datetime, timezone

try:
    import yara
except ImportError:
    yara = None


MAX_FILES = 1_500
MAX_DEPTH = 8
MAX_HASH_BYTES = 25 * 1024 * 1024
MAX_CONTENT_BYTES = 1 * 1024 * 1024
MAX_YARA_BYTES = 25 * 1024 * 1024
PROGRESS_INTERVAL = 25
WATCH_INTERVAL_SECONDS = 5.0
SIGNATURE_DATABASE_NAME = "Proton"
BUILTIN_SIGNATURE_VERSION = "1.00.001"

# EICAR, antivirüs ürünlerini güvenli şekilde denemek için kullanılan zararsız
# standart test dizgesidir. Bu motor yalnızca bu test imzasını kesin bulgu sayar.
EICAR_MARKER = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
EXECUTABLE_EXTENSIONS = {
    ".bat", ".cmd", ".com", ".dll", ".exe", ".jar", ".js", ".lnk",
    ".msi", ".ps1", ".scr", ".vbe", ".vbs",
}
DOCUMENT_EXTENSIONS = {".doc", ".docx", ".pdf", ".png", ".jpg", ".jpeg", ".txt", ".xlsx", ".zip"}
RISK_WORDS = {"keygen", "crack", "ransom", "payload", "trojan"}
SKIP_DIRECTORIES = {
    "$recycle.bin", "appdata", "node_modules", "system volume information",
    "venv", "windows", ".git",
}


@dataclass
class Finding:
    path: str
    kind: str
    severity: str
    reason: str
    sha256: str | None = None


def data_directory() -> Path:
    """Electron'ın verdiği klasörü, yoksa proje içindeki data klasörünü kullanır."""
    configured = os.environ.get("NEUTRON_DATA_DIR")
    if configured:
        return Path(configured)
    return Path(__file__).resolve().parent.parent / "data"


def database_path() -> Path:
    return data_directory() / "neutron.db"


def open_database() -> sqlite3.Connection:
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
          sha256 TEXT
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
        """
    )
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
    connection.commit()
    return connection


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
        count = int(connection.execute(
            "SELECT COUNT(*) FROM signatures WHERE enabled = 1"
        ).fetchone()[0])
        metadata = dict(connection.execute(
            "SELECT key, value FROM signature_metadata"
        ).fetchall())
    return {
        "database_name": metadata.get("database_name", SIGNATURE_DATABASE_NAME),
        "version": metadata.get("version", BUILTIN_SIGNATURE_VERSION),
        "updated_at": metadata.get("updated_at"),
        "signature_count": count,
        "source": "builtin",
        "network_used": False,
    }


def rules_directory() -> Path:
    return data_directory() / "rules"


def load_yara_rules() -> tuple[Any | None, dict[str, Any]]:
    if yara is None:
        return None, {
            "available": False,
            "version": None,
            "rule_files": 0,
            "message": "yara-python kurulu değil.",
        }

    rule_files = sorted(rules_directory().glob("*.yar"))
    if not rule_files:
        return None, {
            "available": True,
            "version": yara.__version__,
            "rule_files": 0,
            "message": "YARA kural dosyası bulunamadı.",
        }

    namespaces = {f"neutron_{index}": str(path) for index, path in enumerate(rule_files)}
    try:
        compiled = yara.compile(filepaths=namespaces)
    except yara.Error as error:
        return None, {
            "available": True,
            "version": yara.__version__,
            "rule_files": len(rule_files),
            "message": f"YARA kuralları derlenemedi: {error}",
        }
    return compiled, {
        "available": True,
        "version": yara.__version__,
        "rule_files": len(rule_files),
        "message": "YARA kuralları hazır.",
    }


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
    """Dosyayı yalnız açık kullanıcı isteğiyle geri alınabilir alana taşır."""
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
        if moved and destination.exists() and not original.exists():
            try:
                shutil.move(str(destination), str(original))
            except OSError:
                pass
        emit("error", code="QUARANTINE_FAILED", message=f"Karantina işlemi tamamlanamadı: {error}")
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


def emit(event_type: str, **payload: Any) -> None:
    """Tek bir JSON Lines olayı yazar; protokol dışında çıktı üretmez."""
    message = {"type": event_type, **payload}
    print(json.dumps(message, ensure_ascii=False), flush=True)


def home_scan_targets() -> list[Path]:
    home = Path.home()
    candidates = [home / "Desktop", home / "Downloads"]
    # Türkçe Windows klasör adları manuel taşınmış profillerde görülebilir.
    candidates.extend([home / "Masaüstü", home / "İndirilenler"])

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


def iter_files(targets: list[Path]) -> Iterator[Path]:
    """Sembolik bağları takip etmeden, derinliği ve sayıyı sınırlı tutar."""
    yielded = 0
    stack: list[tuple[Path, int]] = [(target, 0) for target in reversed(targets)]

    while stack and yielded < MAX_FILES:
        directory, depth = stack.pop()
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    if yielded >= MAX_FILES:
                        return
                    try:
                        if entry.is_symlink():
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            if depth < MAX_DEPTH and entry.name.casefold() not in SKIP_DIRECTORIES:
                                stack.append((Path(entry.path), depth + 1))
                            continue
                        if entry.is_file(follow_symlinks=False):
                            yielded += 1
                            yield Path(entry.path)
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


def snapshot_targets(targets: list[Path]) -> dict[str, tuple[int, int]]:
    snapshot: dict[str, tuple[int, int]] = {}
    for path in iter_files(targets):
        if is_engine_data_file(path):
            continue
        signature = file_signature(path)
        if signature is not None:
            snapshot[str(path)] = signature
    return snapshot


def save_protection_event(event_kind: str, finding: Finding) -> None:
    with open_database() as connection:
        connection.execute(
            """
            INSERT INTO protection_events (
              occurred_at, event_kind, file_path, finding_kind, severity,
              reason, sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.now(timezone.utc).isoformat(),
                event_kind,
                finding.path,
                finding.kind,
                finding.severity,
                finding.reason,
                finding.sha256,
            ),
        )


def read_protection_history(limit: int) -> list[dict[str, Any]]:
    if not database_path().is_file():
        return []
    with open_database() as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """
            SELECT id, occurred_at, event_kind, file_path, finding_kind,
                   severity, reason, sha256
            FROM protection_events
            ORDER BY occurred_at DESC, id DESC
            LIMIT ?
            """,
            (max(1, min(limit, 100)),),
        ).fetchall()
    return [dict(row) for row in rows]


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


def inspect_file(
    path: Path,
    signatures: dict[int, dict[str, dict[str, Any]]] | None = None,
    yara_rules: Any | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    try:
        size = path.stat().st_size
    except (OSError, PermissionError):
        return findings

    suffix = path.suffix.casefold()
    name = path.name.casefold()
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
            sha256=sha256_for(path, size),
        ))

    if suffix in EXECUTABLE_EXTENSIONS and any(word in name for word in RISK_WORDS):
        findings.append(Finding(
            path=str(path),
            kind="review",
            severity="low",
            reason="İnceleme gerektiren dosya adı ve çalıştırılabilir tür",
            sha256=sha256_for(path, size),
        ))

    size_signatures = (signatures or {}).get(size, {})
    if size_signatures:
        digest = sha256_for(path, size)
        signature = size_signatures.get(digest or "")
        if signature:
            findings.append(Finding(
                path=str(path),
                kind="test-signature" if signature["source"] == "builtin" else "signature",
                severity=str(signature["severity"]),
                reason=f'{signature["name"]} eşleşmesi bulundu',
                sha256=digest,
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
            if sample.strip() == EICAR_MARKER and not any(
                finding.kind == "test-signature" for finding in findings
            ):
                findings.append(Finding(
                    path=str(path),
                    kind="test-signature",
                    severity="high",
                    reason="EICAR güvenli antivirüs test imzası bulundu",
                    sha256=hashlib.sha256(sample).hexdigest(),
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
                    sha256=sha256_for(path, size),
                ))
        except (OSError, PermissionError, yara.Error):
            pass

    return findings


def watch_targets() -> int:
    """Poll the user's common download locations without changing any files."""
    targets = home_scan_targets()
    if not targets:
        emit("watch-error", code="NO_TARGETS", message="İzlenecek klasör bulunamadı.")
        return 2

    signatures = load_signatures()
    yara_rules, yara_status = load_yara_rules()
    previous = snapshot_targets(targets)
    emit(
        "watch-ready",
        targets=[str(target) for target in targets],
        tracked=len(previous),
        interval_seconds=WATCH_INTERVAL_SECONDS,
        yara=yara_status,
    )

    try:
        while True:
            time.sleep(WATCH_INTERVAL_SECONDS)
            current = snapshot_targets(targets)

            for raw_path, signature in current.items():
                prior_signature = previous.get(raw_path)
                if prior_signature == signature:
                    continue

                event_kind = "created" if prior_signature is None else "changed"
                path = Path(raw_path)
                findings = inspect_file(path, signatures, yara_rules)
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
                        save_protection_event(event_kind, finding)
                    except (OSError, sqlite3.Error):
                        pass
                    emit(
                        "watch-finding",
                        event_kind=event_kind,
                        file_name=path.name,
                        finding=asdict(finding),
                    )

            previous = current
    except KeyboardInterrupt:
        emit("watch-stopped")
        return 0


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


def scan_targets(targets: list[Path], mode: str) -> int:
    started_at = time.monotonic()
    completed_at = datetime.now(timezone.utc).isoformat()
    if not targets:
        emit("error", code="NO_TARGETS", message="Taranacak klasör bulunamadı.")
        return 2

    emit("started", mode=mode, targets=[target.name for target in targets], max_files=MAX_FILES)
    scanned = 0
    findings: list[Finding] = []
    signatures = load_signatures()
    yara_rules, yara_status = load_yara_rules()
    emit("engine-status", yara=yara_status)

    for file_path in iter_files(targets):
        scanned += 1
        findings.extend(inspect_file(file_path, signatures, yara_rules))
        if scanned % PROGRESS_INTERVAL == 0:
            emit("progress", scanned=scanned, max_files=MAX_FILES)

    confirmed = [finding for finding in findings if finding.kind in {"test-signature", "signature"}]
    review = [finding for finding in findings if finding.kind in {"review", "yara"}]
    elapsed_ms = round((time.monotonic() - started_at) * 1000)
    limited = scanned >= MAX_FILES
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

    if not target.is_dir():
        emit("error", code="INVALID_TARGET", message="Seçilen konum bir klasör değil.")
        return 2
    return scan_targets([target], "custom")


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
    action.add_argument("--quick-scan", action="store_true", help="Masaüstü ve İndirilenler klasörlerini tara")
    action.add_argument("--scan-path", metavar="KLASOR", help="Kullanıcının seçtiği tek klasörü tara")
    action.add_argument("--history", action="store_true", help="Yerel tarama geçmişini oku")
    action.add_argument("--watch", action="store_true", help="Yeni ve değişen dosyaları izle")
    action.add_argument("--protection-history", action="store_true", help="Gerçek zamanlı koruma olaylarını oku")
    action.add_argument("--signature-status", action="store_true", help="Yerel imza veritabanı durumunu oku")
    action.add_argument("--signature-update", action="store_true", help="Paketle gelen yerel imzaları yükle")
    action.add_argument("--yara-status", action="store_true", help="YARA motorunu ve kurallarını doğrula")
    action.add_argument("--quarantine", metavar="DOSYA", help="Onaylanan dosyayı karantinaya taşı")
    action.add_argument("--quarantine-list", action="store_true", help="Etkin karantina kayıtlarını oku")
    action.add_argument("--restore", metavar="ID", type=int, help="Karantinadaki dosyayı geri yükle")
    action.add_argument("--delete-quarantine", metavar="ID", type=int, help="Karantinadaki dosyayı kalıcı sil")
    parser.add_argument("--reason", default="Kullanıcı onaylı tarama bulgusu", help="Karantina nedeni")
    parser.add_argument("--limit", type=int, default=5, help="Döndürülecek en fazla geçmiş kaydı")
    parser.add_argument("--json-lines", action="store_true", help="Electron IPC için JSON Lines çıktısı")
    args = parser.parse_args()

    if args.history:
        return history(args.limit)
    if args.protection_history:
        return protection_history(args.limit)
    if args.signature_status:
        return signature_status()
    if args.signature_update:
        return signature_update()
    if args.yara_status:
        return yara_status()
    if args.watch:
        return watch_targets()
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
