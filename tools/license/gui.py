#!/usr/bin/env python3
"""Small local GUI for issuing device-bound Neutron licenses."""

from __future__ import annotations

import calendar
import hashlib
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk


PROJECT_ROOT = Path(__file__).resolve().parents[2]
ISSUE_SCRIPT = PROJECT_ROOT / "tools" / "license" / "issue.cjs"
DEVICE_HASH_RE = re.compile(r"^[a-fA-F0-9]{64}$")
MACHINE_GUID_RE = re.compile(r"^\{?[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}\}?$")
EXPIRY_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

DURATION_MONTHS = {
    "1 Ay": 1,
    "3 Ay": 3,
    "6 Ay": 6,
    "1 Yıl": 12,
}


def add_months(value: datetime, months: int) -> datetime:
    month_index = value.month - 1 + months
    year = value.year + month_index // 12
    month = month_index % 12 + 1
    day = min(value.day, calendar.monthrange(year, month)[1])
    return value.replace(year=year, month=month, day=day)


def expiry_for_duration(label: str, now: datetime | None = None) -> str:
    if label == "Süresiz":
        return ""
    months = DURATION_MONTHS.get(label)
    if months is None:
        return ""
    current = now or datetime.now(timezone.utc)
    expires = add_months(current, months).replace(hour=23, minute=59, second=59, microsecond=0)
    return expires.strftime("%Y-%m-%dT%H:%M:%SZ")


def default_private_key() -> Path:
    candidates = [
        Path(os.environ["NEUTRON_LICENSE_PRIVATE_KEY"]).expanduser()
        if os.environ.get("NEUTRON_LICENSE_PRIVATE_KEY")
        else None,
        PROJECT_ROOT.parent / "NeutronSecret" / "license-signing-private.pem",
        PROJECT_ROOT / "NeutronLicenseSecret" / "license-signing-private.pem",
    ]
    for candidate in candidates:
        if candidate and candidate.is_file():
            return candidate.resolve()
    return candidates[1]


def node_executable() -> str:
    found = shutil.which("node") or shutil.which("node.exe")
    if found:
        return found
    fallback = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "nodejs" / "node.exe"
    if fallback.is_file():
        return str(fallback)
    raise RuntimeError("Node.js bulunamadı. Neutron geliştirme ortamındaki Node.js kurulumunu kontrol edin.")


def normalize_device_hash(value: str) -> str:
    candidate = value.strip()
    if DEVICE_HASH_RE.fullmatch(candidate):
        return candidate.lower()
    machine_guid = candidate[4:] if candidate.lower().startswith("win:") else candidate
    if MACHINE_GUID_RE.fullmatch(machine_guid):
        material = f"Neutron device binding v1|win:{machine_guid}".encode("utf-8")
        return hashlib.sha256(material).hexdigest()
    raise ValueError("Cihaz kimliği 64 karakterlik SHA-256 veya setup'ta gösterilen Windows cihaz kodu olmalı.")


def issue_license(
    private_key: str,
    device_hash: str,
    license_id: str,
    customer: str,
    edition: str,
    expires_at: str,
) -> str:
    key_path = Path(private_key).expanduser()
    if not key_path.is_file():
        raise ValueError("Özel anahtar dosyası bulunamadı.")
    device_hash = normalize_device_hash(device_hash)
    if not license_id.strip():
        raise ValueError("Lisans kimliği boş bırakılamaz.")
    if expires_at and not EXPIRY_RE.fullmatch(expires_at):
        raise ValueError("Bitiş tarihi YYYY-AA-GGTss:dd:ssZ biçiminde olmalı.")

    command = [
        node_executable(),
        str(ISSUE_SCRIPT),
        "--private-key", str(key_path.resolve()),
        "--device", device_hash,
        "--id", license_id.strip(),
        "--customer", customer.strip() or license_id.strip(),
        "--edition", edition.strip() or "Standard",
    ]
    if expires_at:
        command.extend(["--expires", expires_at])
    result = subprocess.run(
        command,
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip().splitlines()
        raise RuntimeError(detail[-1] if detail else "Lisans üretilemedi.")
    activation_key = result.stdout.strip()
    if not activation_key.startswith("NTR1-"):
        raise RuntimeError("Lisans aracı beklenmeyen bir çıktı döndürdü.")
    return activation_key


class LicenseApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Neutron Lisans Oluşturucu")
        self.geometry("760x650")
        self.minsize(680, 590)

        now = datetime.now()
        self.private_key = tk.StringVar(value=str(default_private_key()))
        self.device_hash = tk.StringVar()
        self.license_id = tk.StringVar(value=f"test-{now:%Y%m%d-%H%M}")
        self.customer = tk.StringVar(value="Test Bilgisayarı")
        self.edition = tk.StringVar(value="Standard")
        self.duration = tk.StringVar(value="1 Ay")
        self.expires_at = tk.StringVar(value=expiry_for_duration("1 Ay"))
        self.status = tk.StringVar(value="Cihaz kimliğini girip lisansı oluşturun.")

        self._build_ui()

    def _build_ui(self) -> None:
        root = ttk.Frame(self, padding=22)
        root.pack(fill="both", expand=True)
        root.columnconfigure(1, weight=1)

        ttk.Label(root, text="Neutron Lisans Oluşturucu", font=("Segoe UI", 18, "bold")).grid(
            row=0, column=0, columnspan=3, sticky="w", pady=(0, 18)
        )

        row = 1
        ttk.Label(root, text="Özel anahtar").grid(row=row, column=0, sticky="w", padx=(0, 10), pady=6)
        ttk.Entry(root, textvariable=self.private_key).grid(row=row, column=1, sticky="ew", pady=6)
        ttk.Button(root, text="Seç…", command=self.choose_private_key).grid(row=row, column=2, padx=(8, 0), pady=6)

        row += 1
        ttk.Label(root, text="Cihaz kimliği / setup cihaz kodu").grid(row=row, column=0, sticky="nw", padx=(0, 10), pady=6)
        device_entry = ttk.Entry(root, textvariable=self.device_hash)
        device_entry.grid(row=row, column=1, columnspan=2, sticky="ew", pady=6)
        device_entry.focus_set()

        row += 1
        ttk.Label(root, text="Lisans kimliği").grid(row=row, column=0, sticky="w", padx=(0, 10), pady=6)
        ttk.Entry(root, textvariable=self.license_id).grid(row=row, column=1, columnspan=2, sticky="ew", pady=6)

        row += 1
        ttk.Label(root, text="Müşteri adı").grid(row=row, column=0, sticky="w", padx=(0, 10), pady=6)
        ttk.Entry(root, textvariable=self.customer).grid(row=row, column=1, columnspan=2, sticky="ew", pady=6)

        row += 1
        ttk.Label(root, text="Sürüm").grid(row=row, column=0, sticky="w", padx=(0, 10), pady=6)
        ttk.Combobox(root, textvariable=self.edition, values=("Standard", "Pro", "Enterprise")).grid(
            row=row, column=1, columnspan=2, sticky="ew", pady=6
        )

        row += 1
        ttk.Label(root, text="Süre").grid(row=row, column=0, sticky="w", padx=(0, 10), pady=6)
        duration = ttk.Combobox(
            root,
            textvariable=self.duration,
            state="readonly",
            values=("1 Ay", "3 Ay", "6 Ay", "1 Yıl", "Süresiz", "Özel Tarih"),
        )
        duration.grid(row=row, column=1, columnspan=2, sticky="ew", pady=6)
        duration.bind("<<ComboboxSelected>>", self.update_expiry)

        row += 1
        ttk.Label(root, text="Bitiş (UTC)").grid(row=row, column=0, sticky="w", padx=(0, 10), pady=6)
        ttk.Entry(root, textvariable=self.expires_at).grid(row=row, column=1, columnspan=2, sticky="ew", pady=6)

        row += 1
        ttk.Button(root, text="Lisans Oluştur", command=self.generate).grid(
            row=row, column=0, columnspan=3, sticky="ew", pady=(18, 10), ipady=7
        )

        row += 1
        ttk.Label(root, text="Aktivasyon anahtarı").grid(row=row, column=0, columnspan=3, sticky="w", pady=(8, 6))
        row += 1
        self.output = tk.Text(root, height=9, wrap="word", font=("Consolas", 9))
        self.output.grid(row=row, column=0, columnspan=3, sticky="nsew")
        root.rowconfigure(row, weight=1)

        row += 1
        ttk.Button(root, text="Panoya Kopyala", command=self.copy_key).grid(
            row=row, column=0, columnspan=3, sticky="ew", pady=(10, 6)
        )
        row += 1
        ttk.Label(root, textvariable=self.status, wraplength=690).grid(
            row=row, column=0, columnspan=3, sticky="w", pady=(6, 0)
        )

    def choose_private_key(self) -> None:
        selected = filedialog.askopenfilename(
            title="Neutron özel lisans anahtarını seçin",
            filetypes=(("PEM anahtarı", "*.pem"), ("Tüm dosyalar", "*.*")),
        )
        if selected:
            self.private_key.set(selected)

    def update_expiry(self, _event: object | None = None) -> None:
        label = self.duration.get()
        if label != "Özel Tarih":
            self.expires_at.set(expiry_for_duration(label))

    def generate(self) -> None:
        try:
            key = issue_license(
                self.private_key.get(),
                self.device_hash.get(),
                self.license_id.get(),
                self.customer.get(),
                self.edition.get(),
                self.expires_at.get().strip(),
            )
        except (ValueError, RuntimeError, OSError) as error:
            self.status.set(str(error))
            messagebox.showerror("Lisans oluşturulamadı", str(error), parent=self)
            return
        self.output.delete("1.0", "end")
        self.output.insert("1.0", key)
        self.status.set("Lisans başarıyla oluşturuldu. Anahtarı test bilgisayarına kopyalayabilirsiniz.")
        self.copy_key(show_message=False)

    def copy_key(self, show_message: bool = True) -> None:
        key = self.output.get("1.0", "end").strip()
        if not key:
            if show_message:
                messagebox.showinfo("Neutron", "Önce bir lisans oluşturun.", parent=self)
            return
        self.clipboard_clear()
        self.clipboard_append(key)
        self.update()
        self.status.set("Aktivasyon anahtarı panoya kopyalandı.")


def self_test() -> None:
    fixed = datetime(2026, 8, 14, 12, 0, tzinfo=timezone.utc)
    assert expiry_for_duration("1 Ay", fixed) == "2026-09-14T23:59:59Z"
    assert expiry_for_duration("1 Yıl", fixed) == "2027-08-14T23:59:59Z"
    assert expiry_for_duration("Süresiz", fixed) == ""
    guid = "01234567-89ab-cdef-0123-456789abcdef"
    expected_hash = hashlib.sha256(f"Neutron device binding v1|win:{guid}".encode("utf-8")).hexdigest()
    assert normalize_device_hash(guid) == expected_hash
    assert normalize_device_hash(expected_hash.upper()) == expected_hash
    assert default_private_key().name == "license-signing-private.pem"
    assert ISSUE_SCRIPT.is_file()
    print("Lisans GUI öz testi başarılı.")


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()
    else:
        LicenseApp().mainloop()
