from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR))
temp_dir = tempfile.TemporaryDirectory()
database_path = Path(temp_dir.name) / "test.db"
os.environ["DATABASE_URL"] = f"sqlite:///{database_path.as_posix()}"
os.environ["BOOTSTRAP_ADMIN_USERNAME"] = "admin"
os.environ["BOOTSTRAP_ADMIN_DISPLAY_NAME"] = "مدير الاختبار"
os.environ["BOOTSTRAP_ADMIN_PASSWORD"] = "InitialAdmin2026!"
os.environ["COOKIE_SECURE"] = "1"

from fastapi.testclient import TestClient  # noqa: E402
from app import app  # noqa: E402


client = TestClient(app, base_url="https://testserver")


def csrf_headers() -> dict[str, str]:
    token = client.cookies.get("biometric_csrf")
    assert token
    return {"X-CSRF-Token": token}


def run() -> None:
    health = client.get("/health")
    assert health.status_code == 200
    assert health.json()["version"] == "2.1.1"

    public_page = client.get("/")
    assert public_page.status_code == 200
    assert "tile.openstreetmap.org/{z}/{x}/{y}.png" in public_page.text
    assert "api.mapbox.com" not in public_page.text
    assert "https://tile.openstreetmap.org" in public_page.headers["content-security-policy"]
    assert "https://tiles.openfreemap.org" not in public_page.headers["content-security-policy"]
    assert "https://api.mapbox.com" not in public_page.headers["content-security-policy"]

    map_config = client.get("/api/config")
    assert map_config.status_code == 200
    assert map_config.json()["map_provider"] == "OpenStreetMap"
    assert map_config.json()["map_tile_url"] == "https://tile.openstreetmap.org/{z}/{x}/{y}.png"

    public_devices = client.get("/api/devices")
    assert public_devices.status_code == 200
    assert any(item["name"] == "بناية البصمة" for item in public_devices.json())
    assert client.get("/api/admin/devices").status_code == 401

    login = client.post("/api/auth/login", json={"username": "admin", "password": "InitialAdmin2026!"})
    assert login.status_code == 200, login.text
    assert login.json()["must_change_password"] is True

    blocked = client.post(
        "/api/admin/devices",
        json={"name": "يجب ألا يضاف", "area": "", "lat": 32.3, "lng": 44.0},
        headers=csrf_headers(),
    )
    assert blocked.status_code == 403

    changed = client.post(
        "/api/auth/change-password",
        json={"current_password": "InitialAdmin2026!", "new_password": "UpdatedAdmin2026!"},
        headers=csrf_headers(),
    )
    assert changed.status_code == 200, changed.text

    new_user = client.post(
        "/api/admin/users",
        json={
            "username": "device.admin",
            "display_name": "مسؤول الأجهزة",
            "password": "DeviceAdmin2026!",
            "role": "device_admin",
        },
        headers=csrf_headers(),
    )
    assert new_user.status_code == 201, new_user.text

    created = client.post(
        "/api/admin/devices",
        json={"name": "البوابة الرئيسية", "area": "المدخل", "lat": 32.36, "lng": 44.09},
        headers=csrf_headers(),
    )
    assert created.status_code == 201, created.text
    device_id = created.json()["id"]

    updated = client.put(
        f"/api/admin/devices/{device_id}",
        json={"name": "البوابة الرئيسية", "area": "المدخل الجديد", "lat": 32.361, "lng": 44.091},
        headers=csrf_headers(),
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["area"] == "المدخل الجديد"
    assert len(client.get("/devices.json").json()) == 2

    audit = client.get("/api/admin/audit")
    assert audit.status_code == 200
    assert any(row["action"] == "device_updated" for row in audit.json())

    assert client.post("/api/auth/logout", headers=csrf_headers()).status_code == 200
    assert client.get("/api/admin/devices").status_code == 401

    login_device_admin = client.post(
        "/api/auth/login", json={"username": "device.admin", "password": "DeviceAdmin2026!"}
    )
    assert login_device_admin.status_code == 200
    assert client.post(
        "/api/auth/change-password",
        json={"current_password": "DeviceAdmin2026!", "new_password": "DeviceAdminNew2026!"},
        headers=csrf_headers(),
    ).status_code == 200
    assert client.get("/api/admin/users").status_code == 403
    assert client.post(
        "/api/admin/devices",
        json={"name": "جهاز ثانٍ", "area": "المبنى", "lat": 32.37, "lng": 44.10},
        headers=csrf_headers(),
    ).status_code == 201

    print("SMOKE TEST PASSED")


if __name__ == "__main__":
    run()
