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
import httpx  # noqa: E402
from app import SessionLocal, app, apply_admin_recovery, coordinates_from_text, resolve_location_value  # noqa: E402


client = TestClient(app, base_url="https://testserver")


def csrf_headers() -> dict[str, str]:
    token = client.cookies.get("biometric_csrf")
    assert token
    return {"X-CSRF-Token": token}


def run() -> None:
    health = client.get("/health")
    assert health.status_code == 200
    assert health.json()["version"] == "2.7.0"

    public_page = client.get("/")
    assert public_page.status_code == 200
    assert "tile.openstreetmap.org/{z}/{x}/{y}.png" in public_page.text
    assert "api.mapbox.com" not in public_page.text
    assert "https://tile.openstreetmap.org" in public_page.headers["content-security-policy"]
    assert "https://tiles.openfreemap.org" not in public_page.headers["content-security-policy"]
    assert "https://api.mapbox.com" not in public_page.headers["content-security-policy"]
    assert "المسافة تقديرية لأن دقة الهاتف الحالية" in public_page.text
    assert "setInterval(async" not in public_page.text
    assert "setTimeout(tryNext" in public_page.text
    assert "دقة الموقع غير كافية الآن" not in public_page.text
    assert 'id="deviceSearch"' in public_page.text
    assert "البحث باسم الجهاز أو الموقع" in public_page.text
    assert "function normalizeSearch" in public_page.text
    assert "function filterDevices" in public_page.text
    assert "function renderDeviceCards" in public_page.text
    assert "renderDeviceCards(list,data.slice(0,10))" in public_page.text
    assert "renderDeviceCards(searchResultsEl,matches)" in public_page.text
    assert "لا يوجد جهاز مطابق" in public_page.text
    assert 'id="searchResults"' in public_page.text
    assert public_page.text.index('id="deviceSearch"') < public_page.text.index('id="map"')
    assert "لا يتم تخزينه في خادم الموقع" in public_page.text
    assert "Google Maps" in public_page.text
    assert '<a href="/admin"' not in public_page.text

    admin_page = client.get("/admin")
    assert admin_page.status_code == 200
    assert 'id="exportDevicesBtn"' in admin_page.text
    assert 'id="importDevicesBtn"' in admin_page.text
    assert 'id="importDevicesFile"' in admin_page.text
    assert 'id="deviceCount"' in admin_page.text
    assert 'id="locationLink"' in admin_page.text
    assert 'id="resolveLocationBtn"' in admin_page.text
    assert "/api/admin/devices/import" in admin_page.text
    assert "/api/admin/location/resolve" in admin_page.text
    assert "ولا يحذف أي جهاز موجود" in admin_page.text
    assert "لا تحتاج إلى فتحه في تطبيق الخرائط" in admin_page.text

    assert coordinates_from_text("32.357802, 44.093349") == (32.357802, 44.093349)
    assert coordinates_from_text("https://maps.google.com/?q=32.357802%2C44.093349") == (32.357802, 44.093349)
    assert coordinates_from_text("https://www.google.com/maps/place/test/@32.357802,44.093349,18z") == (
        32.357802,
        44.093349,
    )
    assert coordinates_from_text("https://www.google.com/maps/data=!3d32.357802!4d44.093349") == (
        32.357802,
        44.093349,
    )

    def location_redirect(request: httpx.Request) -> httpx.Response:
        if request.url.host == "maps.app.goo.gl":
            return httpx.Response(
                302,
                headers={"Location": "https://www.google.com/maps/place/test/@32.357802,44.093349,18z"},
                request=request,
            )
        return httpx.Response(200, request=request)

    short_location = resolve_location_value(
        "https://maps.app.goo.gl/test-link",
        transport=httpx.MockTransport(location_redirect),
    )
    assert short_location[:2] == (32.357802, 44.093349)

    map_config = client.get("/api/config")
    assert map_config.status_code == 200
    assert map_config.json()["map_provider"] == "OpenStreetMap"
    assert map_config.json()["map_tile_url"] == "https://tile.openstreetmap.org/{z}/{x}/{y}.png"

    public_devices = client.get("/api/devices")
    assert public_devices.status_code == 200
    assert any(item["name"] == "بناية البصمة" for item in public_devices.json())
    assert client.get("/api/admin/devices").status_code == 401
    assert client.post(
        "/api/admin/location/resolve",
        json={"value": "https://maps.google.com/?q=32.357802,44.093349"},
    ).status_code == 401
    assert client.post(
        "/api/admin/devices/import",
        json={"devices": [{"id": "unauthorized", "name": "مرفوض", "area": "", "lat": 32.3, "lng": 44.0}]},
    ).status_code == 401

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

    resolved_location = client.post(
        "/api/admin/location/resolve",
        json={"value": "موقع الجهاز https://maps.google.com/?q=32.357802%2C44.093349"},
        headers=csrf_headers(),
    )
    assert resolved_location.status_code == 200, resolved_location.text
    assert resolved_location.json()["lat"] == 32.357802
    assert resolved_location.json()["lng"] == 44.093349

    rejected_location = client.post(
        "/api/admin/location/resolve",
        json={"value": "https://example.com/?q=32.357802,44.093349"},
        headers=csrf_headers(),
    )
    assert rejected_location.status_code == 400

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

    imported = client.post(
        "/api/admin/devices/import",
        json={
            "devices": [
                {
                    "id": device_id,
                    "name": "البوابة الرئيسية",
                    "area": "مستعاد من النسخة",
                    "lat": 32.362,
                    "lng": 44.092,
                },
                {
                    "id": "backup-device-1",
                    "name": "جهاز النسخة الاحتياطية",
                    "area": "المبنى الإداري",
                    "lat": 32.38,
                    "lng": 44.11,
                },
            ]
        },
        headers=csrf_headers(),
    )
    assert imported.status_code == 200, imported.text
    assert imported.json() == {"ok": True, "total": 2, "created": 1, "updated": 1, "unchanged": 0}
    assert len(client.get("/devices.json").json()) == 3
    assert any(item["area"] == "مستعاد من النسخة" for item in client.get("/devices.json").json())

    imported_again = client.post(
        "/api/admin/devices/import",
        json={
            "devices": [
                {
                    "id": device_id,
                    "name": "البوابة الرئيسية",
                    "area": "مستعاد من النسخة",
                    "lat": 32.362,
                    "lng": 44.092,
                },
                {
                    "id": "backup-device-1",
                    "name": "جهاز النسخة الاحتياطية",
                    "area": "المبنى الإداري",
                    "lat": 32.38,
                    "lng": 44.11,
                },
            ]
        },
        headers=csrf_headers(),
    )
    assert imported_again.status_code == 200, imported_again.text
    assert imported_again.json()["unchanged"] == 2

    duplicate_import = client.post(
        "/api/admin/devices/import",
        json={
            "devices": [
                {"id": "same-id", "name": "الأول", "area": "", "lat": 32.3, "lng": 44.0},
                {"id": "same-id", "name": "الثاني", "area": "", "lat": 32.4, "lng": 44.1},
            ]
        },
        headers=csrf_headers(),
    )
    assert duplicate_import.status_code == 400
    assert len(client.get("/devices.json").json()) == 3

    invalid_import = client.post(
        "/api/admin/devices/import",
        json={"devices": [{"id": "invalid-lat", "name": "غير صالح", "area": "", "lat": 95, "lng": 44.0}]},
        headers=csrf_headers(),
    )
    assert invalid_import.status_code == 422
    assert len(client.get("/devices.json").json()) == 3

    audit = client.get("/api/admin/audit")
    assert audit.status_code == 200
    assert any(row["action"] == "device_updated" for row in audit.json())
    assert any(row["action"] == "devices_imported" for row in audit.json())

    assert client.post("/api/auth/logout", headers=csrf_headers()).status_code == 200
    assert client.get("/api/admin/devices").status_code == 401

    os.environ["ADMIN_RECOVERY_USERNAME"] = "admin"
    os.environ["ADMIN_RECOVERY_ID"] = "smoke-reset-1"
    os.environ["ADMIN_RECOVERY_PASSWORD"] = "ResetA12"
    with SessionLocal() as db:
        assert apply_admin_recovery(db) is True
        db.commit()
    recovered_login = client.post("/api/auth/login", json={"username": "admin", "password": "ResetA12"})
    assert recovered_login.status_code == 200
    assert recovered_login.json()["must_change_password"] is False
    assert client.post("/api/auth/logout", headers=csrf_headers()).status_code == 200
    with SessionLocal() as db:
        assert apply_admin_recovery(db) is False
    os.environ.pop("ADMIN_RECOVERY_USERNAME")
    os.environ.pop("ADMIN_RECOVERY_ID")
    os.environ.pop("ADMIN_RECOVERY_PASSWORD")

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
    assert client.post(
        "/api/admin/devices/import",
        json={
            "devices": [
                {"id": "device-admin-import", "name": "استيراد مسؤول الأجهزة", "area": "", "lat": 32.39, "lng": 44.12}
            ]
        },
        headers=csrf_headers(),
    ).status_code == 200

    print("SMOKE TEST PASSED")


if __name__ == "__main__":
    run()
