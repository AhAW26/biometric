from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qs, unquote, urljoin, urlparse

import httpx
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.responses import FileResponse, RedirectResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, create_engine, delete, func, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session as DbSession, mapped_column, relationship, sessionmaker


BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)
load_dotenv(BASE_DIR / ".env")

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger("biometric-map")

DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{(DATA_DIR / 'biometric.db').as_posix()}").strip()
# Most hosting providers expose a standard postgresql:// URL. SQLAlchemy needs
# the explicit psycopg driver name because this project uses psycopg v3.
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg://", 1)
elif DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)
IS_SQLITE = DATABASE_URL.startswith("sqlite")
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if IS_SQLITE else {},
    pool_pre_ping=True,
)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)

SESSION_COOKIE = "biometric_session"
CSRF_COOKIE = "biometric_csrf"
SESSION_HOURS = max(1, int(os.getenv("SESSION_HOURS", "12")))
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "1").strip().lower() not in {"0", "false", "no"}
EMPLOYEE_LAUNCHER_ORIGIN = os.getenv("EMPLOYEE_LAUNCHER_ORIGIN", "https://ahaw26.github.io").strip().rstrip("/")
PASSWORD_HASHER = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)
VALID_ROLES = {"super_admin", "device_admin", "viewer"}
MIN_PASSWORD_LENGTH = 8
MAX_DEVICE_IMPORT = 5000
MAX_LOCATION_RESPONSE_BYTES = 512 * 1024
ALLOWED_LOCATION_HOSTS = {
    "google.com",
    "www.google.com",
    "maps.google.com",
    "maps.app.goo.gl",
    "goo.gl",
    "maps.apple.com",
    "openstreetmap.org",
    "www.openstreetmap.org",
}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(120))
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(32), default="viewer")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    sessions: Mapped[list[LoginSession]] = relationship(back_populates="user", cascade="all, delete-orphan")


class LoginSession(Base):
    __tablename__ = "login_sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    csrf_hash: Mapped[str] = mapped_column(String(64))
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    ip_address: Mapped[str] = mapped_column(String(64), default="")
    user_agent: Mapped[str] = mapped_column(String(300), default="")

    user: Mapped[User] = relationship(back_populates="sessions")


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(150), index=True)
    area: Mapped[str] = mapped_column(String(250), default="")
    lat: Mapped[float] = mapped_column(Float)
    lng: Mapped[float] = mapped_column(Float)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    updated_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    username: Mapped[str] = mapped_column(String(64), default="system")
    action: Mapped[str] = mapped_column(String(80), index=True)
    entity_type: Mapped[str] = mapped_column(String(50), default="")
    entity_id: Mapped[str] = mapped_column(String(80), default="")
    details: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class LoginBody(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=200)


class PasswordBody(BaseModel):
    current_password: str = Field(min_length=1, max_length=200)
    new_password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=200)


class ResetPasswordBody(BaseModel):
    new_password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=200)


class DeviceBody(BaseModel):
    name: str = Field(min_length=1, max_length=150)
    area: str = Field(default="", max_length=250)
    lat: float = Field(ge=-90, le=90)
    lng: float = Field(ge=-180, le=180)

    @field_validator("name")
    @classmethod
    def clean_name(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("device name is required")
        return cleaned

    @field_validator("area")
    @classmethod
    def clean_area(cls, value: str) -> str:
        return value.strip()


class DeviceOut(DeviceBody):
    model_config = ConfigDict(from_attributes=True)
    id: str
    created_at: datetime
    updated_at: datetime


class DeviceImportItem(DeviceBody):
    id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")

    @field_validator("id", mode="before")
    @classmethod
    def clean_id(cls, value: Any) -> Any:
        return value.strip() if isinstance(value, str) else value


class DeviceImportBody(BaseModel):
    devices: list[DeviceImportItem] = Field(min_length=1, max_length=MAX_DEVICE_IMPORT)


class LocationResolveBody(BaseModel):
    value: str = Field(min_length=1, max_length=3000)

    @field_validator("value")
    @classmethod
    def clean_value(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("location value is required")
        return cleaned


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    display_name: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=200)
    role: str

    @field_validator("username")
    @classmethod
    def normalize_username(cls, value: str) -> str:
        return value.strip().lower()

    @field_validator("display_name")
    @classmethod
    def clean_display_name(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("display name is required")
        return cleaned

    @field_validator("role")
    @classmethod
    def valid_role(cls, value: str) -> str:
        if value not in VALID_ROLES:
            raise ValueError("invalid role")
        return value


class UserUpdate(BaseModel):
    display_name: str | None = Field(default=None, min_length=1, max_length=120)
    role: str | None = None
    is_active: bool | None = None

    @field_validator("role")
    @classmethod
    def valid_role(cls, value: str | None) -> str | None:
        if value is not None and value not in VALID_ROLES:
            raise ValueError("invalid role")
        return value

    @field_validator("display_name")
    @classmethod
    def clean_display_name(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("display name is required")
        return cleaned


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    username: str
    display_name: str
    role: str
    is_active: bool
    must_change_password: bool
    created_at: datetime


class AuditOut(BaseModel):
    id: int
    username: str
    action: str
    entity_type: str
    entity_id: str
    details: dict[str, Any]
    created_at: datetime


@dataclass
class AuthContext:
    user: User
    session: LoginSession


def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def token_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def password_is_valid(value: str) -> bool:
    return len(value) >= MIN_PASSWORD_LENGTH and any(ch.isalpha() for ch in value) and any(ch.isdigit() for ch in value)


def password_error() -> HTTPException:
    return HTTPException(status_code=422, detail="يجب أن تتكون كلمة المرور من 8 محارف على الأقل وتتضمن حرفًا ورقمًا.")


def request_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
    return forwarded or (request.client.host if request.client else "")


def audit(
    db: DbSession,
    user: User | None,
    action: str,
    entity_type: str = "",
    entity_id: str = "",
    details: dict[str, Any] | None = None,
) -> None:
    db.add(
        AuditLog(
            user_id=user.id if user else None,
            username=user.username if user else "system",
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            details=json.dumps(details or {}, ensure_ascii=False, default=str),
        )
    )


def device_dict(device: Device) -> dict[str, Any]:
    return {"id": device.id, "name": device.name, "area": device.area, "lat": device.lat, "lng": device.lng}


COORDINATE_NUMBER = r"-?\d{1,3}(?:\.\d+)?"
COORDINATE_PAIR = re.compile(rf"({COORDINATE_NUMBER})\s*[,،]\s*({COORDINATE_NUMBER})")


def valid_coordinate_pair(lat_value: str | float, lng_value: str | float) -> tuple[float, float] | None:
    try:
        lat = float(lat_value)
        lng = float(lng_value)
    except (TypeError, ValueError):
        return None
    if -90 <= lat <= 90 and -180 <= lng <= 180:
        return lat, lng
    return None


def coordinates_from_text(value: str) -> tuple[float, float] | None:
    decoded = unquote(value.strip())
    direct = re.fullmatch(rf"\s*({COORDINATE_NUMBER})\s*[,،]\s*({COORDINATE_NUMBER})\s*", decoded)
    if direct:
        return valid_coordinate_pair(direct.group(1), direct.group(2))

    parsed = urlparse(decoded)
    query = parse_qs(parsed.query)
    if "mlat" in query and "mlon" in query:
        coordinates = valid_coordinate_pair(query["mlat"][0], query["mlon"][0])
        if coordinates:
            return coordinates
    for key in ("q", "query", "ll", "center", "destination"):
        for item in query.get(key, []):
            match = COORDINATE_PAIR.search(item)
            if match:
                coordinates = valid_coordinate_pair(match.group(1), match.group(2))
                if coordinates:
                    return coordinates

    patterns = (
        re.compile(rf"@({COORDINATE_NUMBER}),({COORDINATE_NUMBER})(?:,|\b)"),
        re.compile(rf"!3d({COORDINATE_NUMBER})!4d({COORDINATE_NUMBER})"),
        re.compile(rf"#map=\d+(?:\.\d+)?/({COORDINATE_NUMBER})/({COORDINATE_NUMBER})"),
    )
    for pattern in patterns:
        match = pattern.search(decoded)
        if match:
            coordinates = valid_coordinate_pair(match.group(1), match.group(2))
            if coordinates:
                return coordinates
    return None


def extract_location_url(value: str) -> str | None:
    match = re.search(r"https://[^\s<>\"']+", value)
    if not match:
        return None
    return match.group(0).rstrip(".,،؛;!)]}")


def allowed_location_url(value: str) -> bool:
    try:
        parsed = urlparse(value)
        return (
            parsed.scheme == "https"
            and parsed.hostname is not None
            and parsed.hostname.lower().rstrip(".") in ALLOWED_LOCATION_HOSTS
            and parsed.username is None
            and parsed.password is None
            and parsed.port in {None, 443}
        )
    except ValueError:
        return False


def resolve_location_value(
    value: str,
    transport: httpx.BaseTransport | None = None,
) -> tuple[float, float, str]:
    location_url = extract_location_url(value)
    if location_url and not allowed_location_url(location_url):
        raise ValueError("يُسمح فقط بروابط Google Maps أو Apple Maps أو OpenStreetMap.")

    coordinates = coordinates_from_text(location_url or value)
    if coordinates:
        return coordinates[0], coordinates[1], location_url or value

    current_url = location_url
    if not current_url:
        raise ValueError("ألصق رابط موقع من واتساب أو إحداثيات بالشكل Latitude, Longitude.")

    headers = {"User-Agent": "Mozilla/5.0 (compatible; BiometricMap/2.7)"}
    try:
        with httpx.Client(timeout=10, follow_redirects=False, transport=transport, headers=headers) as client:
            for _ in range(7):
                coordinates = coordinates_from_text(current_url)
                if coordinates:
                    return coordinates[0], coordinates[1], current_url
                if not allowed_location_url(current_url):
                    raise ValueError("أعاد الرابط التوجيه إلى موقع غير مسموح.")

                with client.stream("GET", current_url) as response:
                    location = response.headers.get("location")
                    if 300 <= response.status_code < 400 and location:
                        next_url = urljoin(current_url, location)
                        if not allowed_location_url(next_url):
                            raise ValueError("أعاد الرابط التوجيه إلى موقع غير مسموح.")
                        current_url = next_url
                        continue
                    if response.status_code >= 400:
                        raise ValueError("تعذر فتح رابط الموقع المرسل.")

                    content = bytearray()
                    for chunk in response.iter_bytes():
                        remaining = MAX_LOCATION_RESPONSE_BYTES - len(content)
                        if remaining <= 0:
                            break
                        content.extend(chunk[:remaining])
                    coordinates = coordinates_from_text(content.decode("utf-8", errors="ignore"))
                    if coordinates:
                        return coordinates[0], coordinates[1], current_url
                    break
    except httpx.RequestError as exc:
        raise ValueError("تعذر الاتصال بخدمة الخرائط لاستخراج الموقع.") from exc

    raise ValueError("تعذر استخراج الإحداثيات من الرابط. اطلب إرسال الموقع الحالي مرة أخرى.")


def active_super_admins(db: DbSession) -> int:
    return db.scalar(select(func.count()).select_from(User).where(User.role == "super_admin", User.is_active.is_(True))) or 0


def apply_admin_recovery(db: DbSession) -> bool:
    """Apply an environment-controlled password reset once per recovery ID."""
    recovery_id = os.getenv("ADMIN_RECOVERY_ID", "").strip()
    recovery_password = os.getenv("ADMIN_RECOVERY_PASSWORD", "")
    recovery_username = os.getenv("ADMIN_RECOVERY_USERNAME", "admin").strip().lower()
    if not recovery_id and not recovery_password:
        return False
    if not recovery_id or not recovery_password or not recovery_username:
        logger.warning("Admin recovery ignored: both ADMIN_RECOVERY_ID and ADMIN_RECOVERY_PASSWORD are required.")
        return False
    if not password_is_valid(recovery_password):
        logger.warning("Admin recovery ignored: the recovery password does not meet the password policy.")
        return False

    recovery_marker = hashlib.sha256(recovery_id.encode("utf-8")).hexdigest()
    already_applied = db.scalar(
        select(AuditLog.id).where(
            AuditLog.action == "admin_password_recovery",
            AuditLog.entity_id == recovery_marker,
        )
    )
    if already_applied:
        return False

    user = db.scalar(select(User).where(User.username == recovery_username))
    if not user:
        logger.warning("Admin recovery ignored: requested user does not exist.")
        return False

    user.password_hash = PASSWORD_HASHER.hash(recovery_password)
    user.must_change_password = False
    user.is_active = True
    db.execute(delete(LoginSession).where(LoginSession.user_id == user.id))
    audit(
        db,
        user,
        "admin_password_recovery",
        "recovery",
        recovery_marker,
        {"username": recovery_username},
    )
    logger.warning("Administrator password recovery applied once. Remove the recovery environment variables.")
    return True


def get_auth_context(request: Request, db: DbSession = Depends(db_session)) -> AuthContext:
    raw = request.cookies.get(SESSION_COOKIE, "")
    if not raw:
        raise HTTPException(status_code=401, detail="يلزم تسجيل الدخول.")
    login_session = db.scalar(select(LoginSession).where(LoginSession.token_hash == token_hash(raw)))
    if not login_session:
        raise HTTPException(status_code=401, detail="الجلسة غير صالحة.")
    expires_at = login_session.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at <= utcnow():
        db.delete(login_session)
        db.commit()
        raise HTTPException(status_code=401, detail="انتهت جلسة الدخول.")
    user = db.get(User, login_session.user_id)
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="الحساب غير فعال.")
    return AuthContext(user=user, session=login_session)


def verify_csrf(request: Request, auth: AuthContext = Depends(get_auth_context)) -> AuthContext:
    cookie_value = request.cookies.get(CSRF_COOKIE, "")
    header_value = request.headers.get("x-csrf-token", "")
    if not cookie_value or not secrets.compare_digest(cookie_value, header_value):
        raise HTTPException(status_code=403, detail="رمز حماية الطلب غير صالح.")
    if not secrets.compare_digest(token_hash(cookie_value), auth.session.csrf_hash):
        raise HTTPException(status_code=403, detail="رمز حماية الجلسة غير صالح.")
    return auth


def require_roles(*roles: str, write: bool = False) -> Callable[..., AuthContext]:
    dependency = verify_csrf if write else get_auth_context

    def check(auth: AuthContext = Depends(dependency)) -> AuthContext:
        if auth.user.must_change_password:
            raise HTTPException(status_code=403, detail="PASSWORD_CHANGE_REQUIRED")
        if auth.user.role not in roles:
            raise HTTPException(status_code=403, detail="لا تملك الصلاحية المطلوبة.")
        return auth

    return check


LOGIN_FAILURES: dict[str, list[float]] = {}


def login_blocked(key: str) -> bool:
    now = time.time()
    recent = [stamp for stamp in LOGIN_FAILURES.get(key, []) if now - stamp < 900]
    LOGIN_FAILURES[key] = recent
    return len(recent) >= 5


def register_failure(key: str) -> None:
    LOGIN_FAILURES.setdefault(key, []).append(time.time())


def set_auth_cookies(response: Response, raw_session: str, raw_csrf: str) -> None:
    max_age = SESSION_HOURS * 3600
    response.set_cookie(
        SESSION_COOKIE,
        raw_session,
        max_age=max_age,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="strict",
        path="/",
    )
    response.set_cookie(
        CSRF_COOKIE,
        raw_csrf,
        max_age=max_age,
        httponly=False,
        secure=COOKIE_SECURE,
        samesite="strict",
        path="/",
    )


def clear_auth_cookies(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE, path="/")
    response.delete_cookie(CSRF_COOKIE, path="/")


def initialize_database() -> None:
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        if not db.scalar(select(func.count()).select_from(Device)):
            seed_path = STATIC_DIR / "devices_seed.json"
            if seed_path.exists():
                try:
                    for item in json.loads(seed_path.read_text(encoding="utf-8")):
                        db.add(
                            Device(
                                id=str(item.get("id") or secrets.token_hex(16)),
                                name=str(item["name"]).strip(),
                                area=str(item.get("area") or "").strip(),
                                lat=float(item["lat"]),
                                lng=float(item["lng"]),
                            )
                        )
                    audit(db, None, "seed_devices", "device")
                except Exception:
                    logger.exception("Could not import devices_seed.json")

        if not db.scalar(select(func.count()).select_from(User)):
            username = os.getenv("BOOTSTRAP_ADMIN_USERNAME", "").strip().lower()
            password = os.getenv("BOOTSTRAP_ADMIN_PASSWORD", "")
            display_name = os.getenv("BOOTSTRAP_ADMIN_DISPLAY_NAME", "المدير العام").strip()
            if username and password and password_is_valid(password):
                admin = User(
                    username=username,
                    display_name=display_name,
                    password_hash=PASSWORD_HASHER.hash(password),
                    role="super_admin",
                    is_active=True,
                    must_change_password=True,
                )
                db.add(admin)
                db.flush()
                audit(db, admin, "bootstrap_admin", "user", str(admin.id))
                logger.info("Bootstrap administrator created; password change is required on first login.")
            else:
                logger.warning("No users exist. Set valid BOOTSTRAP_ADMIN_USERNAME and BOOTSTRAP_ADMIN_PASSWORD.")
        apply_admin_recovery(db)
        db.commit()


initialize_database()
app = FastAPI(title="خريطة أجهزة البصمة", version="2.7.1", docs_url=None, redoc_url=None)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(self), camera=(), microphone=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self' 'unsafe-inline' https://unpkg.com; "
        "style-src 'self' 'unsafe-inline' https://unpkg.com; "
        "img-src 'self' data: blob: https://unpkg.com https://tile.openstreetmap.org; "
        "connect-src 'self'; "
        "object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
    )
    if request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if request.url.path.startswith("/api/") or request.url.path == "/devices.json":
        response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/", include_in_schema=False)
def home():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/index.html", include_in_schema=False)
def home_alias():
    return RedirectResponse("/", status_code=307)


@app.get("/admin", include_in_schema=False)
@app.get("/admin.html", include_in_schema=False)
def admin_page():
    return FileResponse(STATIC_DIR / "admin.html")


@app.get("/health")
def health():
    return {"status": "ok", "version": app.version}


@app.get("/api/ready")
def employee_launcher_readiness(response: Response):
    response.headers["Access-Control-Allow-Origin"] = EMPLOYEE_LAUNCHER_ORIGIN
    response.headers["Vary"] = "Origin"
    return {"status": "ok", "version": app.version, "target": "/"}


@app.get("/api/config")
def public_config():
    return {
        "map_provider": "OpenStreetMap",
        "map_tile_url": "https://tile.openstreetmap.org/{z}/{x}/{y}.png",
        "map_max_zoom": 19,
    }


@app.get("/api/devices", response_model=list[DeviceOut])
def public_devices(db: DbSession = Depends(db_session)):
    return list(db.scalars(select(Device).order_by(Device.name)).all())


@app.get("/devices.json")
def compatible_devices_json(db: DbSession = Depends(db_session)):
    devices = db.scalars(select(Device).order_by(Device.name)).all()
    return [device_dict(item) for item in devices]


@app.post("/api/auth/login")
def login(body: LoginBody, request: Request, response: Response, db: DbSession = Depends(db_session)):
    username = body.username.strip().lower()
    key = f"{request_ip(request)}:{username}"
    if login_blocked(key):
        raise HTTPException(status_code=429, detail="تم إيقاف المحاولات مؤقتًا. حاول بعد 15 دقيقة.")
    user = db.scalar(select(User).where(User.username == username))
    valid = False
    if user and user.is_active:
        try:
            valid = PASSWORD_HASHER.verify(user.password_hash, body.password)
        except (VerifyMismatchError, InvalidHashError):
            valid = False
    if not valid:
        register_failure(key)
        audit(db, user, "login_failed", "user", str(user.id) if user else "", {"ip": request_ip(request)})
        db.commit()
        raise HTTPException(status_code=401, detail="اسم المستخدم أو كلمة المرور غير صحيحة.")
    LOGIN_FAILURES.pop(key, None)
    raw_session = secrets.token_urlsafe(48)
    raw_csrf = secrets.token_urlsafe(32)
    login_session = LoginSession(
        token_hash=token_hash(raw_session),
        csrf_hash=token_hash(raw_csrf),
        user_id=user.id,
        expires_at=utcnow() + timedelta(hours=SESSION_HOURS),
        ip_address=request_ip(request),
        user_agent=request.headers.get("user-agent", "")[:300],
    )
    db.add(login_session)
    audit(db, user, "login_success", "user", str(user.id), {"ip": request_ip(request)})
    db.commit()
    set_auth_cookies(response, raw_session, raw_csrf)
    return {"user": UserOut.model_validate(user), "must_change_password": user.must_change_password}


@app.get("/api/auth/me")
def me(auth: AuthContext = Depends(get_auth_context)):
    return {"user": UserOut.model_validate(auth.user), "must_change_password": auth.user.must_change_password}


@app.post("/api/auth/logout")
def logout(response: Response, auth: AuthContext = Depends(verify_csrf), db: DbSession = Depends(db_session)):
    audit(db, auth.user, "logout", "user", str(auth.user.id))
    db.delete(auth.session)
    db.commit()
    clear_auth_cookies(response)
    return {"ok": True}


@app.post("/api/auth/change-password")
def change_password(body: PasswordBody, auth: AuthContext = Depends(verify_csrf), db: DbSession = Depends(db_session)):
    if not password_is_valid(body.new_password):
        raise password_error()
    try:
        PASSWORD_HASHER.verify(auth.user.password_hash, body.current_password)
    except (VerifyMismatchError, InvalidHashError):
        raise HTTPException(status_code=400, detail="كلمة المرور الحالية غير صحيحة.")
    auth.user.password_hash = PASSWORD_HASHER.hash(body.new_password)
    auth.user.must_change_password = False
    auth.user.updated_at = utcnow()
    audit(db, auth.user, "password_changed", "user", str(auth.user.id))
    db.commit()
    return {"ok": True}


@app.get("/api/admin/devices", response_model=list[DeviceOut])
def admin_devices(
    auth: AuthContext = Depends(require_roles("super_admin", "device_admin", "viewer")),
    db: DbSession = Depends(db_session),
):
    return list(db.scalars(select(Device).order_by(Device.name)).all())


@app.post("/api/admin/location/resolve")
def resolve_location(
    body: LocationResolveBody,
    auth: AuthContext = Depends(require_roles("super_admin", "device_admin", write=True)),
):
    try:
        lat, lng, resolved_url = resolve_location_value(body.value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"ok": True, "lat": lat, "lng": lng, "resolved_url": resolved_url}


@app.post("/api/admin/devices", response_model=DeviceOut, status_code=status.HTTP_201_CREATED)
def create_device(
    body: DeviceBody,
    auth: AuthContext = Depends(require_roles("super_admin", "device_admin", write=True)),
    db: DbSession = Depends(db_session),
):
    device = Device(
        id=secrets.token_hex(16),
        name=body.name,
        area=body.area,
        lat=body.lat,
        lng=body.lng,
        created_by=auth.user.id,
        updated_by=auth.user.id,
    )
    db.add(device)
    audit(db, auth.user, "device_created", "device", device.id, {"after": device_dict(device)})
    db.commit()
    db.refresh(device)
    return device


@app.post("/api/admin/devices/import")
def import_devices(
    body: DeviceImportBody,
    auth: AuthContext = Depends(require_roles("super_admin", "device_admin", write=True)),
    db: DbSession = Depends(db_session),
):
    imported_ids = [item.id for item in body.devices]
    if len(imported_ids) != len(set(imported_ids)):
        raise HTTPException(status_code=400, detail="ملف النسخة يحتوي معرّف جهاز مكررًا.")

    existing_by_id = {device.id: device for device in db.scalars(select(Device)).all()}
    created = 0
    updated = 0
    unchanged = 0

    for item in body.devices:
        device = existing_by_id.get(item.id)
        if device is None:
            device = Device(
                id=item.id,
                name=item.name,
                area=item.area,
                lat=item.lat,
                lng=item.lng,
                created_by=auth.user.id,
                updated_by=auth.user.id,
            )
            db.add(device)
            existing_by_id[item.id] = device
            created += 1
            continue

        before = (device.name, device.area, device.lat, device.lng)
        after = (item.name, item.area, item.lat, item.lng)
        if before == after:
            unchanged += 1
            continue

        device.name = item.name
        device.area = item.area
        device.lat = item.lat
        device.lng = item.lng
        device.updated_by = auth.user.id
        device.updated_at = utcnow()
        updated += 1

    result = {
        "ok": True,
        "total": len(body.devices),
        "created": created,
        "updated": updated,
        "unchanged": unchanged,
    }
    audit(db, auth.user, "devices_imported", "device_backup", "", result)
    db.commit()
    return result


@app.put("/api/admin/devices/{device_id}", response_model=DeviceOut)
def update_device(
    device_id: str,
    body: DeviceBody,
    auth: AuthContext = Depends(require_roles("super_admin", "device_admin", write=True)),
    db: DbSession = Depends(db_session),
):
    device = db.get(Device, device_id)
    if not device:
        raise HTTPException(status_code=404, detail="الجهاز غير موجود.")
    before = device_dict(device)
    device.name = body.name
    device.area = body.area
    device.lat = body.lat
    device.lng = body.lng
    device.updated_by = auth.user.id
    device.updated_at = utcnow()
    audit(db, auth.user, "device_updated", "device", device.id, {"before": before, "after": device_dict(device)})
    db.commit()
    db.refresh(device)
    return device


@app.delete("/api/admin/devices/{device_id}")
def delete_device(
    device_id: str,
    auth: AuthContext = Depends(require_roles("super_admin", "device_admin", write=True)),
    db: DbSession = Depends(db_session),
):
    device = db.get(Device, device_id)
    if not device:
        raise HTTPException(status_code=404, detail="الجهاز غير موجود.")
    before = device_dict(device)
    audit(db, auth.user, "device_deleted", "device", device.id, {"before": before})
    db.delete(device)
    db.commit()
    return {"ok": True}


@app.get("/api/admin/users", response_model=list[UserOut])
def list_users(
    auth: AuthContext = Depends(require_roles("super_admin")),
    db: DbSession = Depends(db_session),
):
    return list(db.scalars(select(User).order_by(User.username)).all())


@app.post("/api/admin/users", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(
    body: UserCreate,
    auth: AuthContext = Depends(require_roles("super_admin", write=True)),
    db: DbSession = Depends(db_session),
):
    if not password_is_valid(body.password):
        raise password_error()
    if db.scalar(select(User).where(User.username == body.username)):
        raise HTTPException(status_code=409, detail="اسم المستخدم موجود مسبقًا.")
    user = User(
        username=body.username,
        display_name=body.display_name,
        password_hash=PASSWORD_HASHER.hash(body.password),
        role=body.role,
        must_change_password=True,
    )
    db.add(user)
    db.flush()
    audit(db, auth.user, "user_created", "user", str(user.id), {"username": user.username, "role": user.role})
    db.commit()
    db.refresh(user)
    return user


@app.put("/api/admin/users/{user_id}", response_model=UserOut)
def update_user(
    user_id: int,
    body: UserUpdate,
    auth: AuthContext = Depends(require_roles("super_admin", write=True)),
    db: DbSession = Depends(db_session),
):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="المستخدم غير موجود.")
    new_role = body.role if body.role is not None else user.role
    new_active = body.is_active if body.is_active is not None else user.is_active
    if user.id == auth.user.id and (new_role != "super_admin" or not new_active):
        raise HTTPException(status_code=400, detail="لا يمكنك إزالة صلاحية حسابك الحالي أو تعطيله.")
    if user.role == "super_admin" and user.is_active and (new_role != "super_admin" or not new_active) and active_super_admins(db) <= 1:
        raise HTTPException(status_code=400, detail="يجب إبقاء مدير عام فعال واحد على الأقل.")
    before = {"display_name": user.display_name, "role": user.role, "is_active": user.is_active}
    if body.display_name is not None:
        user.display_name = body.display_name.strip()
    user.role = new_role
    user.is_active = new_active
    user.updated_at = utcnow()
    after = {"display_name": user.display_name, "role": user.role, "is_active": user.is_active}
    audit(db, auth.user, "user_updated", "user", str(user.id), {"before": before, "after": after})
    db.commit()
    db.refresh(user)
    return user


@app.post("/api/admin/users/{user_id}/reset-password")
def reset_user_password(
    user_id: int,
    body: ResetPasswordBody,
    auth: AuthContext = Depends(require_roles("super_admin", write=True)),
    db: DbSession = Depends(db_session),
):
    if not password_is_valid(body.new_password):
        raise password_error()
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="المستخدم غير موجود.")
    user.password_hash = PASSWORD_HASHER.hash(body.new_password)
    user.must_change_password = True
    user.updated_at = utcnow()
    for login_session in list(user.sessions):
        db.delete(login_session)
    audit(db, auth.user, "user_password_reset", "user", str(user.id), {"username": user.username})
    db.commit()
    return {"ok": True}


@app.get("/api/admin/audit", response_model=list[AuditOut])
def list_audit(
    limit: int = 100,
    auth: AuthContext = Depends(require_roles("super_admin")),
    db: DbSession = Depends(db_session),
):
    limit = min(max(limit, 1), 500)
    rows = db.scalars(select(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit)).all()
    result = []
    for row in rows:
        try:
            details = json.loads(row.details or "{}")
        except json.JSONDecodeError:
            details = {}
        result.append(
            AuditOut(
                id=row.id,
                username=row.username,
                action=row.action,
                entity_type=row.entity_type,
                entity_id=row.entity_id,
                details=details,
                created_at=row.created_at,
            )
        )
    return result
