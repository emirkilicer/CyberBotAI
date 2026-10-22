"""
Django settings for the CYBERBOT project.

Configuration is environment driven. Copy ``.env.example`` to ``.env`` and
generate the two required secrets before starting the application.

Security defaults:
  * DEBUG is off unless explicitly enabled.
  * SECRET_KEY and TOTP_ENCRYPTION_KEY have no usable defaults.
  * Secure cookies / HSTS / HTTPS redirect are production defaults that can
    be disabled for plain-HTTP local development via environment variables.
"""

from __future__ import annotations

import os
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent

# Load .env before reading any settings. Existing environment variables win.
load_dotenv(BASE_DIR / ".env")


def env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None or not value.strip():
        return default
    try:
        return int(value)
    except ValueError as exc:
        raise ImproperlyConfigured(f"{name} must be an integer.") from exc


def env_float(name: str, default: float) -> float:
    value = os.getenv(name)
    if value is None or not value.strip():
        return default
    try:
        return float(value)
    except ValueError as exc:
        raise ImproperlyConfigured(f"{name} must be a number.") from exc


def env_list(name: str, default: str = "") -> list[str]:
    return [item.strip() for item in os.getenv(name, default).split(",") if item.strip()]


# ---------------------------------------------------------------------------
# Core
# ---------------------------------------------------------------------------

DEBUG = env_bool("DJANGO_DEBUG", False)

# Local HTTP development escape hatch. Production must leave this false so the
# fail-fast checks below require HTTPS, secure cookies, HSTS, Redis and Postgres.
ALLOW_INSECURE_HTTP = env_bool("DJANGO_ALLOW_INSECURE_HTTP", False)

SECRET_KEY = os.getenv("DJANGO_SECRET_KEY", "").strip()
if not SECRET_KEY or SECRET_KEY.lower().startswith("change-me") or len(SECRET_KEY) < 32:
    raise ImproperlyConfigured(
        "DJANGO_SECRET_KEY is missing or invalid. Copy .env.example to .env and "
        "generate one with: python -c \"from django.core.management.utils import "
        "get_random_secret_key; print(get_random_secret_key())\""
    )

ALLOWED_HOSTS = env_list("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1,[::1]")
CSRF_TRUSTED_ORIGINS = env_list("DJANGO_CSRF_TRUSTED_ORIGINS")
SITE_URL = os.getenv("DJANGO_SITE_URL", "http://localhost:8081").rstrip("/")

ROOT_URLCONF = "config.urls"
WSGI_APPLICATION = "config.wsgi.application"
ASGI_APPLICATION = "config.asgi.application"

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "core",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "core.middleware.SecurityHeadersMiddleware",
    "core.middleware.AdminIPAllowlistMiddleware",
    "core.middleware.Require2FAForAuthenticatedMiddleware",
    "core.middleware.AdminLoginThrottleMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
# SQLite is fine for a single-node demo. For a real authentication service
# use PostgreSQL (and point DATABASE_URL at a replicated cluster).
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}

# Production deployments should point this at PostgreSQL, e.g.
# postgres://user:pass@db:5432/cyberbot. SQLite is only used for local dev/test.
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
if DATABASE_URL:
    try:
        import dj_database_url
    except ImportError as exc:  # pragma: no cover - configuration error
        raise ImproperlyConfigured(
            "DATABASE_URL is set but dj-database-url is not installed."
        ) from exc
    DATABASES["default"] = dj_database_url.parse(
        DATABASE_URL,
        conn_max_age=600,
        conn_health_checks=True,
    )

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# ---------------------------------------------------------------------------
# Authentication / sessions
# ---------------------------------------------------------------------------

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
        "OPTIONS": {"min_length": 8},
    },
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

# Argon2 first; existing PBKDF2 hashes keep working and are upgraded on login.
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.Argon2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher",
    "django.contrib.auth.hashers.ScryptPasswordHasher",
]

SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_HTTPONLY = True  # the token is exposed through a <meta> tag instead
CSRF_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_AGE = env_int("DJANGO_SESSION_COOKIE_AGE", 60 * 60 * 8)

SECURE_COOKIES = env_bool("DJANGO_SECURE_COOKIES", not DEBUG)
SESSION_COOKIE_SECURE = SECURE_COOKIES
CSRF_COOKIE_SECURE = SECURE_COOKIES

# Two-factor authentication
TOTP_ISSUER = os.getenv("TOTP_ISSUER", "CYBERBOT")
TOTP_ENCRYPTION_KEY = os.getenv("TOTP_ENCRYPTION_KEY", "").strip()
TWO_FACTOR_PENDING_TIMEOUT = env_int("TWO_FACTOR_PENDING_TIMEOUT", 10 * 60)
TWO_FACTOR_MAX_ATTEMPTS = env_int("TWO_FACTOR_MAX_ATTEMPTS", 5)
TWO_FACTOR_LOCKOUT_SECONDS = env_int("TWO_FACTOR_LOCKOUT_SECONDS", 15 * 60)
TWO_FACTOR_VALID_WINDOW = env_int("TWO_FACTOR_VALID_WINDOW", 1)

# Brute-force protection. A shared Redis cache is required when running more
# than one worker/replica; LocMemCache is per process.
REDIS_URL = os.getenv("REDIS_URL", "").strip()
if REDIS_URL:
    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.redis.RedisCache",
            "LOCATION": REDIS_URL,
        }
    }
else:
    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "cyberbot-rate-limits",
        }
    }

LOGIN_ATTEMPT_LIMIT = env_int("LOGIN_ATTEMPT_LIMIT", 10)
LOGIN_ATTEMPT_WINDOW_SECONDS = env_int("LOGIN_ATTEMPT_WINDOW_SECONDS", 15 * 60)
SIGNUP_RATE_LIMIT_PER_HOUR = env_int("SIGNUP_RATE_LIMIT_PER_HOUR", 10)
CHAT_RATE_LIMIT_PER_MINUTE = env_int("CHAT_RATE_LIMIT_PER_MINUTE", 20)

# Admin protection. Leave ADMIN_IP_ALLOWLIST empty only for local development.
ADMIN_LOGIN_ATTEMPT_LIMIT = env_int("ADMIN_LOGIN_ATTEMPT_LIMIT", 5)
ADMIN_LOGIN_WINDOW_SECONDS = env_int("ADMIN_LOGIN_WINDOW_SECONDS", 15 * 60)
ADMIN_IP_ALLOWLIST = env_list("ADMIN_IP_ALLOWLIST")

# ---------------------------------------------------------------------------
# Email / account recovery
# ---------------------------------------------------------------------------

REQUIRE_EMAIL_VERIFICATION = env_bool(
    "DJANGO_REQUIRE_EMAIL_VERIFICATION",
    not ALLOW_INSECURE_HTTP,
)
PASSWORD_RESET_TIMEOUT = env_int("DJANGO_PASSWORD_RESET_TIMEOUT", 60 * 60)

DEFAULT_FROM_EMAIL = os.getenv("DJANGO_DEFAULT_FROM_EMAIL", "noreply@cyberbot.local")
SERVER_EMAIL = DEFAULT_FROM_EMAIL
EMAIL_TIMEOUT = 10

if DEBUG or ALLOW_INSECURE_HTTP:
    EMAIL_BACKEND = os.getenv(
        "DJANGO_EMAIL_BACKEND",
        "django.core.mail.backends.console.EmailBackend",
    )
else:
    EMAIL_BACKEND = os.getenv(
        "DJANGO_EMAIL_BACKEND",
        "django.core.mail.backends.smtp.EmailBackend",
    )

EMAIL_HOST = os.getenv("DJANGO_EMAIL_HOST", "localhost")
EMAIL_PORT = env_int("DJANGO_EMAIL_PORT", 587)
EMAIL_HOST_USER = os.getenv("DJANGO_EMAIL_HOST_USER", "")
EMAIL_HOST_PASSWORD = os.getenv("DJANGO_EMAIL_HOST_PASSWORD", "")
EMAIL_USE_TLS = env_bool("DJANGO_EMAIL_USE_TLS", True)
EMAIL_USE_SSL = env_bool("DJANGO_EMAIL_USE_SSL", False)

# ---------------------------------------------------------------------------
# AI / chat
# ---------------------------------------------------------------------------

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "").strip()
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.8-flash").strip()
GEMINI_TIMEOUT_SECONDS = env_float("GEMINI_TIMEOUT_SECONDS", 30.0)
GEMINI_MAX_OUTPUT_TOKENS = env_int("GEMINI_MAX_OUTPUT_TOKENS", 2048)
CHAT_MAX_MESSAGE_LENGTH = env_int("CHAT_MAX_MESSAGE_LENGTH", 2000)
CHAT_MAX_BODY_BYTES = env_int("CHAT_MAX_BODY_BYTES", 64 * 1024)
CHAT_MAX_OUTPUT_LENGTH = env_int("CHAT_MAX_OUTPUT_LENGTH", 8000)

# ---------------------------------------------------------------------------
# Transport security
# ---------------------------------------------------------------------------

SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "same-origin"
SECURE_CROSS_ORIGIN_OPENER_POLICY = "same-origin"
X_FRAME_OPTIONS = "DENY"

SECURE_SSL_REDIRECT = env_bool("DJANGO_SECURE_SSL_REDIRECT", False)
SECURE_HSTS_SECONDS = env_int("DJANGO_SECURE_HSTS_SECONDS", 0)
SECURE_HSTS_INCLUDE_SUBDOMAINS = env_bool("DJANGO_SECURE_HSTS_INCLUDE_SUBDOMAINS", False)
SECURE_HSTS_PRELOAD = env_bool("DJANGO_SECURE_HSTS_PRELOAD", False)

# Only enable when a trusted reverse proxy sets X-Forwarded-Proto.
if env_bool("DJANGO_TRUST_PROXY", False):
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

# ---------------------------------------------------------------------------
# Static files
# ---------------------------------------------------------------------------

STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_DIRS = [BASE_DIR / "static"]

STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "whitenoise.storage.CompressedStaticFilesStorage"},
}

# ---------------------------------------------------------------------------
# i18n / logging
# ---------------------------------------------------------------------------

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

LOG_LEVEL = os.getenv("DJANGO_LOG_LEVEL", "INFO").upper()
LOG_JSON = env_bool("DJANGO_LOG_JSON", False)

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {
            "format": "%(asctime)s %(levelname)s %(name)s %(message)s",
        },
        "json": {
            "()": "core.logging.JsonFormatter",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "json" if LOG_JSON else "verbose",
        },
    },
    "root": {
        "handlers": ["console"],
        "level": LOG_LEVEL,
    },
    "loggers": {
        "core.audit": {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": False,
        },
        "django.security": {
            "handlers": ["console"],
            "level": "WARNING",
            "propagate": False,
        },
    },
}

# ---------------------------------------------------------------------------
# Production fail-fast
# ---------------------------------------------------------------------------
# Local development can opt out explicitly with DJANGO_ALLOW_INSECURE_HTTP=True.
# A production deployment that forgets TLS/Redis/Postgres must not start.
if not DEBUG and not ALLOW_INSECURE_HTTP:
    problems = []

    if not SECURE_COOKIES:
        problems.append("DJANGO_SECURE_COOKIES must be True")
    if not SECURE_SSL_REDIRECT:
        problems.append("DJANGO_SECURE_SSL_REDIRECT must be True")
    if SECURE_HSTS_SECONDS <= 0:
        problems.append("DJANGO_SECURE_HSTS_SECONDS must be > 0")
    if not REDIS_URL:
        problems.append("REDIS_URL is required for shared rate limiting")
    if not DATABASE_URL or not DATABASE_URL.startswith(("postgres://", "postgresql://")):
        problems.append("DATABASE_URL must point to PostgreSQL")
    if "*" in ALLOWED_HOSTS:
        problems.append("DJANGO_ALLOWED_HOSTS must not contain '*'")
    if not ADMIN_IP_ALLOWLIST:
        problems.append("ADMIN_IP_ALLOWLIST is required in production")
    if not REQUIRE_EMAIL_VERIFICATION:
        problems.append("DJANGO_REQUIRE_EMAIL_VERIFICATION must be True")
    if not TOTP_ENCRYPTION_KEY:
        problems.append("TOTP_ENCRYPTION_KEY is required")
    if EMAIL_BACKEND.endswith("console.EmailBackend"):
        problems.append("A real email backend is required")

    if problems:
        raise ImproperlyConfigured(
            "Insecure production configuration: " + "; ".join(problems)
        )
