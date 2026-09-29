from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

from cryptography.fernet import Fernet
from dotenv import load_dotenv

from core.errors import StrictError
from core.logging import LEVELS

load_dotenv()

_VALID_ENVS = {'development', 'staging', 'production'}
_VALID_SSLMODES = {'disable', 'allow', 'prefer', 'require', 'verify-ca', 'verify-full'}
_SHA256_HEX = re.compile(r'[0-9a-f]{64}')


def _get_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {'1', 'true', 'yes', 'on'}


def _get_int(name: str, default: int, *, minimum: int = 0) -> int:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw)
    except ValueError:
        raise StrictError(f'{name} must be an integer, got {raw!r}', field=name) from None
    if value < minimum:
        raise StrictError(f'{name} must be >= {minimum}, got {value}', field=name)
    return value


def _get_list(name: str, default: tuple[str, ...] = ()) -> tuple[str, ...]:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return tuple(item.strip() for item in raw.split(',') if item.strip())


# frozen=True makes instances read-only, so settings can't be changed accidentally at runtime.
@dataclass(frozen=True)
class Settings:
    # --- Logging ---
    app_env: str
    logging_enabled: bool
    log_level: str
    log_file: str

    # --- PostgreSQL ---
    db_host: str
    db_port: int
    db_name: str
    db_user: str
    db_password: str = field(repr=False)
    db_sslmode: str
    db_pool_min: int
    db_pool_max: int

    # --- API ---
    api_host: str
    api_port: int
    api_key_hashes: tuple[str, ...] = field(repr=False)
    cors_origins: tuple[str, ...]
    trusted_hosts: tuple[str, ...]
    max_body_bytes: int
    cred_encryption_key: str = field(repr=False)


def load_settings() -> Settings:
    app_env = os.environ.get('APP_ENV', 'development').strip().lower()
    if app_env not in _VALID_ENVS:
        raise StrictError(
            f'APP_ENV must be one of {sorted(_VALID_ENVS)}, got {app_env!r}', field='APP_ENV'
        )

    log_level = os.environ.get('LOG_LEVEL', 'INFO').strip().upper()
    if log_level not in LEVELS:
        raise StrictError(
            f'LOG_LEVEL must be one of {sorted(LEVELS)}, got {log_level!r}', field='LOG_LEVEL'
        )

    db_sslmode = os.environ.get('DB_SSLMODE', 'prefer').strip().lower()
    if db_sslmode not in _VALID_SSLMODES:
        raise StrictError(
            f'DB_SSLMODE must be one of {sorted(_VALID_SSLMODES)}, got {db_sslmode!r}', field='DB_SSLMODE'
        )

    db_pool_min = _get_int('DB_POOL_MIN', 1, minimum=1)
    db_pool_max = _get_int('DB_POOL_MAX', 10, minimum=1)
    if db_pool_max < db_pool_min:
        raise StrictError('DB_POOL_MAX must be >= DB_POOL_MIN', field='DB_POOL_MAX')

    api_key_hashes = tuple(h.lower() for h in _get_list('API_KEY_HASHES'))
    for key_hash in api_key_hashes:
        if not _SHA256_HEX.fullmatch(key_hash):
            raise StrictError(
                'API_KEY_HASHES must be comma-separated SHA-256 hex digests '
                '(generate one with app/core/security.py)',
                field='API_KEY_HASHES',
            )

    cred_encryption_key = os.environ.get('CRED_ENCRYPTION_KEY', '').strip()
    if cred_encryption_key:
        try:
            Fernet(cred_encryption_key)
        except ValueError:
            raise StrictError(
                'CRED_ENCRYPTION_KEY is not a valid Fernet key '
                '(generate one with app/core/security.py encryption-key)',
                field='CRED_ENCRYPTION_KEY',
            ) from None

    return Settings(
        app_env=app_env,
        logging_enabled=_get_bool('LOGGING_ENABLED', True),
        log_level=log_level,
        log_file=os.environ.get('LOG_FILE', 'logs/app.log'),
        db_host=os.environ.get('DB_HOST', 'localhost'),
        db_port=_get_int('DB_PORT', 5432, minimum=1),
        db_name=os.environ.get('DB_NAME', 'wmi_inventory'),
        db_user=os.environ.get('DB_USER', 'postgres'),
        db_password=os.environ.get('DB_PASSWORD', ''),
        db_sslmode=db_sslmode,
        db_pool_min=db_pool_min,
        db_pool_max=db_pool_max,
        api_host=os.environ.get('API_HOST', '127.0.0.1'),
        api_port=_get_int('API_PORT', 8000, minimum=1),
        api_key_hashes=api_key_hashes,
        cors_origins=_get_list('CORS_ORIGINS'),
        trusted_hosts=_get_list('TRUSTED_HOSTS', ('localhost', '127.0.0.1')),
        max_body_bytes=_get_int('MAX_BODY_BYTES', 1_048_576, minimum=1),
        cred_encryption_key=cred_encryption_key,
    )


settings = load_settings()
