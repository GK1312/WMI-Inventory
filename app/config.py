from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv

from core.errors import StrictError
from core.logging import LEVELS

load_dotenv()

_VALID_ENVS = {'development', 'staging', 'production'}


def _get_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {'1', 'true', 'yes', 'on'}


@dataclass(frozen=True)
class Settings:
    app_env: str
    logging_enabled: bool
    log_level: str
    log_file: str


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

    return Settings(
        app_env=app_env,
        logging_enabled=_get_bool('LOGGING_ENABLED', True),
        log_level=log_level,
        log_file=os.environ.get('LOG_FILE', 'logs/app.log'),
    )


settings = load_settings()
