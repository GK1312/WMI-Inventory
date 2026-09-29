from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

import psycopg
from psycopg.conninfo import make_conninfo
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from core.errors import StrictError

_INSECURE_SSLMODES = {'disable', 'allow', 'prefer'}

_pool: ConnectionPool | None = None


def _conninfo(settings) -> str:
    return make_conninfo(
        host=settings.db_host,
        port=settings.db_port,
        dbname=settings.db_name,
        user=settings.db_user,
        password=settings.db_password,
        sslmode=settings.db_sslmode,
        connect_timeout=5,
        application_name='wmi-inventory',
    )


def init_pool(settings) -> None:
    global _pool
    if _pool is not None:
        return
    if settings.app_env == 'production' and settings.db_sslmode in _INSECURE_SSLMODES:
        raise StrictError('DB_SSLMODE must be require/verify-ca/verify-full in production', field='DB_SSLMODE')

    pool = ConnectionPool(
        _conninfo(settings),
        min_size=settings.db_pool_min,
        max_size=settings.db_pool_max,
        kwargs={'row_factory': dict_row},
        name='wmi-inventory',
        timeout=10,
        open=False,
    )
    pool.open(wait=False)
    _pool = pool


def close_pool() -> None:
    global _pool
    if _pool is not None:
        _pool.close()
        _pool = None


@contextmanager
def get_connection(timeout: float | None = None) -> Iterator[psycopg.Connection]:
    if _pool is None:
        raise StrictError('database pool is not initialised; call init_pool(settings) first')
    with _pool.connection(timeout=timeout) as conn:
        yield conn


def ping() -> bool:
    try:
        with get_connection(timeout=3) as conn:
            conn.execute('SELECT 1')
        return True
    except (psycopg.Error, StrictError):  # PoolTimeout is a psycopg.OperationalError
        return False
