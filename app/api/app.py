from __future__ import annotations

import logging
import re
from contextlib import asynccontextmanager

import psycopg
from fastapi import APIRouter, Depends, FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware

from api.auth import require_api_key
from api.middleware import BodySizeLimitMiddleware, SecurityHeadersMiddleware
from api.routes import credentials, ip_ranges
from core import db
from core.errors import StrictError, ValidationError
from core.logging import setup_logging

logger = logging.getLogger(__name__)


def create_app(settings) -> FastAPI:
    if not settings.api_key_hashes:
        raise StrictError(
            'API_KEY_HASHES is empty; generate a key with app/core/security.py', field='API_KEY_HASHES'
        )
    if not settings.cred_encryption_key:
        raise StrictError(
            'CRED_ENCRYPTION_KEY is empty; generate one with app/core/security.py encryption-key',
            field='CRED_ENCRYPTION_KEY',
        )
    setup_logging(settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        db.init_pool(settings)
        try:
            yield
        finally:
            db.close_pool()

    docs_enabled = settings.app_env == 'development'
    app = FastAPI(
        title='WMI Inventory API',
        version='0.1.0',
        lifespan=lifespan,
        docs_url='/docs' if docs_enabled else None,
        redoc_url=None,
        openapi_url='/openapi.json' if docs_enabled else None,
    )
    app.state.settings = settings

    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_body_bytes)
    app.add_middleware(SecurityHeadersMiddleware, hsts=settings.app_env != 'development')
    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(settings.cors_origins),
            allow_credentials=False,
            allow_methods=['GET', 'POST', 'PATCH', 'DELETE'],
            allow_headers=['Authorization', 'Content-Type'],
        )
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(settings.trusted_hosts))

    _register_error_handlers(app)

    @app.get('/health', tags=['health'])
    def health() -> JSONResponse:
        db_ok = db.ping()
        return JSONResponse(
            {'status': 'ok' if db_ok else 'degraded', 'database': 'ok' if db_ok else 'unavailable'},
            status_code=status.HTTP_200_OK if db_ok else status.HTTP_503_SERVICE_UNAVAILABLE,
        )

    v1 = APIRouter(prefix='/api/v1', dependencies=[Depends(require_api_key)])
    v1.include_router(ip_ranges.router)
    v1.include_router(credentials.router)
    app.include_router(v1)
    return app


def _register_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(ValidationError)
    async def _validation(request: Request, exc: ValidationError) -> JSONResponse:
        return JSONResponse({'detail': str(exc), 'field': exc.field}, status_code=422)

    @app.exception_handler(psycopg.errors.UniqueViolation)
    async def _unique(request: Request, exc: psycopg.Error) -> JSONResponse:
        return JSONResponse({'detail': 'resource already exists'}, status_code=409)

    @app.exception_handler(psycopg.errors.CheckViolation)
    async def _check(request: Request, exc: psycopg.Error) -> JSONResponse:
        constraint = exc.diag.constraint_name
        return JSONResponse({'detail': f'violates constraint {constraint}'}, status_code=422)

    @app.exception_handler(psycopg.errors.ForeignKeyViolation)
    async def _foreign_key(request: Request, exc: psycopg.Error) -> JSONResponse:
        if 'is still referenced' in (exc.diag.message_detail or ''):
            return JSONResponse({'detail': 'record is still referenced by other records'}, status_code=409)
        match = re.match(r'Key \((\w+)\)=', exc.diag.message_detail or '')
        column = match.group(1) if match else None
        detail = f'{column} does not reference an existing record' if column else 'referenced record does not exist'
        return JSONResponse({'detail': detail, 'field': column}, status_code=422)

    @app.exception_handler(psycopg.errors.NotNullViolation)
    async def _not_null(request: Request, exc: psycopg.Error) -> JSONResponse:
        column = exc.diag.column_name
        return JSONResponse({'detail': f'{column} must not be null', 'field': column}, status_code=422)

    @app.exception_handler(psycopg.OperationalError)
    async def _db_unavailable(request: Request, exc: psycopg.Error) -> JSONResponse:
        logger.error('database unavailable: %s', exc)
        return JSONResponse({'detail': 'database unavailable'}, status_code=503)

    @app.exception_handler(psycopg.Error)
    async def _db_error(request: Request, exc: psycopg.Error) -> JSONResponse:
        logger.exception('database error on %s %s', request.method, request.url.path)
        return JSONResponse({'detail': 'internal server error'}, status_code=500)

    @app.exception_handler(StrictError)
    async def _strict(request: Request, exc: StrictError) -> JSONResponse:
        logger.error('strict error on %s %s: %s', request.method, request.url.path, exc)
        return JSONResponse({'detail': 'internal server error'}, status_code=500)

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        logger.exception('unhandled error on %s %s', request.method, request.url.path)
        return JSONResponse({'detail': 'internal server error'}, status_code=500)
