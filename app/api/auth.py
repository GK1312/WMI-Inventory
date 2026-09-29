import logging

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from core.security import verify_api_key

logger = logging.getLogger(__name__)

_bearer = HTTPBearer(auto_error=False, description='API key sent as `Authorization: Bearer <key>`')

_UNAUTHORIZED = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail='invalid or missing API key',
    headers={'WWW-Authenticate': 'Bearer'},
)


def require_api_key(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> None:
    if credentials is None or credentials.scheme.lower() != 'bearer':
        raise _UNAUTHORIZED
    if not verify_api_key(credentials.credentials, request.app.state.settings.api_key_hashes):
        client = request.client.host if request.client else 'unknown'
        logger.warning('rejected API key from %s for %s %s', client, request.method, request.url.path)
        raise _UNAUTHORIZED
