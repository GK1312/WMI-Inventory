from datetime import datetime

from fastapi import APIRouter, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field

from core.db import get_connection
from core.errors import ValidationError
from core.security import encrypt_secret
from repositories.credentials import (
    delete_credential,
    get_credential,
    insert_credential,
    list_credentials,
    update_credential,
)
from repositories.ip_ranges import remove_credential_from_ranges
from utils.query_responses import ResponseTable, create_query_response

router = APIRouter(prefix='/credentials', tags=['credentials'])

_NOT_FOUND = 'credential not found'


class CredentialIn(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    cred_user_name: str = Field(min_length=1, max_length=256)
    cred_password: str = Field(min_length=1, max_length=1024)
    cred_is_domain: bool | None = None
    cred_domain: str | None = Field(default=None, min_length=1, max_length=255)
    cred_type: int | None = None
    cred_global: bool | None = None
    cred_status: bool | None = None


class CredentialUpdate(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    cred_user_name: str | None = Field(default=None, min_length=1, max_length=256)
    cred_password: str | None = Field(default=None, min_length=1, max_length=1024)
    cred_is_domain: bool | None = None
    cred_domain: str | None = Field(default=None, min_length=1, max_length=255)
    cred_type: int | None = None
    cred_global: bool | None = None
    cred_status: bool | None = None


class CredentialOut(BaseModel):
    credential_id: int
    cred_user_name: str | None
    cred_is_domain: bool | None
    cred_domain: str | None
    cred_type: int | None
    cred_global: bool | None
    cred_creation_date: datetime | None
    cred_update_date: datetime | None
    cred_validated: bool | None
    cred_status: bool | None


def _encrypt_password(row: dict, request: Request) -> dict:
    if row.get('cred_password') is None:
        return row
    return {**row, 'cred_password': encrypt_secret(row['cred_password'], request.app.state.settings.cred_encryption_key)}


@router.post('', response_model=CredentialOut, status_code=status.HTTP_201_CREATED)
def create_credential(body: CredentialIn, request: Request) -> dict:
    row = create_query_response(body.model_dump(), ResponseTable.TB_SYS_CRED_MASTER)
    with get_connection() as conn:
        return insert_credential(conn, _encrypt_password(row, request))


@router.get('', response_model=list[CredentialOut])
def read_credentials(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> list[dict]:
    with get_connection() as conn:
        return list_credentials(conn, limit=limit, offset=offset)


@router.get('/{credential_id}', response_model=CredentialOut)
def read_credential(credential_id: int) -> dict:
    with get_connection() as conn:
        row = get_credential(conn, credential_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=_NOT_FOUND)
    return row


@router.patch('/{credential_id}', response_model=CredentialOut)
def patch_credential(credential_id: int, body: CredentialUpdate, request: Request) -> dict:
    changes = body.model_dump(exclude_unset=True)
    if not changes:
        raise ValidationError('request body must include at least one field to update')
    with get_connection() as conn:
        current = get_credential(conn, credential_id, for_update=True)
        if current is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=_NOT_FOUND)
        merged = {field: current[field] for field in CredentialUpdate.model_fields} | changes
        row = create_query_response(merged, ResponseTable.TB_SYS_CRED_MASTER)
        updates = _encrypt_password({field: row.get(field) for field in changes}, request)
        return update_credential(conn, credential_id, updates)


@router.delete('/{credential_id}', status_code=status.HTTP_204_NO_CONTENT)
def remove_credential(credential_id: int) -> None:
    with get_connection() as conn:
        deleted = delete_credential(conn, credential_id)
        if deleted:
            remove_credential_from_ranges(conn, credential_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=_NOT_FOUND)
