from datetime import datetime

import psycopg
from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress

from core.db import get_connection
from core.errors import ValidationError
from repositories.credentials import lock_existing_credential_ids
from repositories.ip_ranges import delete_ip_range, get_ip_range, insert_ip_range, list_ip_ranges, update_ip_range
from utils.query_responses import ResponseTable, create_query_response

router = APIRouter(prefix='/ip-ranges', tags=['ip-ranges'])

_NOT_FOUND = 'ip range not found'


class IpRangeIn(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    start_ip: str = Field(max_length=45)
    end_ip: str = Field(max_length=45)
    range_enabled: bool | None = None
    range_desc: str | None = Field(default=None, max_length=500)
    site_id: int | None = None
    cloud_id: int | None = None
    scan_engine_id: int | None = None
    cred_id_range: list[int] | None = Field(default=None, max_length=100)


class IpRangeUpdate(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    start_ip: str = Field(default=None, max_length=45)
    end_ip: str = Field(default=None, max_length=45)
    range_enabled: bool | None = None
    range_desc: str | None = Field(default=None, max_length=500)
    site_id: int | None = None
    cloud_id: int | None = None
    scan_engine_id: int | None = None
    cred_id_range: list[int] | None = Field(default=None, max_length=100)


class IpRangeOut(BaseModel):
    range_id: int
    start_ip: IPvAnyAddress | None
    end_ip: IPvAnyAddress | None
    range_enabled: bool | None
    last_scan_time: datetime | None
    range_desc: str | None
    site_id: int | None
    cloud_id: int | None
    scan_engine_id: int | None
    last_updated_time: datetime
    cred_id_range: list[int] | None


def _as_input(value):
    if value is None or isinstance(value, (bool, int, str, list)):
        return value
    return str(getattr(value, 'ip', value))


def _check_credentials(conn: psycopg.Connection, credential_ids: list[int] | None) -> None:
    if not credential_ids:
        return
    existing = lock_existing_credential_ids(conn, credential_ids)
    missing = [cid for cid in credential_ids if cid not in existing]
    if missing:
        raise ValidationError(f'unknown credential id(s): {missing}', field='cred_id_range')


@router.post('', response_model=IpRangeOut, status_code=status.HTTP_201_CREATED)
def create_ip_range(body: IpRangeIn) -> dict:
    row = create_query_response(body.model_dump(), ResponseTable.TB_SYS_IP_RANGES)
    with get_connection() as conn:
        _check_credentials(conn, row.get('cred_id_range'))
        return insert_ip_range(conn, row)


@router.get('', response_model=list[IpRangeOut])
def read_ip_ranges(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> list[dict]:
    with get_connection() as conn:
        return list_ip_ranges(conn, limit=limit, offset=offset)


@router.get('/{range_id}', response_model=IpRangeOut)
def read_ip_range(range_id: int) -> dict:
    with get_connection() as conn:
        row = get_ip_range(conn, range_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=_NOT_FOUND)
    return row


@router.patch('/{range_id}', response_model=IpRangeOut)
def patch_ip_range(range_id: int, body: IpRangeUpdate) -> dict:
    changes = body.model_dump(exclude_unset=True)
    if not changes:
        raise ValidationError('request body must include at least one field to update')
    with get_connection() as conn:
        current = get_ip_range(conn, range_id, for_update=True)
        if current is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=_NOT_FOUND)
        merged = {field: _as_input(current[field]) for field in IpRangeUpdate.model_fields} | changes
        row = create_query_response(merged, ResponseTable.TB_SYS_IP_RANGES)
        updates = {field: row.get(field) for field in changes}
        if 'cred_id_range' in updates:
            _check_credentials(conn, updates['cred_id_range'])
        return update_ip_range(conn, range_id, updates)


@router.delete('/{range_id}', status_code=status.HTTP_204_NO_CONTENT)
def remove_ip_range(range_id: int) -> None:
    with get_connection() as conn:
        deleted = delete_ip_range(conn, range_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=_NOT_FOUND)
