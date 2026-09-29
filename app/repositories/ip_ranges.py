import psycopg
from psycopg import sql

from repositories.common import delete_row, get_row, insert_row, list_rows, update_row
from utils.query_responses import ResponseTable

_TABLE = ResponseTable.TB_SYS_IP_RANGES.value
_KEY = 'range_id'

def insert_ip_range(conn: psycopg.Connection, row: dict) -> dict:
    return insert_row(conn, _TABLE, row)

def get_ip_range(conn: psycopg.Connection, range_id: int, *, for_update: bool = False) -> dict | None:
    return get_row(conn, _TABLE, _KEY, range_id, for_update=for_update)

def list_ip_ranges(conn: psycopg.Connection, *, limit: int, offset: int) -> list[dict]:
    return list_rows(conn, _TABLE, _KEY, limit=limit, offset=offset)

def update_ip_range(conn: psycopg.Connection, range_id: int, changes: dict) -> dict | None:
    return update_row(conn, _TABLE, _KEY, range_id, changes)

def delete_ip_range(conn: psycopg.Connection, range_id: int) -> bool:
    return delete_row(conn, _TABLE, _KEY, range_id)

def remove_credential_from_ranges(conn: psycopg.Connection, credential_id: int) -> int:
    query = sql.SQL(
        'UPDATE {table} SET cred_id_range = array_remove(cred_id_range, %(cid)s) WHERE %(cid)s = ANY(cred_id_range)'
    ).format(table=sql.Identifier(_TABLE))
    return conn.execute(query, {'cid': credential_id}).rowcount
