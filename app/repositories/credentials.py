import psycopg
from psycopg import sql

from repositories.common import NOW, delete_row, get_row, insert_row, list_rows, update_row
from utils.query_responses import ResponseTable

_TABLE = ResponseTable.TB_SYS_CRED_MASTER.value
_KEY = 'credential_id'

def insert_credential(conn: psycopg.Connection, row: dict) -> dict:
    return insert_row(conn, _TABLE, row, server_values={'cred_creation_date': NOW, 'cred_update_date': NOW})

def get_credential(conn: psycopg.Connection, credential_id: int, *, for_update: bool = False) -> dict | None:
    return get_row(conn, _TABLE, _KEY, credential_id, for_update=for_update)

def list_credentials(conn: psycopg.Connection, *, limit: int, offset: int) -> list[dict]:
    return list_rows(conn, _TABLE, _KEY, limit=limit, offset=offset)

def update_credential(conn: psycopg.Connection, credential_id: int, changes: dict) -> dict | None:
    return update_row(conn, _TABLE, _KEY, credential_id, changes, server_values={'cred_update_date': NOW})

def delete_credential(conn: psycopg.Connection, credential_id: int) -> bool:
    return delete_row(conn, _TABLE, _KEY, credential_id)

def lock_existing_credential_ids(conn: psycopg.Connection, credential_ids: list[int]) -> set[int]:
    query = sql.SQL('SELECT {key} FROM {table} WHERE {key} = ANY(%s) FOR SHARE').format(
        table=sql.Identifier(_TABLE),
        key=sql.Identifier(_KEY),
    )
    return {row[_KEY] for row in conn.execute(query, (credential_ids,)).fetchall()}
