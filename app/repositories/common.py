from uuid import UUID

import psycopg
from psycopg import sql

NOW = sql.SQL('LOCALTIMESTAMP')

def insert_row(
    conn: psycopg.Connection,
    table: str,
    row: dict,
    *,
    server_values: dict[str, sql.Composable] | None = None,
) -> dict:
    server_values = server_values or {}
    query = sql.SQL('INSERT INTO {table} ({columns}) VALUES ({values}) RETURNING *').format(
        table=sql.Identifier(table),
        columns=sql.SQL(', ').join(map(sql.Identifier, [*row, *server_values])),
        values=sql.SQL(', ').join([*(sql.Placeholder(col) for col in row), *server_values.values()]),
    )
    return conn.execute(query, row).fetchone()

def get_row(conn: psycopg.Connection, table: str, key_column: str, key: int | UUID, *, for_update: bool = False) -> dict | None:
    query = sql.SQL('SELECT * FROM {table} WHERE {key_column} = %s{lock}').format(
        table=sql.Identifier(table),
        key_column=sql.Identifier(key_column),
        lock=sql.SQL(' FOR UPDATE' if for_update else ''),
    )
    return conn.execute(query, (key,)).fetchone()

def list_rows(conn: psycopg.Connection, table: str, key_column: str, *, limit: int, offset: int) -> list[dict]:
    query = sql.SQL('SELECT * FROM {table} ORDER BY {key_column} LIMIT %s OFFSET %s').format(
        table=sql.Identifier(table),
        key_column=sql.Identifier(key_column),
    )
    return conn.execute(query, (limit, offset)).fetchall()

def update_row(
    conn: psycopg.Connection,
    table: str,
    key_column: str,
    key: int | UUID,
    changes: dict,
    *,
    server_values: dict[str, sql.Composable] | None = None,
) -> dict | None:
    server_values = server_values or {}
    assignments = [
        *(sql.SQL('{} = {}').format(sql.Identifier(col), sql.Placeholder(col)) for col in changes),
        *(sql.SQL('{} = {}').format(sql.Identifier(col), value) for col, value in server_values.items()),
    ]
    query = sql.SQL('UPDATE {table} SET {assignments} WHERE {key_column} = %(__key)s RETURNING *').format(
        table=sql.Identifier(table),
        assignments=sql.SQL(', ').join(assignments),
        key_column=sql.Identifier(key_column),
    )
    return conn.execute(query, {**changes, '__key': key}).fetchone()

def delete_row(conn: psycopg.Connection, table: str, key_column: str, key: int | UUID) -> bool:
    query = sql.SQL('DELETE FROM {table} WHERE {key_column} = %s').format(
        table=sql.Identifier(table),
        key_column=sql.Identifier(key_column),
    )
    return conn.execute(query, (key,)).rowcount > 0
