from __future__ import annotations

import ipaddress
from typing import Any

from core.errors import ValidationError

OMIT = object()

INT4_MIN = -2_147_483_648
INT4_MAX = 2_147_483_647

def drop_omitted(fields: dict) -> dict:
    return {key: value for key, value in fields.items() if value is not OMIT}

def validate_inet(value, field_name: str, default: Any = OMIT, required: bool = False) -> OMIT | str | Any:
    if value is None or value == '':
        if required:
            raise ValidationError(f'{field_name} is required', field=field_name)
        return default
    if not isinstance(value, str):
        raise ValidationError(f'{field_name} must be a string, got {type(value).__name__}', field=field_name)
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValidationError(f'{field_name} {value!r} is not a valid IP address', field=field_name) from exc
    if getattr(address, 'scope_id', None):
        raise ValidationError(f'{field_name} {value!r} must not include an IPv6 zone (%...)', field=field_name)
    return value

def validate_inet_range(start: str, end: str, start_field: str, end_field: str) -> None:
    start_ip = ipaddress.ip_address(start)
    end_ip = ipaddress.ip_address(end)
    if start_ip.version != end_ip.version:
        raise ValidationError(
            f'{start_field} and {end_field} must both be IPv4 or both be IPv6', field=end_field
        )
    if start_ip > end_ip:
        raise ValidationError(f'{start_field} {start} is greater than {end_field} {end}', field=start_field)

def validate_bool(value, field_name: str, default: Any = OMIT, required: bool = False) -> OMIT | bool | Any:
    if value is None:
        if required:
            raise ValidationError(f'{field_name} is required', field=field_name)
        return default
    if not isinstance(value, bool):
        raise ValidationError(f'{field_name} must be a bool, got {type(value).__name__}', field=field_name)
    return value

def validate_str(value, field_name: str, default: Any = OMIT, required: bool = False) -> OMIT | str | Any:
    if value is None:
        if required:
            raise ValidationError(f'{field_name} is required', field=field_name)
        return default
    if not isinstance(value, str):
        raise ValidationError(f'{field_name} must be a string, got {type(value).__name__}', field=field_name)
    return value

def _check_int4(value, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError(f'{field_name} must be an integer, got {type(value).__name__}', field=field_name)
    if not INT4_MIN <= value <= INT4_MAX:
        raise ValidationError(f'{field_name} {value} is out of range for an integer column', field=field_name)
    return value

def validate_int(value, field_name: str, default: Any = OMIT, required: bool = False) -> OMIT | int | Any:
    if value is None:
        if required:
            raise ValidationError(f'{field_name} is required', field=field_name)
        return default
    return _check_int4(value, field_name)

def validate_int_list(value, field_name: str, default: Any = OMIT, required: bool = False) -> OMIT | list[int] | Any:
    if value is None:
        if required:
            raise ValidationError(f'{field_name} is required', field=field_name)
        return default
    if not isinstance(value, list):
        raise ValidationError(f'{field_name} must be a list of integers, got {type(value).__name__}', field=field_name)
    return [_check_int4(item, field_name) for item in value]