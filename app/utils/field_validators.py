import ipaddress
from typing import Any

from core.errors import ValidationError

OMIT = object()


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
        ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValidationError(f'{field_name} {value!r} is not a valid IP address', field=field_name) from exc
    return value


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
