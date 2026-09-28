from enum import Enum

from core.errors import StrictError

class ResponseKind(Enum):
    pass

_OTHER_BUILDERS = {}

def create_other_response(data: dict, kind: ResponseKind) -> dict:
    try:
        builder = _OTHER_BUILDERS[kind]
    except KeyError:
        raise StrictError(f'unknown response kind {kind!r}; expected one of {list(_OTHER_BUILDERS)}') from None
    return builder(data)
