from enum import Enum

from core.errors import StrictError
from utils.field_validators import drop_omitted, validate_bool, validate_inet, validate_str


class ResponseTable(Enum):
    TB_SYS_IP_RANGES = 'tb_sys_ip_ranges'


def tb_sys_ip_ranges_response(data: dict) -> dict:
    return drop_omitted({
        'start_ip': validate_inet(data.get('start_ip'), 'start_ip', required=True),
        'end_ip': validate_inet(data.get('end_ip'), 'end_ip', required=True),
        'range_enabled': validate_bool(data.get('range_enabled'), 'range_enabled'),
        'range_desc': validate_str(data.get('range_desc'), 'range_desc'),
        'site_id': validate_str(data.get('site_id'), 'site_id'),
        'cloud_id': validate_str(data.get('cloud_id'), 'cloud_id'),
        'scan_engine_id': validate_str(data.get('scan_engine_id'), 'scan_engine_id'),
        'cred_id_range': validate_str(data.get('cred_id_range'), 'cred_id_range'),
    })


_TABLE_BUILDERS = {
    ResponseTable.TB_SYS_IP_RANGES: tb_sys_ip_ranges_response,
}


def create_query_response(data: dict, table: ResponseTable) -> dict:
    try:
        builder = _TABLE_BUILDERS[table]
    except KeyError:
        raise StrictError(f'unknown table {table!r}; expected one of {list(_TABLE_BUILDERS)}') from None
    return builder(data)
