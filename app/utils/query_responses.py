from enum import Enum

from core.errors import StrictError, ValidationError
from utils.field_validators import (
    drop_omitted,
    validate_bool,
    validate_inet,
    validate_inet_range,
    validate_int,
    validate_int_list,
    validate_str,
)

class ResponseTable(Enum):
    TB_SYS_IP_RANGES = 'tbsysipranges'
    TB_SYS_CRED_MASTER = 'tbsyscredmaster'


def tb_sys_cred_master_response(data: dict) -> dict:
    row = drop_omitted({
        'cred_user_name': validate_str(data.get('cred_user_name'), 'cred_user_name', required=True),
        'cred_password': validate_str(data.get('cred_password'), 'cred_password', required=True),
        'cred_is_domain': validate_bool(data.get('cred_is_domain'), 'cred_is_domain'),
        'cred_domain': validate_str(data.get('cred_domain'), 'cred_domain'),
        'cred_type': validate_int(data.get('cred_type'), 'cred_type'),
        'cred_global': validate_bool(data.get('cred_global'), 'cred_global'),
        'cred_status': validate_bool(data.get('cred_status'), 'cred_status'),
    })
    if row.get('cred_is_domain') and not row.get('cred_domain'):
        raise ValidationError('cred_domain is required when cred_is_domain is true', field='cred_domain')
    return row


def tb_sys_ip_ranges_response(data: dict) -> dict:
    row = drop_omitted({
        'start_ip': validate_inet(data.get('start_ip'), 'start_ip', required=True),
        'end_ip': validate_inet(data.get('end_ip'), 'end_ip', required=True),
        'range_enabled': validate_bool(data.get('range_enabled'), 'range_enabled'),
        'range_desc': validate_str(data.get('range_desc'), 'range_desc'),
        'site_id': validate_int(data.get('site_id'), 'site_id'),
        'cloud_id': validate_int(data.get('cloud_id'), 'cloud_id'),
        'scan_engine_id': validate_int(data.get('scan_engine_id'), 'scan_engine_id'),
        'cred_id_range': validate_int_list(data.get('cred_id_range'), 'cred_id_range'),
    })
    validate_inet_range(row['start_ip'], row['end_ip'], 'start_ip', 'end_ip')
    if 'cred_id_range' in row:
        row['cred_id_range'] = list(dict.fromkeys(row['cred_id_range']))
    return row

_TABLE_BUILDERS = {
    ResponseTable.TB_SYS_IP_RANGES: tb_sys_ip_ranges_response,
    ResponseTable.TB_SYS_CRED_MASTER: tb_sys_cred_master_response,
}

def create_query_response(data: dict, table: ResponseTable) -> dict:
    try:
        builder = _TABLE_BUILDERS[table]

    except KeyError:
        raise StrictError(f'unknown table {table!r}; expected one of {list(_TABLE_BUILDERS)}') from None
    return builder(data)
