from __future__ import annotations

import socket
import struct
import uuid
from dataclasses import dataclass
from typing import Any

from core.errors import ProbeError
from core.logging import get_logger
from probes.tcp_ping import resolve_host, validate_port, validate_timeout

logger = get_logger(__name__)

PROBE_NAME = 'smb_ntlm'
DEFAULT_PORT = 445
DEFAULT_TIMEOUT = 2.0

_STATUS_SUCCESS = 0x00000000
_STATUS_MORE_PROCESSING_REQUIRED = 0xC0000016

_NBSS_SESSION_MESSAGE = 0x00

_SMB1_SIGNATURE = b'\xffSMB'
_SMB2_SIGNATURE = b'\xfeSMB'

_SMB1_COM_NEGOTIATE = 0x72
_SMB1_COM_SESSION_SETUP_ANDX = 0x73
_SMB1_DIALECTS = ('NT LM 0.12',)
_SMB1_FLAGS2_LONG_NAMES = 0x0001
_SMB1_FLAGS2_EXTENDED_SECURITY = 0x0800
_SMB1_FLAGS2_NT_STATUS = 0x4000
_SMB1_FLAGS2_UNICODE = 0x8000
_SMB1_CAP_UNICODE = 0x00000004
_SMB1_CAP_NT_SMBS = 0x00000010
_SMB1_CAP_STATUS32 = 0x00000040
_SMB1_CAP_EXTENDED_SECURITY = 0x80000000
_SMB1_CAPS = _SMB1_CAP_UNICODE | _SMB1_CAP_NT_SMBS | _SMB1_CAP_STATUS32 | _SMB1_CAP_EXTENDED_SECURITY

_SMB2_NEGOTIATE = 0
_SMB2_SESSION_SETUP = 1
_SMB2_DIALECTS = (0x0202, 0x0210, 0x0300, 0x0302)
_SMB2_DIALECT_NAMES = {
    0x0202: 'SMB 2.0.2',
    0x0210: 'SMB 2.1',
    0x0300: 'SMB 3.0',
    0x0302: 'SMB 3.0.2',
}

_NTLM_SIGNATURE = b'NTLMSSP\x00'
_NTLM_NEGOTIATE_FLAGS = 0xA0088205
_NTLM_FLAG_TARGET_INFO = 0x00800000
_NTLM_FLAG_VERSION = 0x02000000

_AV_EOL = 0
_AV_NB_COMPUTER_NAME = 1
_AV_NB_DOMAIN_NAME = 2
_AV_DNS_COMPUTER_NAME = 3
_AV_DNS_DOMAIN_NAME = 4
_AV_FIELD_NAMES = {
    _AV_NB_COMPUTER_NAME: 'netbios_computer_name',
    _AV_NB_DOMAIN_NAME: 'netbios_domain_name',
    _AV_DNS_COMPUTER_NAME: 'dns_computer_name',
    _AV_DNS_DOMAIN_NAME: 'dns_domain_name',
}


@dataclass(frozen=True)
class SmbNtlmResult:
    host: str
    port: int
    reachable: bool
    dialect: str | None
    ntlm_available: bool
    netbios_computer_name: str | None = None
    netbios_domain_name: str | None = None
    dns_computer_name: str | None = None
    dns_domain_name: str | None = None
    os_major: int | None = None
    os_minor: int | None = None
    os_build: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            'probe': PROBE_NAME,
            'host': self.host,
            'port': self.port,
            'reachable': self.reachable,
            'dialect': self.dialect,
            'ntlm_available': self.ntlm_available,
            'netbios_computer_name': self.netbios_computer_name,
            'netbios_domain_name': self.netbios_domain_name,
            'dns_computer_name': self.dns_computer_name,
            'dns_domain_name': self.dns_domain_name,
            'os_major': self.os_major,
            'os_minor': self.os_minor,
            'os_build': self.os_build,
        }


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks = []
    remaining = size
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ProbeError('connection closed while reading SMB response')
        chunks.append(chunk)
        remaining -= len(chunk)
    return b''.join(chunks)


def _send_nbss(sock: socket.socket, payload: bytes) -> None:
    sock.sendall(struct.pack('>I', len(payload)) + payload)


def _recv_nbss(sock: socket.socket) -> bytes:
    header = _recv_exact(sock, 4)
    if header[0] != _NBSS_SESSION_MESSAGE:
        raise ProbeError(f'unexpected NetBIOS session service message type {header[0]}')
    length = struct.unpack('>I', header)[0] & 0x00FFFFFF
    return _recv_exact(sock, length)


def _build_ntlm_negotiate() -> bytes:
    return (
        _NTLM_SIGNATURE
        + struct.pack('<I', 1)
        + struct.pack('<I', _NTLM_NEGOTIATE_FLAGS)
        + struct.pack('<HHI', 0, 0, 32)
        + struct.pack('<HHI', 0, 0, 32)
    )


def _parse_av_pairs(data: bytes, offset: int, length: int, fields: dict[str, Any]) -> None:
    end = offset + length
    if offset < 0 or length < 0 or end > len(data):
        raise ProbeError('truncated NTLM target info')
    pos = offset
    while pos + 4 <= end:
        av_id, av_len = struct.unpack_from('<HH', data, pos)
        pos += 4
        if av_id == _AV_EOL:
            break
        if pos + av_len > end:
            raise ProbeError('truncated NTLM AV_PAIR value')
        key = _AV_FIELD_NAMES.get(av_id)
        if key:
            fields[key] = data[pos:pos + av_len].decode('utf-16-le', errors='replace')
        pos += av_len


def _parse_ntlm_challenge(data: bytes) -> dict[str, Any]:
    if len(data) < 32 or data[:8] != _NTLM_SIGNATURE or struct.unpack_from('<I', data, 8)[0] != 2:
        raise ProbeError('malformed NTLM challenge message')
    negotiate_flags = struct.unpack_from('<I', data, 20)[0]
    fields: dict[str, Any] = {
        'netbios_computer_name': None,
        'netbios_domain_name': None,
        'dns_computer_name': None,
        'dns_domain_name': None,
        'os_major': None,
        'os_minor': None,
        'os_build': None,
    }
    if negotiate_flags & _NTLM_FLAG_TARGET_INFO and len(data) >= 48:
        ti_len, _ti_max, ti_offset = struct.unpack_from('<HHI', data, 40)
        _parse_av_pairs(data, ti_offset, ti_len, fields)
    if negotiate_flags & _NTLM_FLAG_VERSION and len(data) >= 56:
        major, minor, build = struct.unpack_from('<BBH', data, 48)
        fields['os_major'] = major
        fields['os_minor'] = minor
        fields['os_build'] = build
    return fields


def _smb1_header(command: int, flags2: int, mid: int) -> bytes:
    return (
        _SMB1_SIGNATURE
        + bytes((command,))
        + struct.pack('<I', 0)
        + bytes((0x18,))
        + struct.pack('<H', flags2)
        + struct.pack('<H', 0)
        + bytes(8)
        + struct.pack('<H', 0)
        + struct.pack('<H', 0xFFFF)
        + struct.pack('<H', 0x1234)
        + struct.pack('<H', 0)
        + struct.pack('<H', mid)
    )


def _build_smb1_negotiate() -> bytes:
    flags2 = _SMB1_FLAGS2_LONG_NAMES | _SMB1_FLAGS2_EXTENDED_SECURITY | _SMB1_FLAGS2_NT_STATUS | _SMB1_FLAGS2_UNICODE
    dialects = b''.join(b'\x02' + dialect.encode('ascii') + b'\x00' for dialect in _SMB1_DIALECTS)
    body = bytes((0,)) + struct.pack('<H', len(dialects)) + dialects
    return _smb1_header(_SMB1_COM_NEGOTIATE, flags2, 0) + body


def _parse_smb1_negotiate(message: bytes) -> None:
    if len(message) < 33:
        raise ProbeError('truncated SMB1 negotiate response')
    command = message[4]
    status = struct.unpack_from('<I', message, 5)[0]
    if command != _SMB1_COM_NEGOTIATE or status != _STATUS_SUCCESS:
        raise ProbeError(f'SMB1 negotiate rejected (status=0x{status:08x})')
    word_count = message[32]
    if word_count < 1 or len(message) < 35:
        raise ProbeError('SMB1 server rejected all offered dialects')
    dialect_index = struct.unpack_from('<H', message, 33)[0]
    if dialect_index != 0:
        raise ProbeError(f'unexpected SMB1 dialect index {dialect_index}')


def _build_smb1_session_setup(ntlm_blob: bytes) -> bytes:
    flags2 = _SMB1_FLAGS2_LONG_NAMES | _SMB1_FLAGS2_EXTENDED_SECURITY | _SMB1_FLAGS2_NT_STATUS
    params = (
        struct.pack('<BB', 0xFF, 0)
        + struct.pack('<H', 0)
        + struct.pack('<H', 4356)
        + struct.pack('<H', 50)
        + struct.pack('<H', 0)
        + struct.pack('<I', 0)
        + struct.pack('<H', len(ntlm_blob))
        + struct.pack('<I', 0)
        + struct.pack('<I', _SMB1_CAPS)
    )
    body_bytes = ntlm_blob + b'\x00\x00'
    body = bytes((len(params) // 2,)) + params + struct.pack('<H', len(body_bytes)) + body_bytes
    return _smb1_header(_SMB1_COM_SESSION_SETUP_ANDX, flags2, 1) + body


def _parse_smb1_session_setup(message: bytes) -> bytes | None:
    if len(message) < 33:
        raise ProbeError('truncated SMB1 session setup response')
    command = message[4]
    status = struct.unpack_from('<I', message, 5)[0]
    if command != _SMB1_COM_SESSION_SETUP_ANDX:
        raise ProbeError(f'unexpected SMB1 command 0x{command:02x} replying to session setup')
    if status not in (_STATUS_SUCCESS, _STATUS_MORE_PROCESSING_REQUIRED):
        return None
    if len(message) < 43:
        raise ProbeError('truncated SMB1 session setup response')
    word_count = message[32]
    if word_count < 4:
        raise ProbeError('SMB1 session setup response missing security blob')
    security_blob_length = struct.unpack_from('<H', message, 39)[0]
    blob_start = 43
    if len(message) < blob_start + security_blob_length:
        raise ProbeError('truncated SMB1 session setup security blob')
    return message[blob_start:blob_start + security_blob_length]


def _smb2_header(command: int, message_id: int) -> bytes:
    return (
        _SMB2_SIGNATURE
        + struct.pack('<H', 64)
        + struct.pack('<H', 0)
        + struct.pack('<I', 0)
        + struct.pack('<H', command)
        + struct.pack('<H', 1)
        + struct.pack('<I', 0)
        + struct.pack('<I', 0)
        + struct.pack('<Q', message_id)
        + struct.pack('<I', 0)
        + struct.pack('<I', 0)
        + struct.pack('<Q', 0)
        + bytes(16)
    )


def _parse_smb2_header(message: bytes) -> tuple[int, int]:
    if len(message) < 64 or message[:4] != _SMB2_SIGNATURE:
        raise ProbeError('malformed SMB2 header')
    status = struct.unpack_from('<I', message, 8)[0]
    command = struct.unpack_from('<H', message, 12)[0]
    return status, command


def _build_smb2_negotiate(client_guid: bytes) -> bytes:
    dialects = b''.join(struct.pack('<H', dialect) for dialect in _SMB2_DIALECTS)
    body = (
        struct.pack('<H', 36)
        + struct.pack('<H', len(_SMB2_DIALECTS))
        + struct.pack('<H', 0)
        + struct.pack('<H', 0)
        + struct.pack('<I', 0)
        + client_guid
        + bytes(8)
        + dialects
    )
    return _smb2_header(_SMB2_NEGOTIATE, 0) + body


def _parse_smb2_negotiate(message: bytes) -> int:
    status, command = _parse_smb2_header(message)
    if command != _SMB2_NEGOTIATE or status != _STATUS_SUCCESS:
        raise ProbeError(f'SMB2 negotiate rejected (status=0x{status:08x})')
    if len(message) < 70:
        raise ProbeError('truncated SMB2 negotiate response')
    return struct.unpack_from('<H', message, 68)[0]


def _build_smb2_session_setup(ntlm_blob: bytes, message_id: int) -> bytes:
    offset = 64 + 24
    body = (
        struct.pack('<H', 25)
        + bytes((0, 0))
        + struct.pack('<I', 0)
        + struct.pack('<I', 0)
        + struct.pack('<H', offset)
        + struct.pack('<H', len(ntlm_blob))
        + struct.pack('<Q', 0)
        + ntlm_blob
    )
    return _smb2_header(_SMB2_SESSION_SETUP, message_id) + body


def _parse_smb2_session_setup(message: bytes) -> bytes | None:
    status, command = _parse_smb2_header(message)
    if command != _SMB2_SESSION_SETUP:
        raise ProbeError(f'unexpected SMB2 command {command} replying to session setup')
    if status not in (_STATUS_SUCCESS, _STATUS_MORE_PROCESSING_REQUIRED):
        return None
    if len(message) < 72:
        raise ProbeError('truncated SMB2 session setup response')
    sec_offset, sec_length = struct.unpack_from('<HH', message, 68)
    if len(message) < sec_offset + sec_length:
        raise ProbeError('truncated SMB2 session setup security buffer')
    return message[sec_offset:sec_offset + sec_length]


def _extract_ntlm_fields(security_buffer: bytes | None, host: str) -> tuple[bool, dict[str, Any]]:
    fields: dict[str, Any] = {
        'netbios_computer_name': None,
        'netbios_domain_name': None,
        'dns_computer_name': None,
        'dns_domain_name': None,
        'os_major': None,
        'os_minor': None,
        'os_build': None,
    }
    if security_buffer is None:
        logger.debug('smb_ntlm %s: session setup rejected, no NTLM challenge', host)
        return False, fields
    if len(security_buffer) < 12 or security_buffer[:8] != _NTLM_SIGNATURE or struct.unpack_from('<I', security_buffer, 8)[0] != 2:
        logger.debug('smb_ntlm %s: session setup did not return an NTLM challenge', host)
        return False, fields
    fields.update(_parse_ntlm_challenge(security_buffer))
    return True, fields


def _run_smb2(host: str, port: int, address: Any, timeout: float) -> SmbNtlmResult:
    with socket.create_connection((str(address), port), timeout=timeout) as sock:
        _send_nbss(sock, _build_smb2_negotiate(uuid.uuid4().bytes))
        message = _recv_nbss(sock)
        if message[:4] != _SMB2_SIGNATURE:
            raise ProbeError('server did not reply with SMB2 to a native SMB2 negotiate')
        dialect_revision = _parse_smb2_negotiate(message)
        dialect = _SMB2_DIALECT_NAMES.get(dialect_revision, f'0x{dialect_revision:04x}')
        _send_nbss(sock, _build_smb2_session_setup(_build_ntlm_negotiate(), 1))
        security_buffer = _parse_smb2_session_setup(_recv_nbss(sock))

    ntlm_available, fields = _extract_ntlm_fields(security_buffer, host)
    return SmbNtlmResult(host, port, True, dialect, ntlm_available, **fields)


def _run_smb1(host: str, port: int, address: Any, timeout: float) -> SmbNtlmResult:
    with socket.create_connection((str(address), port), timeout=timeout) as sock:
        _send_nbss(sock, _build_smb1_negotiate())
        _parse_smb1_negotiate(_recv_nbss(sock))
        _send_nbss(sock, _build_smb1_session_setup(_build_ntlm_negotiate()))
        security_buffer = _parse_smb1_session_setup(_recv_nbss(sock))

    ntlm_available, fields = _extract_ntlm_fields(security_buffer, host)
    return SmbNtlmResult(host, port, True, 'NT LM 0.12', ntlm_available, **fields)


def smb_ntlm(host: str, *, port: int = DEFAULT_PORT, timeout: float = DEFAULT_TIMEOUT) -> SmbNtlmResult:
    port = validate_port(port)
    timeout = validate_timeout(timeout)
    address = resolve_host(host)

    try:
        result = _run_smb2(host, port, address, timeout)
    except (OSError, ProbeError) as exc:
        logger.debug('smb_ntlm %s: SMB2 negotiate failed (%s), falling back to SMB1', host, exc)
        try:
            result = _run_smb1(host, port, address, timeout)
        except OSError as exc2:
            raise ProbeError(f'SMB NTLM probe to {address}:{port} failed: {exc2}') from exc2

    logger.data('smb_ntlm %s -> %s', host, result.to_dict())
    return result
