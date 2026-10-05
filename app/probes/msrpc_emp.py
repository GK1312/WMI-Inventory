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

PROBE_NAME = 'msrpc_emp'
DEFAULT_PORT = 135
DEFAULT_TIMEOUT = 2.0

_MAX_XMIT_FRAG = 4280
_MAX_RECV_FRAG = 4280

_PTYPE_BIND = 11
_PTYPE_BIND_ACK = 12
_PTYPE_BIND_NAK = 13

_PFC_FIRST_FRAG = 0x01
_PFC_LAST_FRAG = 0x02

_DREP = bytes((0x10, 0x00, 0x00, 0x00))

_EPM_IFACE_UUID = uuid.UUID('e1af8308-5d1f-11c9-91a4-08002b14a0fa')
_EPM_IFACE_VERSION = (3, 0)
_NDR_SYNTAX_UUID = uuid.UUID('8a885d04-1ceb-11c9-9fe8-08002b104860')
_NDR_SYNTAX_VERSION = (2, 0)


@dataclass(frozen=True)
class EmpResult:
    host: str
    port: int
    reachable: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            'probe': PROBE_NAME,
            'host': self.host,
            'port': self.port,
            'reachable': self.reachable,
        }


def _pdu_header(ptype: int, pfc_flags: int, call_id: int, frag_length: int) -> bytes:
    return struct.pack('<BBBB', 5, 0, ptype, pfc_flags) + _DREP + struct.pack('<HHI', frag_length, 0, call_id)


def _build_bind(call_id: int) -> bytes:
    context_item = (
        struct.pack('<HBB', 0, 1, 0)
        + _EPM_IFACE_UUID.bytes_le + struct.pack('<HH', *_EPM_IFACE_VERSION)
        + _NDR_SYNTAX_UUID.bytes_le + struct.pack('<HH', *_NDR_SYNTAX_VERSION)
    )
    body = struct.pack('<HHIBBH', _MAX_XMIT_FRAG, _MAX_RECV_FRAG, 0, 1, 0, 0) + context_item
    frag_length = 16 + len(body)
    return _pdu_header(_PTYPE_BIND, _PFC_FIRST_FRAG | _PFC_LAST_FRAG, call_id, frag_length) + body


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks = []
    remaining = size
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ProbeError('connection closed while reading MSRPC response')
        chunks.append(chunk)
        remaining -= len(chunk)
    return b''.join(chunks)


def _recv_pdu(sock: socket.socket) -> tuple[int, bytes]:
    header = _recv_exact(sock, 16)
    rpc_vers, rpc_vers_minor, ptype, _pfc_flags = struct.unpack('<BBBB', header[:4])
    frag_length, auth_length, _call_id = struct.unpack('<HHI', header[8:16])
    if rpc_vers != 5:
        raise ProbeError(f'unexpected MSRPC version {rpc_vers}.{rpc_vers_minor}')
    if frag_length < 16:
        raise ProbeError(f'invalid MSRPC fragment length {frag_length}')
    body = _recv_exact(sock, frag_length - 16)
    if auth_length:
        body = body[:-auth_length]
    return ptype, body


def _parse_bind_ack(body: bytes) -> bool:
    if len(body) < 10:
        raise ProbeError('truncated MSRPC bind_ack')
    sec_addr_len = struct.unpack_from('<H', body, 8)[0]
    offset = 10 + sec_addr_len
    offset += (-offset) % 4
    if len(body) < offset + 4:
        raise ProbeError('truncated MSRPC bind_ack result list')
    n_results = body[offset]
    offset += 4
    if n_results < 1 or len(body) < offset + 24:
        raise ProbeError('MSRPC bind_ack carried no presentation results')
    result = struct.unpack_from('<H', body, offset)[0]
    return result == 0


def msrpc_emp(host: str, *, port: int = DEFAULT_PORT, timeout: float = DEFAULT_TIMEOUT) -> EmpResult:
    port = validate_port(port)
    timeout = validate_timeout(timeout)
    address = resolve_host(host)

    try:
        with socket.create_connection((str(address), port), timeout=timeout) as sock:
            sock.sendall(_build_bind(1))
            ptype, body = _recv_pdu(sock)
            if ptype == _PTYPE_BIND_NAK:
                reachable = False
            elif ptype == _PTYPE_BIND_ACK:
                reachable = _parse_bind_ack(body)
            else:
                raise ProbeError(f'unexpected MSRPC PDU type {ptype} replying to bind')
    except OSError as exc:
        raise ProbeError(f'MSRPC endpoint mapper probe to {address}:{port} failed: {exc}') from exc

    result = EmpResult(host, port, reachable)
    logger.data('msrpc_emp %s -> %s', host, result.to_dict())
    return result
