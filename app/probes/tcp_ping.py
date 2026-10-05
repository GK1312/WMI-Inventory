from __future__ import annotations

import errno
import ipaddress
import os
import selectors
import socket
import struct
import time
from dataclasses import asdict, dataclass, replace
from enum import Enum
from typing import Any

from scapy.config import conf
from scapy.consts import WINDOWS
from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6
from scapy.sendrecv import sr

from core.errors import ProbeError, ValidationError
from core.logging import get_logger

logger = get_logger(__name__)

DEFAULT_TIMEOUT = 2.0
DEFAULT_PORTS: tuple[int, ...] = (135, 445, 3389, 22, 80, 443)
MAX_TIMEOUT = 30.0

_SYN_ACK = 0x12
_RST = 0x04

_TCP_NOSYNRETRIES = 9
_RCVALL_IPLEVEL = 3
_CAPTURE_GRACE = 0.1
_CAPTURE_BUFFER = 4 * 1024 * 1024

_WSAEADDRNOTAVAIL = 10049

_REFUSED_ERRNOS = {errno.ECONNREFUSED}
_FILTERED_ERRNOS = {
    errno.EHOSTUNREACH, errno.ENETUNREACH, errno.ETIMEDOUT, errno.ENETDOWN, errno.EHOSTDOWN,
    errno.EACCES, errno.EPERM, _WSAEADDRNOTAVAIL,
}
_IN_PROGRESS_ERRNOS = {errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EAGAIN}
_LIMITED_BROADCAST = ipaddress.IPv4Address('255.255.255.255')


class PortState(str, Enum):
    OPEN = 'open'
    CLOSED = 'closed'
    FILTERED = 'filtered'


@dataclass(frozen=True)
class TcpPingResult:
    host: str
    port: int
    state: PortState
    reachable: bool
    latency_ms: float | None = None
    ttl: int | None = None
    src_ip: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data['state'] = self.state.value
        return data


_STATE_PREFERENCE = (PortState.OPEN, PortState.CLOSED, PortState.FILTERED)


def _validate_port(port: int) -> int:
    if isinstance(port, bool) or not isinstance(port, int):
        raise ValidationError(f'port must be an int, got {type(port).__name__}', field='port')
    if not 1 <= port <= 65535:
        raise ValidationError(f'port {port} is out of range 1-65535', field='port')
    return port


def _validate_timeout(timeout: float) -> float:
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise ValidationError(f'timeout must be a number, got {type(timeout).__name__}', field='timeout')
    if not 0 < timeout <= MAX_TIMEOUT:
        raise ValidationError(f'timeout {timeout} must be > 0 and <= {MAX_TIMEOUT}', field='timeout')
    return float(timeout)


def _check_target(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if address.is_unspecified or address.is_multicast or address == _LIMITED_BROADCAST:
        raise ValidationError(f'{address} is not a unicast host address', field='host')
    return address


def _resolve(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if not isinstance(host, str) or not host.strip():
        raise ValidationError('host must be a non-empty string', field='host')
    host = host.strip()
    try:
        return _check_target(ipaddress.ip_address(host))
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError) as exc:
        raise ValidationError(f'host {host!r} could not be resolved: {exc}', field='host') from exc
    families = {info[0]: info[4][0] for info in reversed(infos)}
    address = families.get(socket.AF_INET) or families.get(socket.AF_INET6)
    if address is None:
        raise ValidationError(f'host {host!r} has no IPv4 or IPv6 address', field='host')
    return _check_target(ipaddress.ip_address(address.split('%', 1)[0]))


def _validate_ports(port: int | None) -> tuple[int, ...]:
    if port is None:
        return DEFAULT_PORTS
    return (_validate_port(port),)


def _build_packet(address: ipaddress.IPv4Address | ipaddress.IPv6Address, ports: tuple[int, ...]):
    network_layer = IP(dst=str(address)) if address.version == 4 else IPv6(dst=str(address))
    return network_layer / TCP(dport=list(ports), flags='S')


def _check_capability() -> None:
    if WINDOWS and not conf.use_pcap:
        raise ProbeError('Npcap is required for TCP SYN probes on Windows (raw sockets cannot send TCP)')


def _is_syn_ack_from(address: str, ports: tuple[int, ...]):
    def stop(packet) -> bool:
        ip_layer = packet.getlayer(IP) or packet.getlayer(IPv6)
        tcp_layer = packet.getlayer(TCP)
        return (
            ip_layer is not None
            and tcp_layer is not None
            and ip_layer.src == address
            and tcp_layer.sport in ports
            and int(tcp_layer.flags) & _SYN_ACK == _SYN_ACK
        )
    return stop


def _send(packet, address: str, ports: tuple[int, ...], timeout: float):
    _check_capability()
    try:
        answered, _ = sr(
            packet, timeout=timeout, verbose=0, chainEX=True, promisc=False,
            stop_filter=_is_syn_ack_from(address, ports),
        )
    except PermissionError as exc:
        raise ProbeError('raw socket access denied; run with administrator/root privileges') from exc
    except (OSError, RuntimeError) as exc:
        raise ProbeError(f'packet send failed (is Npcap/libpcap installed?): {exc}') from exc
    return answered


def _classify(host: str, port: int, sent, reply) -> TcpPingResult:
    ip_layer = reply.getlayer(IP) or reply.getlayer(IPv6)
    flags = int(reply.getlayer(TCP).flags)
    if flags & _SYN_ACK == _SYN_ACK:
        state = PortState.OPEN
    elif flags & _RST:
        state = PortState.CLOSED
    else:
        state = PortState.FILTERED
    return TcpPingResult(
        host, port, state, state is not PortState.FILTERED,
        latency_ms=round((reply.time - sent.sent_time) * 1000, 2),
        ttl=ip_layer.ttl if isinstance(ip_layer, IP) else ip_layer.hlim,
        src_ip=ip_layer.src,
    )


def _is_tcp_reply(reply) -> bool:
    return reply.haslayer(TCP) and (reply.haslayer(IP) or reply.haslayer(IPv6))


def _syn_probe(
    host: str, address: ipaddress.IPv4Address | ipaddress.IPv6Address, ports: tuple[int, ...], timeout: float
) -> list[TcpPingResult]:
    answered = _send(_build_packet(address, ports), str(address), ports, timeout)
    by_port = {
        int(sent[TCP].dport): _classify(host, int(sent[TCP].dport), sent, reply)
        for sent, reply in answered
        if _is_tcp_reply(reply)
    }
    return [
        by_port.get(port) or TcpPingResult(host, port, PortState.FILTERED, False)
        for port in ports
    ]


def _disable_syn_retries(sock: socket.socket) -> None:
    try:
        sock.setsockopt(socket.IPPROTO_TCP, _TCP_NOSYNRETRIES, 1)
    except OSError:
        pass


def _error_text(err: int) -> str:
    return getattr(socket, 'errorTab', {}).get(err) or os.strerror(err)


def _connect_result(
    host: str, address: ipaddress.IPv4Address | ipaddress.IPv6Address, port: int, err: int, start: float
) -> TcpPingResult:
    if err == 0:
        state = PortState.OPEN
    elif err in _REFUSED_ERRNOS:
        state = PortState.CLOSED
    elif err in _FILTERED_ERRNOS:
        state = PortState.FILTERED
    else:
        raise ProbeError(f'connect to {address}:{port} failed: {_error_text(err)} (errno {err})')
    reachable = state in (PortState.OPEN, PortState.CLOSED)
    latency_ms = round((time.perf_counter() - start) * 1000, 2) if reachable else None
    return TcpPingResult(host, port, state, reachable, latency_ms=latency_ms)


def _local_ip_for(address: ipaddress.IPv4Address) -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.connect((str(address), 9))
        return probe.getsockname()[0]


class _ReplyCapture:
    def __init__(self, sock: socket.socket, local_ip: str, address: str) -> None:
        self.sock = sock
        self.local_ip = local_ip
        self.address = address
        self.ttls: dict[int, int] = {}

    @classmethod
    def open(cls, address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> _ReplyCapture | None:
        if not WINDOWS or address.version != 4 or address.is_loopback:
            return None
        sock = None
        try:
            local_ip = _local_ip_for(address)
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, _CAPTURE_BUFFER)
            sock.bind((local_ip, 0))
            sock.ioctl(socket.SIO_RCVALL, _RCVALL_IPLEVEL)
            sock.setblocking(False)
        except OSError as exc:
            if sock is not None:
                sock.close()
            logger.debug('tcp_ping reply capture unavailable (needs administrator): %s', exc)
            return None
        return cls(sock, local_ip, str(address))

    def drain(self, local_ports: dict[int, int]) -> None:
        while True:
            try:
                data = self.sock.recv(65535)
            except (BlockingIOError, InterruptedError):
                return
            self._record(data, local_ports)

    def _record(self, data: bytes, local_ports: dict[int, int]) -> None:
        if len(data) < 20 or data[0] >> 4 != 4 or data[9] != socket.IPPROTO_TCP:
            return
        ihl = (data[0] & 0x0F) * 4
        if len(data) < ihl + 14 or socket.inet_ntoa(data[12:16]) != self.address:
            return
        src_port, dst_port = struct.unpack('!HH', data[ihl:ihl + 4])
        port = local_ports.get(dst_port)
        if port != src_port or port in self.ttls:
            return
        flags = data[ihl + 13]
        if flags & _SYN_ACK == _SYN_ACK or flags & _RST:
            self.ttls[port] = data[8]

    def wait_for(self, ports: list[int], local_ports: dict[int, int]) -> None:
        deadline = time.perf_counter() + _CAPTURE_GRACE
        with selectors.DefaultSelector() as selector:
            selector.register(self.sock, selectors.EVENT_READ)
            while any(port not in self.ttls for port in ports):
                remaining = deadline - time.perf_counter()
                if remaining <= 0 or not selector.select(remaining):
                    return
                self.drain(local_ports)

    def apply(self, result: TcpPingResult) -> TcpPingResult:
        ttl = self.ttls.get(result.port)
        if ttl is None:
            return result
        return replace(result, ttl=ttl, src_ip=self.address)

    def close(self) -> None:
        try:
            self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        except OSError:
            pass
        self.sock.close()


def _connect_probe(
    host: str, address: ipaddress.IPv4Address | ipaddress.IPv6Address, ports: tuple[int, ...], timeout: float
) -> list[TcpPingResult]:
    family = socket.AF_INET if address.version == 4 else socket.AF_INET6
    results: dict[int, TcpPingResult] = {}
    sockets: list[socket.socket] = []
    local_ports: dict[int, int] = {}
    capture = _ReplyCapture.open(address)
    selector = selectors.DefaultSelector()
    try:
        if capture is not None:
            selector.register(capture.sock, selectors.EVENT_READ, None)
        start = time.perf_counter()
        deadline = start + timeout
        for port in ports:
            sock = socket.socket(family, socket.SOCK_STREAM)
            sockets.append(sock)
            sock.setblocking(False)
            if WINDOWS:
                _disable_syn_retries(sock)
            if capture is not None:
                sock.bind((capture.local_ip, 0))
                local_ports[sock.getsockname()[1]] = port
            err = sock.connect_ex((str(address), port))
            if err in _IN_PROGRESS_ERRNOS:
                selector.register(sock, selectors.EVENT_WRITE, port)
            else:
                results[port] = _connect_result(host, address, port, err, start)

        while len(selector.get_map()) > (capture is not None) and not any(
            r.state is PortState.OPEN for r in results.values()
        ):
            remaining = deadline - time.perf_counter()
            if remaining <= 0:
                break
            for key, _ in selector.select(remaining):
                if key.data is None:
                    capture.drain(local_ports)
                    continue
                selector.unregister(key.fileobj)
                err = key.fileobj.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                results[key.data] = _connect_result(host, address, key.data, err, start)

        if capture is not None:
            capture.drain(local_ports)
            capture.wait_for([port for port, r in results.items() if r.reachable], local_ports)
            results = {port: capture.apply(r) for port, r in results.items()}
    finally:
        selector.close()
        for sock in sockets:
            sock.close()
        if capture is not None:
            capture.close()

    return [
        results.get(port) or TcpPingResult(host, port, PortState.FILTERED, False)
        for port in ports
    ]


def _pick_best(results: list[TcpPingResult]) -> TcpPingResult:
    for state in _STATE_PREFERENCE:
        for result in results:
            if result.state is state:
                return result
    return results[0]


def tcp_ping(
    host: str, port: int | None = None, timeout: float = DEFAULT_TIMEOUT, *, allow_fallback: bool = True
) -> TcpPingResult:
    ports = _validate_ports(port)
    timeout = _validate_timeout(timeout)
    address = _resolve(host)

    try:
        results = _syn_probe(host, address, ports, timeout)
    except ProbeError as exc:
        if not allow_fallback:
            raise
        logger.debug('tcp_ping SYN probe unavailable, using connect fallback: %s', exc)
        results = _connect_probe(host, address, ports, timeout)

    result = _pick_best(results)
    logger.data('tcp_ping %s ports %s -> %s', host, list(ports), result.to_dict())
    return result
