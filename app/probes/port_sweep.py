from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from enum import Enum
from typing import Any

from core.errors import ProbeError, ValidationError
from core.logging import get_logger
from probes.tcp_ping import (
    DEFAULT_TIMEOUT,
    PortState,
    TcpPingResult,
    connect_probe,
    resolve_host,
    syn_probe,
    validate_port,
    validate_timeout,
)

logger = get_logger(__name__)

TCP_PORTS: tuple[int, ...] = (
    22, 23, 80, 88, 111, 135, 139, 389, 443, 445, 548, 554, 631, 636, 902,
    3000, 3001, 3389, 5060, 5061, 5900, 5985, 5986, 8001, 8002, 8008, 8009,
    8060, 8080, 9100, 16992, 16993,
)
ICS_TCP_PORTS: tuple[int, ...] = (102, 502, 20000, 44818)
UDP_PORTS: tuple[int, ...] = (
    88, 111, 123, 137, 161, 389, 623, 1900, 3283, 3702, 5353, 5355, 47808,
)

_RETRY_TIMEOUT_FACTOR = 0.5
_ANSWERED = (PortState.OPEN, PortState.CLOSED)


class ProbeMethod(str, Enum):
    SYN = 'syn'
    CONNECT = 'connect'


@dataclass(frozen=True)
class PortStatus:
    port: int
    protocol: str
    state: PortState
    latency_ms: float | None = None
    ttl: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            'port': self.port,
            'protocol': self.protocol,
            'state': self.state.value,
            'latency_ms': self.latency_ms,
            'ttl': self.ttl,
        }


@dataclass(frozen=True)
class SweepResult:
    host: str
    src_ip: str | None
    ttl: int | None
    method: ProbeMethod
    ports: list[PortStatus]

    @property
    def reachable(self) -> bool:
        return any(p.state in _ANSWERED for p in self.ports)

    @property
    def latency_ms(self) -> float | None:
        values = [p.latency_ms for p in self.ports if p.state in _ANSWERED and p.latency_ms is not None]
        return min(values) if values else None

    @property
    def ttl_consistent(self) -> bool | None:
        ttls = {p.ttl for p in self.ports if p.ttl is not None}
        return len(ttls) == 1 if ttls else None

    def ports_in(self, state: PortState) -> list[int]:
        return [p.port for p in self.ports if p.state is state]

    def to_dict(self, detail: bool = False) -> dict[str, Any]:
        grouped = {state.value: self.ports_in(state) for state in PortState}
        if not detail:
            return {'ports': grouped}
        return {
            'host': self.host,
            'reachable': self.reachable,
            'method': self.method.value,
            'src_ip': self.src_ip,
            'ttl': self.ttl,
            'ttl_consistent': self.ttl_consistent,
            'latency_ms': self.latency_ms,
            'ports': grouped,
            'details': [p.to_dict() for p in self.ports],
        }


def _normalize_ports(ports: tuple[int, ...]) -> tuple[int, ...]:
    normalized = tuple(dict.fromkeys(validate_port(port) for port in ports))
    if not normalized:
        raise ValidationError('ports must not be empty', field='ports')
    return normalized


def _merge_methods(*methods: ProbeMethod) -> ProbeMethod:
    return ProbeMethod.SYN if all(method is ProbeMethod.SYN for method in methods) else ProbeMethod.CONNECT


def _probe_tcp(
    host: str, address: ipaddress.IPv4Address | ipaddress.IPv6Address, ports: tuple[int, ...],
    timeout: float, allow_fallback: bool,
) -> tuple[list[TcpPingResult], ProbeMethod]:
    try:
        return syn_probe(host, address, ports, timeout, early_stop=False), ProbeMethod.SYN
    except ProbeError as exc:
        if not allow_fallback:
            raise
        logger.debug('port_sweep SYN probe unavailable, using connect fallback: %s', exc)
        return connect_probe(host, address, ports, timeout, early_stop=False, strict=False), ProbeMethod.CONNECT


def _sweep_tcp(
    host: str, address: ipaddress.IPv4Address | ipaddress.IPv6Address, ports: tuple[int, ...],
    timeout: float, allow_fallback: bool,
) -> tuple[list[TcpPingResult], ProbeMethod]:
    probed, method = _probe_tcp(host, address, ports, timeout, allow_fallback)
    results = {r.port: r for r in probed}
    filtered = tuple(port for port, r in results.items() if r.state is PortState.FILTERED)
    if filtered and any(r.reachable for r in results.values()):
        retried, retry_method = _probe_tcp(host, address, filtered, timeout * _RETRY_TIMEOUT_FACTOR, allow_fallback)
        results.update({r.port: r for r in retried})
        method = _merge_methods(method, retry_method)
    return [results[port] for port in ports], method


def _sweep_ics(
    host: str, address: ipaddress.IPv4Address | ipaddress.IPv6Address, ports: tuple[int, ...],
    timeout: float, allow_fallback: bool,
) -> tuple[list[TcpPingResult], ProbeMethod]:
    out: list[TcpPingResult] = []
    methods: list[ProbeMethod] = []
    for port in ports:
        results, method = _sweep_tcp(host, address, (port,), timeout, allow_fallback)
        out.extend(results)
        methods.append(method)
    return out, _merge_methods(*methods)


def _host_meta(results: list[TcpPingResult]) -> tuple[str | None, int | None]:
    for state in (PortState.OPEN, PortState.CLOSED):
        for r in results:
            if r.state is state and r.ttl is not None:
                return r.src_ip, r.ttl
    return None, None


def port_sweep(
    host: str, *, timeout: float = DEFAULT_TIMEOUT, include_ics: bool = False,
    ports: tuple[int, ...] | None = None, allow_fallback: bool = True,
) -> SweepResult:
    timeout = validate_timeout(timeout)
    address = resolve_host(host)

    tcp_ports = TCP_PORTS if ports is None else _normalize_ports(ports)
    ics_ports = tuple(port for port in ICS_TCP_PORTS if port not in tcp_ports) if include_ics else ()

    tcp_results, method = _sweep_tcp(host, address, tcp_ports, timeout, allow_fallback)
    if ics_ports:
        ics_results, ics_method = _sweep_ics(host, address, ics_ports, timeout, allow_fallback)
        tcp_results += ics_results
        method = _merge_methods(method, ics_method)

    src_ip, ttl = _host_meta(tcp_results)
    statuses = sorted(
        (PortStatus(r.port, 'tcp', r.state, r.latency_ms, r.ttl) for r in tcp_results),
        key=lambda s: (s.protocol, s.port),
    )
    unknown = [s.port for s in statuses if s.state is PortState.UNKNOWN]
    if unknown:
        logger.warning('port_sweep %s: unexpected connect errors on ports %s', host, unknown)

    result = SweepResult(host, src_ip, ttl, method, statuses)
    logger.data('port_sweep %s -> %s', host, result.to_dict(detail=True))
    return result
