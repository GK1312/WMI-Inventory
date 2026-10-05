import argparse
import json
import logging
import sys
from dataclasses import replace
from typing import Any

import uvicorn

from api.app import create_app
from config import settings
from core.errors import AppError, ValidationError
from core.logging import get_logger, setup_logging

logger = get_logger(__name__)


def run_api(args: argparse.Namespace) -> int:
    uvicorn.run(
        create_app(settings),
        host=settings.api_host,
        port=settings.api_port,
        server_header=False,
        date_header=False,
        log_config=None,
        proxy_headers=True,
        forwarded_allow_ips='127.0.0.1',
    )
    return 0


def run_tcp_ping(args: argparse.Namespace) -> int:
    from probes.tcp_ping import tcp_ping

    try:
        result = tcp_ping(args.host, args.port, args.timeout, allow_fallback=not args.no_fallback)
    except ValidationError as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 2
    except AppError as exc:
        logger.error('tcp_ping %s port %s failed: %s', args.host, args.port or 'defaults', exc)
        print(f'error: {exc}', file=sys.stderr)
        return 1
    print(json.dumps(result.to_dict(), indent=2))
    return 0 if result.reachable else 3


def _parse_ports(value: str | None) -> tuple[int, ...] | None:
    if not value:
        return None
    try:
        return tuple(int(item) for item in value.split(',') if item.strip())
    except ValueError as exc:
        raise ValidationError(f'invalid --ports value {value!r}: {exc}', field='ports') from exc


def _is_inline(value: Any) -> bool:
    items = value.values() if isinstance(value, dict) else value
    return not any(isinstance(item, (dict, list)) for item in items)


def _format_json(value: Any, level: int = 0) -> str:
    if not isinstance(value, (dict, list)) or not value or _is_inline(value):
        return json.dumps(value)
    indent = '  ' * (level + 1)
    close = '  ' * level
    if isinstance(value, dict):
        body = ',\n'.join(f'{indent}{json.dumps(key)}: {_format_json(item, level + 1)}' for key, item in value.items())
        return '{\n' + body + '\n' + close + '}'
    body = ',\n'.join(indent + _format_json(item, level + 1) for item in value)
    return '[\n' + body + '\n' + close + ']'


def run_port_sweep(args: argparse.Namespace) -> int:
    from probes.port_sweep import port_sweep

    try:
        result = port_sweep(
            args.host, timeout=args.timeout, include_ics=args.include_ics,
            ports=_parse_ports(args.ports), allow_fallback=not args.no_fallback,
        )
    except ValidationError as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 2
    except AppError as exc:
        logger.error('port_sweep %s failed: %s', args.host, exc)
        print(f'error: {exc}', file=sys.stderr)
        return 1
    print(_format_json(result.to_dict(detail=args.detail)))
    return 0 if result.reachable else 3


def run_msrpc_emp(args: argparse.Namespace) -> int:
    from probes.msrpc_emp import msrpc_emp

    try:
        result = msrpc_emp(args.host, port=args.port, timeout=args.timeout)
    except ValidationError as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 2
    except AppError as exc:
        logger.error('msrpc_emp %s failed: %s', args.host, exc)
        print(f'error: {exc}', file=sys.stderr)
        return 1
    print(_format_json(result.to_dict()))
    return 0 if result.reachable else 3


def run_smb_ntlm(args: argparse.Namespace) -> int:
    from probes.smb_ntlm import smb_ntlm

    try:
        result = smb_ntlm(args.host, port=args.port, timeout=args.timeout)
    except ValidationError as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 2
    except AppError as exc:
        logger.error('smb_ntlm %s failed: %s', args.host, exc)
        print(f'error: {exc}', file=sys.stderr)
        return 1
    print(_format_json(result.to_dict()))
    return 0 if result.reachable else 3


_VERBOSE_HELP = 'also print log lines (LOG_LEVEL from .env) and library notices'


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog='main.py')
    subparsers = parser.add_subparsers(dest='command')

    api = subparsers.add_parser('api', help='run the HTTP API (default)')
    api.set_defaults(handler=run_api)

    ping = subparsers.add_parser('tcp-ping', help='probe a TCP port on a host')
    ping.add_argument('host')
    ping.add_argument('port', type=int, nargs='?', help='omit to try the default ports (135, 445, 3389, 22, 80, 443)')
    ping.add_argument('--timeout', type=float, default=2.0)
    ping.add_argument('--no-fallback', action='store_true', help='fail instead of falling back to a connect probe')
    ping.add_argument('-v', '--verbose', action='store_true', help=_VERBOSE_HELP)
    ping.set_defaults(handler=run_tcp_ping)

    sweep = subparsers.add_parser('port-sweep', help='sweep the known TCP ports on a host')
    sweep.add_argument('host')
    sweep.add_argument('--timeout', type=float, default=2.0)
    sweep.add_argument('--ports', help='comma-separated TCP ports to sweep instead of the defaults')
    sweep.add_argument('--include-ics', action='store_true', help='also probe ICS ports (102, 502, 20000, 44818), one at a time')
    sweep.add_argument('--detail', action='store_true', help='also print host details (TTL, method, latency) and a row per port')
    sweep.add_argument('--no-fallback', action='store_true', help='fail instead of falling back to a connect probe')
    sweep.add_argument('-v', '--verbose', action='store_true', help=_VERBOSE_HELP)
    sweep.set_defaults(handler=run_port_sweep)

    emp = subparsers.add_parser('msrpc-emp', help='enumerate registered endpoints via the MSRPC endpoint mapper (port 135)')
    emp.add_argument('host')
    emp.add_argument('--port', type=int, default=135)
    emp.add_argument('--timeout', type=float, default=2.0)
    emp.add_argument('-v', '--verbose', action='store_true', help=_VERBOSE_HELP)
    emp.set_defaults(handler=run_msrpc_emp)

    smb = subparsers.add_parser('smb-ntlm', help='read the NTLM Type-2 challenge from an SMB session setup (port 445)')
    smb.add_argument('host')
    smb.add_argument('--port', type=int, default=445)
    smb.add_argument('--timeout', type=float, default=2.0)
    smb.add_argument('-v', '--verbose', action='store_true', help=_VERBOSE_HELP)
    smb.set_defaults(handler=run_smb_ntlm)

    parser.set_defaults(handler=run_api)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    quiet = not getattr(args, 'verbose', True)
    setup_logging(replace(settings, log_level='WARNING') if quiet else settings)
    if quiet:
        logging.getLogger('scapy.loading').setLevel(logging.ERROR)
    return args.handler(args)


if __name__ == '__main__':
    sys.exit(main())
