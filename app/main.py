import argparse
import json
import sys

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
    ping.set_defaults(handler=run_tcp_ping)

    parser.set_defaults(handler=run_api)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    setup_logging(settings)
    return args.handler(args)


if __name__ == '__main__':
    sys.exit(main())
