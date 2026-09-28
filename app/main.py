import argparse
import json
import sys

from utils.iprange import expand_hosts, expand_ranges


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='Expand an inclusive IPv4 range into the CIDR networks that cover it.'
    )
    parser.add_argument('start', nargs='?', help='first IPv4 address in the range, e.g. 192.168.1.1')
    parser.add_argument('end', nargs='?', help='last IPv4 address in the range, e.g. 192.168.1.254')
    parser.add_argument('--hosts', action='store_true', help='print individual IP addresses instead of CIDR networks')
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    try:
        if args.start is None:
            args.start = input('Start IP: ')
        if args.end is None:
            args.end = input('End IP: ')
    except (EOFError, KeyboardInterrupt):
        print(file=sys.stderr)
        return 1

    try:
        networks = expand_ranges(args.start, args.end)
    except (ValueError, TypeError) as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 1

    total = sum(net.num_addresses for net in networks)
    if args.hosts:
        print(json.dumps([str(ip) for ip in expand_hosts(networks)]))
    else:
        print(json.dumps([str(net) for net in networks]))
    print(f'{len(networks)} network(s), {total} address(es)', file=sys.stderr)
    return 0


if __name__ == '__main__':
    sys.exit(main())
