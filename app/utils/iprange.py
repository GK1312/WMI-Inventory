import ipaddress


def _parse_ipv4(value: str, label: str) -> ipaddress.IPv4Address:
    if not isinstance(value, str):
        raise TypeError(f"{label} address must be a string, got {type(value).__name__}")

    cleaned = value.replace(' ', '').strip()
    if not cleaned:
        raise ValueError(f"{label} address is empty")

    try:
        return ipaddress.IPv4Address(cleaned)
    except ipaddress.AddressValueError as exc:
        raise ValueError(f"{label} address {value!r} is not a valid IPv4 address") from exc


def expand_ranges(start: str, end: str) -> list[ipaddress.IPv4Network]:
    start_ip = _parse_ipv4(start, 'Start')
    end_ip = _parse_ipv4(end, 'End')

    if start_ip > end_ip:
        raise ValueError(f"Start address {start_ip} is greater than end address {end_ip}")

    return list(ipaddress.summarize_address_range(start_ip, end_ip))


def expand_hosts(networks: list[ipaddress.IPv4Network]) -> list[ipaddress.IPv4Address]:
    addresses = []
    for network in networks:
        addresses.extend(network)
    return addresses
