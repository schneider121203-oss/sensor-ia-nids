"""Adaptadores puros entre telemetría NFStream y el esquema del modelo."""

from typing import Any


# IANA protocol numbers most commonly observed by the sensor.  UNSW-NB15
# represents these values as lowercase names, not as the numbers returned by
# NFStream.
IP_PROTOCOL_NAMES = {
    1: "icmp",
    2: "igmp",
    6: "tcp",
    17: "udp",
    41: "ipv6",
    47: "gre",
    50: "esp",
    51: "ah",
    58: "ipv6-icmp",
    89: "ospf",
    132: "sctp",
}

PROTOCOL_ALIASES = {
    "icmp6": "ipv6-icmp",
    "icmpv6": "ipv6-icmp",
    "ip6-icmp": "ipv6-icmp",
}


def normalize_protocol(value: Any) -> str:
    """Return the textual protocol representation expected by UNSW-NB15."""
    if value is None:
        return "unknown"

    if isinstance(value, bytes):
        value = value.decode(errors="replace")

    token = str(value).strip().lower()
    if token.isdigit():
        return IP_PROTOCOL_NAMES.get(int(token), token)
    return PROTOCOL_ALIASES.get(token, token)
