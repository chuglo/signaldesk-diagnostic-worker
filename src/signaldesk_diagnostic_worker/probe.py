from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re
import socket
import ssl
import time
from typing import Callable, Protocol

import dns.exception
import dns.resolver


class TargetError(ValueError):
    """The authoritative target is outside the accepted diagnostic grammar."""


@dataclass(frozen=True)
class ParsedTarget:
    scheme: str
    host: str
    port: int
    request_target: str


_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_STATUS_LINE = re.compile(rb"^HTTP/1\.[01] ([1-5][0-9]{2})(?:[ \r])")
_SCHEME = re.compile(r"^(tcp|https?)://", re.IGNORECASE)
_HEX = frozenset("0123456789abcdefABCDEF")
_UNRESERVED = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)
_SUB_DELIMS = frozenset("!$&'()*+,;=")
_PATH_CHARACTERS = _UNRESERVED | _SUB_DELIMS | frozenset(":@/")
_QUERY_CHARACTERS = _PATH_CHARACTERS | frozenset("?")
_IPV6_TRANSITION_NETWORKS = (
    ipaddress.IPv6Network("::/96"),
    ipaddress.IPv6Network("::ffff:0:0/96"),
    ipaddress.IPv6Network("2002::/16"),
    ipaddress.IPv6Network("2001::/32"),
    ipaddress.IPv6Network("64:ff9b::/96"),
    ipaddress.IPv6Network("64:ff9b:1::/48"),
)


def _valid_uri_component(value: str, allowed: frozenset[str]) -> bool:
    index = 0
    while index < len(value):
        character = value[index]
        if character == "%":
            if (
                index + 2 >= len(value)
                or value[index + 1] not in _HEX
                or value[index + 2] not in _HEX
            ):
                return False
            index += 3
            continue
        if character not in allowed:
            return False
        index += 1
    return True


def parse_target(target: str) -> ParsedTarget:
    if not isinstance(target, str) or not target or len(target) > 2_048:
        raise TargetError("invalid target")
    if (
        not target.isascii()
        or "\\" in target
        or any(ord(character) <= 0x20 or ord(character) == 0x7F for character in target)
    ):
        raise TargetError("invalid target")
    scheme_match = _SCHEME.match(target)
    if scheme_match is None or "#" in target:
        raise TargetError("invalid target")
    scheme = scheme_match.group(1).lower()
    remainder = target[scheme_match.end() :]
    before_query, query_separator, query = remainder.partition("?")
    authority, path_separator, path_tail = before_query.partition("/")
    path = ("/" + path_tail) if path_separator else ""
    if not authority or "@" in authority:
        raise TargetError("invalid target")

    explicit_port = False
    port_text: str | None = None
    if authority.startswith("["):
        closing = authority.find("]")
        if closing <= 1:
            raise TargetError("invalid target")
        host = authority[1:closing]
        suffix = authority[closing + 1 :]
        if suffix:
            if not suffix.startswith(":") or len(suffix) == 1:
                raise TargetError("invalid target")
            explicit_port = True
            port_text = suffix[1:]
        if "[" in host or "]" in host or "%" in host:
            raise TargetError("invalid target")
        try:
            if ipaddress.ip_address(host).version != 6:
                raise TargetError("invalid target")
        except ValueError as error:
            raise TargetError("invalid target") from error
    else:
        if "[" in authority or "]" in authority or authority.count(":") > 1:
            raise TargetError("invalid target")
        if ":" in authority:
            host, port_text = authority.rsplit(":", 1)
            explicit_port = True
            if not port_text:
                raise TargetError("invalid target")
        else:
            host = authority
    if not host or len(host) > 253 or "%" in host:
        raise TargetError("invalid target")
    host = host.lower()
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not all(_HOST_LABEL.fullmatch(label) for label in host.rstrip(".").split(".")):
            raise TargetError("invalid target")
        host = host.rstrip(".")
    if not host:
        raise TargetError("invalid target")

    if explicit_port:
        if port_text is None or not port_text.isdigit():
            raise TargetError("invalid target")
        port = int(port_text, 10)
    else:
        port = 443 if scheme == "https" else 80

    if scheme == "tcp":
        if not explicit_port or path or query_separator:
            raise TargetError("invalid target")
        request_target = ""
    else:
        path = path or "/"
        if not _valid_uri_component(path, _PATH_CHARACTERS) or not _valid_uri_component(
            query, _QUERY_CHARACTERS
        ):
            raise TargetError("invalid target")
        request_target = path + (("?" + query) if query_separator else "")
        if len(request_target.encode("ascii")) > 2_048:
            raise TargetError("invalid target")
    if port < 1 or port > 65_535:
        raise TargetError("invalid target")
    return ParsedTarget(
        scheme=scheme,
        host=host,
        port=port,
        request_target=request_target,
    )


class SocketLike(Protocol):
    def settimeout(self, value: float) -> None: ...
    def sendall(self, data: bytes) -> None: ...
    def recv(self, size: int) -> bytes: ...
    def close(self) -> None: ...


Resolver = Callable[[str, int, float], list[tuple[int, str]]]
Connector = Callable[[int, str, int, float], SocketLike]
TlsWrapper = Callable[[SocketLike, str], SocketLike]
Monotonic = Callable[[], float]


def resolve_host(
    host: str,
    _port: int,
    timeout: float,
    nameserver: str,
) -> list[tuple[int, str]]:
    deadline = time.monotonic() + timeout
    try:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [nameserver]
    except (dns.exception.DNSException, OSError, ValueError) as error:
        if isinstance(error, dns.exception.Timeout) or time.monotonic() >= deadline:
            raise socket.timeout("DNS resolution deadline exceeded") from error
        raise OSError("DNS resolution failed") from error
    if time.monotonic() >= deadline:
        raise socket.timeout("DNS resolution deadline exceeded")

    answers: list[tuple[int, str]] = []
    for record_type, family in (("A", socket.AF_INET), ("AAAA", socket.AF_INET6)):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise socket.timeout("DNS resolution deadline exceeded")
        try:
            records = resolver.resolve(
                host,
                record_type,
                lifetime=remaining,
                search=False,
            )
        except dns.resolver.NXDOMAIN as error:
            if time.monotonic() >= deadline:
                raise socket.timeout("DNS resolution deadline exceeded") from error
            return []
        except dns.resolver.NoAnswer as error:
            if time.monotonic() >= deadline:
                raise socket.timeout("DNS resolution deadline exceeded") from error
            continue
        except dns.exception.Timeout as error:
            raise socket.timeout("DNS resolution deadline exceeded") from error
        except dns.exception.DNSException as error:
            if time.monotonic() >= deadline:
                raise socket.timeout("DNS resolution deadline exceeded") from error
            raise OSError("DNS resolution failed") from error
        except (OSError, ValueError) as error:
            if time.monotonic() >= deadline:
                raise socket.timeout("DNS resolution deadline exceeded") from error
            raise OSError("DNS resolution failed") from error
        try:
            answers.extend((family, record.to_text()) for record in records)
        except (dns.exception.DNSException, OSError, ValueError) as error:
            raise OSError("DNS resolution failed") from error
        if time.monotonic() >= deadline:
            raise socket.timeout("DNS resolution deadline exceeded")
    return answers


def connect_socket(family: int, address: str, port: int, timeout: float) -> SocketLike:
    connected = socket.socket(family, socket.SOCK_STREAM)
    connected.settimeout(timeout)
    try:
        destination: tuple[object, ...]
        if family == socket.AF_INET6:
            destination = (address, port, 0, 0)
        else:
            destination = (address, port)
        connected.connect(destination)
    except Exception:
        connected.close()
        raise
    return connected


def wrap_tls(connected: SocketLike, hostname: str) -> SocketLike:
    context = ssl.create_default_context()
    return context.wrap_socket(connected, server_hostname=hostname)  # type: ignore[arg-type,return-value]


def _safe_address(answers: list[tuple[int, str]]) -> tuple[int, str] | None:
    if not answers:
        return None
    unique: dict[tuple[int, bytes], tuple[int, str]] = {}
    for family, text in answers:
        if family not in {socket.AF_INET, socket.AF_INET6}:
            return None
        try:
            address = ipaddress.ip_address(text)
        except ValueError:
            return None
        if (
            not address.is_global
            or address.is_loopback
            or address.is_private
            or address.is_link_local
            or address.is_multicast
            or address.is_reserved
            or address.is_unspecified
            or (
                isinstance(address, ipaddress.IPv6Address)
                and any(address in network for network in _IPV6_TRANSITION_NETWORKS)
            )
        ):
            raise TargetError("blocked address")
        unique[(0 if address.version == 4 else 1, address.packed)] = (family, str(address))
    return unique[min(unique)] if unique else None


class DiagnosticRunner:
    """Resolve once and enforce one absolute deadline across the whole probe."""

    def __init__(
        self,
        *,
        resolver: Resolver | None = None,
        dns_nameserver: str | None = None,
        connector: Connector = connect_socket,
        tls_wrapper: TlsWrapper = wrap_tls,
        connect_timeout: float = 3.0,
        read_timeout: float = 3.0,
        total_timeout: float = 10.0,
        max_header_bytes: int = 16_384,
        monotonic: Monotonic = time.monotonic,
    ) -> None:
        if connect_timeout <= 0 or read_timeout <= 0 or total_timeout <= 0:
            raise ValueError("probe timeouts must be positive")
        if not 256 <= max_header_bytes <= 65_536:
            raise ValueError("max_header_bytes must be between 256 and 65536")
        if resolver is None:
            if dns_nameserver is None:
                raise ValueError("dns_nameserver is required for the production resolver")
            self._resolver = lambda host, port, timeout: resolve_host(
                host, port, timeout, dns_nameserver
            )
        else:
            self._resolver = resolver
        self._connector = connector
        self._tls_wrapper = tls_wrapper
        self._connect_timeout = connect_timeout
        self._read_timeout = read_timeout
        self._total_timeout = total_timeout
        self._max_header_bytes = max_header_bytes
        self._monotonic = monotonic

    def _remaining(self, deadline: float) -> float:
        return deadline - self._monotonic()

    def run(self, target: str) -> dict[str, str | int]:
        try:
            parsed = parse_target(target)
        except TargetError:
            return {"error_code": "invalid_target", "outcome": "blocked"}
        deadline = self._monotonic() + self._total_timeout
        answers: list[tuple[int, str]]

        try:
            literal = ipaddress.ip_address(parsed.host)
        except ValueError:
            remaining = self._remaining(deadline)
            if remaining <= 0:
                return {"error_code": "resolution_timeout", "outcome": "error"}
            try:
                answers = self._resolver(parsed.host, parsed.port, remaining)
            except (socket.timeout, TimeoutError):
                return {"error_code": "resolution_timeout", "outcome": "error"}
            except (dns.exception.DNSException, OSError, ValueError):
                return {"error_code": "resolution_failed", "outcome": "error"}
            if self._remaining(deadline) <= 0:
                return {"error_code": "resolution_timeout", "outcome": "error"}
        else:
            answers = [
                (
                    int(socket.AF_INET if literal.version == 4 else socket.AF_INET6),
                    str(literal),
                )
            ]

        try:
            answer = _safe_address(answers)
        except TargetError:
            return {"error_code": "blocked_address", "outcome": "blocked"}
        if answer is None:
            return {"error_code": "resolution_failed", "outcome": "error"}
        family, address = answer

        remaining = self._remaining(deadline)
        if remaining <= 0:
            return {"error_code": "connect_timeout", "outcome": "error"}
        try:
            connected = self._connector(
                family,
                address,
                parsed.port,
                min(self._connect_timeout, remaining),
            )
        except (socket.timeout, TimeoutError):
            return {"error_code": "connect_timeout", "outcome": "error"}
        except OSError:
            return {"error_code": "connect_failed", "outcome": "error"}
        if self._remaining(deadline) <= 0:
            connected.close()
            return {"error_code": "connect_timeout", "outcome": "error"}

        active = connected
        if parsed.scheme == "https":
            remaining = self._remaining(deadline)
            if remaining <= 0:
                connected.close()
                return {"error_code": "tls_timeout", "outcome": "error"}
            try:
                connected.settimeout(min(self._connect_timeout, remaining))
                active = self._tls_wrapper(connected, parsed.host)
            except (socket.timeout, TimeoutError):
                connected.close()
                return {"error_code": "tls_timeout", "outcome": "error"}
            except (ssl.SSLError, OSError):
                connected.close()
                return {"error_code": "tls_failed", "outcome": "error"}
            if self._remaining(deadline) <= 0:
                active.close()
                return {"error_code": "tls_timeout", "outcome": "error"}
        try:
            if parsed.scheme == "tcp":
                return {
                    "address_family": "ipv4" if family == socket.AF_INET else "ipv6",
                    "outcome": "reachable",
                    "protocol": "tcp",
                }
            return self._run_http(active, parsed, family, deadline)
        finally:
            active.close()

    def _run_http(
        self,
        connected: SocketLike,
        parsed: ParsedTarget,
        family: int,
        deadline: float,
    ) -> dict[str, str | int]:
        default_port = 443 if parsed.scheme == "https" else 80
        host = f"[{parsed.host}]" if ":" in parsed.host else parsed.host
        if parsed.port != default_port:
            host = f"{host}:{parsed.port}"
        request = (
            f"HEAD {parsed.request_target} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Connection: close\r\n"
            "User-Agent: SignalDesk-Diagnostic/1\r\n\r\n"
        ).encode("ascii")

        remaining = self._remaining(deadline)
        if remaining <= 0:
            return {"error_code": "write_timeout", "outcome": "error"}
        try:
            connected.settimeout(min(self._read_timeout, remaining))
            connected.sendall(request)
        except (socket.timeout, TimeoutError):
            return {"error_code": "write_timeout", "outcome": "error"}
        except OSError:
            return {"error_code": "write_failed", "outcome": "error"}
        if self._remaining(deadline) <= 0:
            return {"error_code": "write_timeout", "outcome": "error"}

        header = bytearray()
        while b"\r\n\r\n" not in header:
            remaining_time = self._remaining(deadline)
            if remaining_time <= 0:
                return {"error_code": "read_timeout", "outcome": "error"}
            remaining_bytes = self._max_header_bytes + 1 - len(header)
            if remaining_bytes <= 0:
                return {"error_code": "header_too_large", "outcome": "error"}
            try:
                connected.settimeout(min(self._read_timeout, remaining_time))
                chunk = connected.recv(min(4_096, remaining_bytes))
            except (socket.timeout, TimeoutError):
                return {"error_code": "read_timeout", "outcome": "error"}
            except OSError:
                return {"error_code": "read_failed", "outcome": "error"}
            if self._remaining(deadline) <= 0:
                return {"error_code": "read_timeout", "outcome": "error"}
            if not chunk:
                return {"error_code": "protocol_error", "outcome": "error"}
            header.extend(chunk)
            marker = header.find(b"\r\n\r\n")
            if marker >= 0:
                if marker + 4 > self._max_header_bytes:
                    return {"error_code": "header_too_large", "outcome": "error"}
                break
            if len(header) > self._max_header_bytes:
                return {"error_code": "header_too_large", "outcome": "error"}
        first_line = bytes(header).split(b"\r\n", 1)[0] + b"\r"
        match = _STATUS_LINE.match(first_line)
        if match is None:
            return {"error_code": "protocol_error", "outcome": "error"}
        return {
            "address_family": "ipv4" if family == socket.AF_INET else "ipv6",
            "http_status": int(match.group(1)),
            "outcome": "reachable",
            "protocol": parsed.scheme,
        }
