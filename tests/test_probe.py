from __future__ import annotations

import socket
from typing import Any

import pytest

from signaldesk_diagnostic_worker import probe
from signaldesk_diagnostic_worker.probe import DiagnosticRunner, TargetError, parse_target


@pytest.mark.parametrize(
    "target",
    [
        "ftp://example.com/file",
        "http://user:pass@example.com/",
        "https://example.com/path#fragment",
        "tcp://example.com",
        "tcp://example.com:0",
        "http://exa mple.com/",
        "http://example.com/a b",
        "http://example.com/a\tb",
        "http://example.com/a\x7fb",
        "http://example.com\\admin",
        "http://example.com/%",
        "http://example.com/%2",
        "http://example.com/%GG",
        "http://example.com:/",
        "http://example.com::80/",
        "http://[2001:db8::1]extra/",
        "http://example.com/" + "x" * 2049,
    ],
)
def test_target_grammar_rejects_unsupported_or_unsafe_targets(target: str) -> None:
    with pytest.raises(TargetError):
        parse_target(target)


def test_target_grammar_applies_http_defaults_and_preserves_bounded_request_target() -> None:
    parsed = parse_target("https://Example.COM/health%2Fready?brief=1&mode=a%20b")

    assert parsed.scheme == "https"
    assert parsed.host == "example.com"
    assert parsed.port == 443
    assert parsed.request_target == "/health%2Fready?brief=1&mode=a%20b"


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.0.0.1",
        "169.254.1.1",
        "224.0.0.1",
        "0.0.0.0",
        "::1",
        "fe80::1",
        "fc00::1",
        "ff02::1",
        "::",
    ],
)
def test_probe_rejects_non_global_ipv4_and_ipv6_without_connecting(address: str) -> None:
    connects: list[object] = []
    runner = DiagnosticRunner(
        resolver=lambda _host, _port, _timeout: [(socket.AF_INET6 if ":" in address else socket.AF_INET, address)],
        connector=lambda *args: connects.append(args),
    )

    result = runner.run("tcp://blocked.example:443")

    assert result == {"error_code": "blocked_address", "outcome": "blocked"}
    assert connects == []


def test_probe_rejects_entire_resolution_when_any_address_is_not_global() -> None:
    connects: list[object] = []
    runner = DiagnosticRunner(
        resolver=lambda _host, _port, _timeout: [
            (socket.AF_INET, "93.184.216.34"),
            (socket.AF_INET, "127.0.0.1"),
        ],
        connector=lambda *args: connects.append(args),
    )

    assert runner.run("tcp://mixed.example:443")["error_code"] == "blocked_address"
    assert connects == []


@pytest.mark.parametrize(
    "address",
    [
        "::ffff:8.8.8.8",
        "2002:0808:0808::1",
        "2001:0000:4136:e378:8000:63bf:3fff:fdd2",
        "64:ff9b::808:808",
        "64:ff9b:1::808:808",
    ],
)
def test_probe_rejects_ipv4_transition_and_nat64_addresses_without_connecting(
    address: str,
) -> None:
    connects: list[object] = []
    runner = DiagnosticRunner(
        resolver=lambda _host, _port, _timeout: [(socket.AF_INET6, address)],
        connector=lambda *args: connects.append(args),
    )

    assert runner.run("tcp://transition.example:443") == {
        "error_code": "blocked_address",
        "outcome": "blocked",
    }
    assert connects == []


class FakeSocket:
    def __init__(self, response: bytes = b"") -> None:
        self.response = response
        self.sent = b""
        self.timeouts: list[float] = []
        self.closed = False

    def settimeout(self, value: float) -> None:
        self.timeouts.append(value)

    def sendall(self, data: bytes) -> None:
        self.sent += data

    def recv(self, size: int) -> bytes:
        if not self.response:
            return b""
        chunk, self.response = self.response[:size], self.response[size:]
        return chunk

    def close(self) -> None:
        self.closed = True


class FakeClock:
    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


def test_tcp_probe_selects_address_deterministically_and_connects_to_ip() -> None:
    calls: list[tuple[Any, ...]] = []
    sock = FakeSocket()
    runner = DiagnosticRunner(
        resolver=lambda _host, _port, _timeout: [
            (socket.AF_INET6, "2606:2800:220:1:248:1893:25c8:1946"),
            (socket.AF_INET, "93.184.216.35"),
            (socket.AF_INET, "93.184.216.34"),
        ],
        connector=lambda family, address, port, timeout: (
            calls.append((family, address, port, timeout)) or sock
        ),
        connect_timeout=1.25,
    )

    result = runner.run("tcp://example.com:443")

    assert calls == [(socket.AF_INET, "93.184.216.34", 443, 1.25)]
    assert result == {"address_family": "ipv4", "outcome": "reachable", "protocol": "tcp"}
    assert sock.closed


def test_direct_ip_literal_skips_dns_resolution() -> None:
    sock = FakeSocket()
    runner = DiagnosticRunner(
        resolver=lambda *_args: (_ for _ in ()).throw(AssertionError("DNS must not run")),
        connector=lambda *_args: sock,
    )

    assert runner.run("tcp://93.184.216.34:443")["outcome"] == "reachable"


def test_dns_resolution_timeout_is_bounded_by_total_deadline() -> None:
    clock = FakeClock()
    connects: list[object] = []

    def resolve(_host: str, _port: int, timeout: float) -> list[tuple[int, str]]:
        assert timeout == pytest.approx(1.0)
        clock.advance(1.01)
        raise socket.timeout("sensitive DNS timeout")

    runner = DiagnosticRunner(
        resolver=resolve,
        connector=lambda *args: connects.append(args),
        total_timeout=1.0,
        monotonic=clock,
    )

    assert runner.run("tcp://dns-timeout.example:443") == {
        "error_code": "resolution_timeout",
        "outcome": "error",
    }
    assert connects == []


def test_default_resolver_fails_closed_when_aaaa_query_times_out(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    configured: list[bool] = []

    class Record:
        def to_text(self) -> str:
            return "93.184.216.34"

    class Resolver:
        def __init__(self, *, configure: bool) -> None:
            configured.append(configure)
            self.nameservers: list[str] = []

        def resolve(
            self,
            _host: str,
            record_type: str,
            *,
            lifetime: float,
            search: bool,
        ) -> list[Record]:
            assert lifetime > 0
            assert search is False
            calls.append(record_type)
            if record_type == "AAAA":
                raise probe.dns.exception.Timeout("sensitive DNS detail")
            return [Record()]

    monkeypatch.setattr(probe.dns.resolver, "Resolver", Resolver)

    with pytest.raises(socket.timeout):
        probe.resolve_host("example.com", 443, 1.0, "127.0.0.11")
    assert configured == [False]
    assert calls == ["A", "AAAA"]


def test_default_resolver_uses_only_explicit_nameserver_and_one_shared_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = FakeClock()
    calls: list[tuple[str, float, bool, list[str]]] = []

    class Record:
        def __init__(self, address: str) -> None:
            self.address = address

        def to_text(self) -> str:
            return self.address

    class Resolver:
        def __init__(self, *, configure: bool) -> None:
            assert configure is False
            self.nameservers: list[str] = []

        def resolve(
            self,
            _host: str,
            record_type: str,
            *,
            lifetime: float,
            search: bool,
        ) -> list[Record]:
            calls.append((record_type, lifetime, search, list(self.nameservers)))
            clock.advance(0.4)
            return [Record("93.184.216.34" if record_type == "A" else "2606:2800:220:1:248:1893:25c8:1946")]

    monkeypatch.setattr(probe.time, "monotonic", clock)
    monkeypatch.setattr(probe.dns.resolver, "Resolver", Resolver)

    answers = probe.resolve_host("example.com", 443, 1.0, "127.0.0.11")

    assert answers == [
        (socket.AF_INET, "93.184.216.34"),
        (socket.AF_INET6, "2606:2800:220:1:248:1893:25c8:1946"),
    ]
    assert calls == [
        ("A", pytest.approx(1.0), False, ["127.0.0.11"]),
        ("AAAA", pytest.approx(0.6), False, ["127.0.0.11"]),
    ]


@pytest.mark.parametrize("failure_point", ["constructor", "assignment"])
def test_default_resolver_setup_dns_errors_are_enumerated_resolution_failures(
    monkeypatch: pytest.MonkeyPatch,
    failure_point: str,
) -> None:
    class Resolver:
        def __init__(self, *, configure: bool) -> None:
            assert configure is False
            if failure_point == "constructor":
                raise probe.dns.resolver.NoResolverConfiguration("sensitive config")

        @property
        def nameservers(self) -> list[str]:
            return []

        @nameservers.setter
        def nameservers(self, _value: list[str]) -> None:
            if failure_point == "assignment":
                raise probe.dns.exception.DNSException("sensitive assignment")

    monkeypatch.setattr(probe.dns.resolver, "Resolver", Resolver)
    runner = DiagnosticRunner(
        dns_nameserver="127.0.0.11",
        connector=lambda *_args: (_ for _ in ()).throw(AssertionError("must not connect")),
    )

    assert runner.run("tcp://example.com:443") == {
        "error_code": "resolution_failed",
        "outcome": "error",
    }


def test_default_resolver_constructor_time_is_inside_resolution_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = FakeClock()

    class Resolver:
        def __init__(self, *, configure: bool) -> None:
            assert configure is False
            clock.advance(1.01)
            self.nameservers: list[str] = []

        def resolve(self, *_args: object, **_kwargs: object) -> list[object]:
            raise AssertionError("query must not start after deadline")

    monkeypatch.setattr(probe.time, "monotonic", clock)
    monkeypatch.setattr(probe.dns.resolver, "Resolver", Resolver)

    with pytest.raises(socket.timeout):
        probe.resolve_host("example.com", 443, 1.0, "127.0.0.11")


@pytest.mark.parametrize(
    "final_exception",
    [probe.dns.resolver.NXDOMAIN(), probe.dns.resolver.NoAnswer()],
)
def test_default_resolver_checks_deadline_after_negative_dns_answer(
    monkeypatch: pytest.MonkeyPatch,
    final_exception: Exception,
) -> None:
    clock = FakeClock()

    class Resolver:
        def __init__(self, *, configure: bool) -> None:
            assert configure is False
            self.nameservers: list[str] = []

        def resolve(
            self,
            _host: str,
            record_type: str,
            **_kwargs: object,
        ) -> list[object]:
            if isinstance(final_exception, probe.dns.resolver.NoAnswer) and record_type == "A":
                return []
            clock.advance(1.01)
            raise final_exception

    monkeypatch.setattr(probe.time, "monotonic", clock)
    monkeypatch.setattr(probe.dns.resolver, "Resolver", Resolver)

    with pytest.raises(socket.timeout):
        probe.resolve_host("example.com", 443, 1.0, "127.0.0.11")


def test_runner_defensively_enumerates_injected_dns_exception() -> None:
    def fail(_host: str, _port: int, _timeout: float) -> list[tuple[int, str]]:
        raise probe.dns.exception.DNSException("sensitive unexpected DNS detail")

    runner = DiagnosticRunner(resolver=fail)

    assert runner.run("tcp://example.com:443") == {
        "error_code": "resolution_failed",
        "outcome": "error",
    }


def test_connect_timeout_is_clamped_to_shared_remaining_deadline() -> None:
    clock = FakeClock()
    sock = FakeSocket()
    timeouts: list[float] = []

    def resolve(_host: str, _port: int, _timeout: float) -> list[tuple[int, str]]:
        clock.advance(0.6)
        return [(socket.AF_INET, "93.184.216.34")]

    def connect(_family: int, _address: str, _port: int, timeout: float) -> FakeSocket:
        timeouts.append(timeout)
        return sock

    runner = DiagnosticRunner(
        resolver=resolve,
        connector=connect,
        connect_timeout=3.0,
        total_timeout=1.0,
        monotonic=clock,
    )

    assert runner.run("tcp://deadline.example:443")["outcome"] == "reachable"
    assert timeouts == [pytest.approx(0.4)]


def test_tls_handshake_cannot_outlive_total_deadline() -> None:
    clock = FakeClock()
    raw = FakeSocket()
    secured = FakeSocket()

    def wrap(_sock: object, _hostname: str) -> FakeSocket:
        clock.advance(1.01)
        return secured

    runner = DiagnosticRunner(
        resolver=lambda _host, _port, _timeout: [(socket.AF_INET, "93.184.216.34")],
        connector=lambda *_args: raw,
        tls_wrapper=wrap,
        total_timeout=1.0,
        monotonic=clock,
    )

    assert runner.run("https://example.com/") == {
        "error_code": "tls_timeout",
        "outcome": "error",
    }
    assert raw.timeouts == [pytest.approx(1.0)]
    assert secured.closed


def test_http_write_cannot_outlive_total_deadline() -> None:
    clock = FakeClock()
    sock = FakeSocket()

    def sendall(data: bytes) -> None:
        sock.sent += data
        clock.advance(1.01)

    sock.sendall = sendall  # type: ignore[method-assign]
    runner = DiagnosticRunner(
        resolver=lambda _host, _port, _timeout: [(socket.AF_INET, "93.184.216.34")],
        connector=lambda *_args: sock,
        total_timeout=1.0,
        monotonic=clock,
    )

    assert runner.run("http://example.com/status") == {
        "error_code": "write_timeout",
        "outcome": "error",
    }
    assert sock.closed


def test_drip_fed_headers_cannot_extend_total_deadline() -> None:
    clock = FakeClock()
    sock = FakeSocket(b"HTTP/1.1 200 OK\r\n\r\n")
    original_recv = sock.recv

    def recv(_size: int) -> bytes:
        clock.advance(0.26)
        return original_recv(1)

    sock.recv = recv  # type: ignore[method-assign]
    runner = DiagnosticRunner(
        resolver=lambda _host, _port, _timeout: [(socket.AF_INET, "93.184.216.34")],
        connector=lambda *_args: sock,
        read_timeout=3.0,
        total_timeout=1.0,
        monotonic=clock,
    )

    assert runner.run("http://example.com/") == {
        "error_code": "read_timeout",
        "outcome": "error",
    }
    assert sock.closed


def test_https_probe_uses_direct_ip_socket_original_sni_and_host_without_second_resolution() -> None:
    resolve_calls: list[tuple[str, int]] = []
    connect_calls: list[tuple[Any, ...]] = []
    tls_calls: list[tuple[object, str]] = []
    raw = FakeSocket()
    secured = FakeSocket(b"HTTP/1.1 204 No Content\r\nServer: fixture\r\n\r\nignored-body")

    def resolve(host: str, port: int, _timeout: float) -> list[tuple[int, str]]:
        resolve_calls.append((host, port))
        return [(socket.AF_INET, "93.184.216.34")]

    def connect(family: int, address: str, port: int, timeout: float) -> FakeSocket:
        connect_calls.append((family, address, port, timeout))
        return raw

    def wrap(sock: object, hostname: str) -> FakeSocket:
        tls_calls.append((sock, hostname))
        return secured

    runner = DiagnosticRunner(
        resolver=resolve,
        connector=connect,
        tls_wrapper=wrap,
        connect_timeout=2.0,
        read_timeout=1.5,
    )
    result = runner.run("https://Example.COM/status?short=1")

    assert resolve_calls == [("example.com", 443)]
    assert connect_calls == [(socket.AF_INET, "93.184.216.34", 443, 2.0)]
    assert tls_calls == [(raw, "example.com")]
    assert secured.sent == (
        b"HEAD /status?short=1 HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"Connection: close\r\n"
        b"User-Agent: SignalDesk-Diagnostic/1\r\n\r\n"
    )
    assert result == {
        "address_family": "ipv4",
        "http_status": 204,
        "outcome": "reachable",
        "protocol": "https",
    }
    assert secured.timeouts == [1.5, 1.5]
    assert secured.closed


def test_http_probe_never_redirects_or_reads_a_body() -> None:
    sock = FakeSocket(b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1/\r\n\r\nSECRET")
    recv_sizes: list[int] = []
    original_recv = sock.recv

    def recv(size: int) -> bytes:
        recv_sizes.append(size)
        return original_recv(size)

    sock.recv = recv  # type: ignore[method-assign]
    runner = DiagnosticRunner(
        resolver=lambda _host, _port, _timeout: [(socket.AF_INET, "93.184.216.34")],
        connector=lambda *_args: sock,
    )

    result = runner.run("http://example.com/")

    assert result["http_status"] == 302
    assert len(recv_sizes) == 1
    assert b"GET " not in sock.sent
    assert b"HEAD / HTTP/1.1" in sock.sent


def test_http_probe_bounds_response_headers() -> None:
    sock = FakeSocket(b"HTTP/1.1 200 OK\r\nX-Fill: " + b"x" * 500)
    runner = DiagnosticRunner(
        resolver=lambda _host, _port, _timeout: [(socket.AF_INET, "93.184.216.34")],
        connector=lambda *_args: sock,
        max_header_bytes=256,
    )

    assert runner.run("http://example.com/") == {
        "error_code": "header_too_large",
        "outcome": "error",
    }


@pytest.mark.parametrize(
    ("raised", "error_code"),
    [
        (socket.timeout("sensitive timeout detail"), "connect_timeout"),
        (ConnectionRefusedError("sensitive refusal detail"), "connect_failed"),
    ],
)
def test_probe_returns_enumerated_connection_errors(raised: Exception, error_code: str) -> None:
    def fail(*_args: object) -> object:
        raise raised

    runner = DiagnosticRunner(
        resolver=lambda _host, _port, _timeout: [(socket.AF_INET, "93.184.216.34")],
        connector=fail,
    )

    result = runner.run("tcp://example.com:443")

    assert result == {"error_code": error_code, "outcome": "error"}
    assert str(raised) not in str(result)
