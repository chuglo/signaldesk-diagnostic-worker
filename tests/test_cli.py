from __future__ import annotations

from threading import Event

import pytest

from signaldesk_diagnostic_worker import cli


class FakeConsumer:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def setup(self) -> None:
        self.calls.append("setup")

    def process_once(self) -> int:
        self.calls.append("process_once")
        return 0

    def run(self) -> None:
        self.calls.append("run")


def test_run_worker_once_sets_up_and_processes_one_bounded_batch(monkeypatch: pytest.MonkeyPatch) -> None:
    consumer = FakeConsumer()
    monkeypatch.setattr(cli, "create_consumer", lambda _settings, _stop: consumer)

    cli.run_worker(object(), once=True, stop_event=Event())  # type: ignore[arg-type]

    assert consumer.calls == ["setup", "process_once"]


def test_run_worker_loop_delegates_to_gracefully_stoppable_consumer(monkeypatch: pytest.MonkeyPatch) -> None:
    consumer = FakeConsumer()
    stop = Event()
    monkeypatch.setattr(cli, "create_consumer", lambda _settings, received: consumer if received is stop else None)

    cli.run_worker(object(), once=False, stop_event=stop)  # type: ignore[arg-type]

    assert consumer.calls == ["run"]


def test_signal_handler_only_sets_stop_event() -> None:
    stop = Event()
    handler = cli.make_stop_handler(stop)

    handler(15, None)

    assert stop.is_set()


def test_create_consumer_wires_absolute_diagnostic_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}
    settings = cli.Settings(
        redis_url="redis://localhost:6379/0",
        control_api_base_url="https://control.example.test",
        diagnostic_worker_service_credential="d" * 32,
        consumer_name="worker-deadline",
        dns_nameserver="127.0.0.11",
        diagnostic_total_timeout_seconds=7.5,
    )
    monkeypatch.setattr(cli.redis.Redis, "from_url", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(cli, "ControlApiClient", lambda **_kwargs: object())

    class CapturingRunner:
        def __init__(self, **kwargs: object) -> None:
            captured.update(kwargs)

    monkeypatch.setattr(cli, "DiagnosticRunner", CapturingRunner)

    cli.create_consumer(settings, Event())

    assert captured["total_timeout"] == 7.5
    assert captured["dns_nameserver"] == "127.0.0.11"


def test_create_consumer_unwraps_redis_secret_only_for_from_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}
    settings = cli.Settings(
        redis_url="redis://localhost:6379/7",
        control_api_base_url="https://control.example.test",
        diagnostic_worker_service_credential="d" * 32,
        consumer_name="worker-redis-secret",
        dns_nameserver="1.1.1.1",
    )

    def from_url(url: str, **kwargs: object) -> object:
        captured["url"] = url
        captured["redis_kwargs"] = kwargs
        return object()

    monkeypatch.setattr(cli.redis.Redis, "from_url", from_url)
    monkeypatch.setattr(cli, "ControlApiClient", lambda **_kwargs: object())
    monkeypatch.setattr(cli, "DiagnosticRunner", lambda **_kwargs: object())

    cli.create_consumer(settings, Event())

    assert captured["url"] == "redis://localhost:6379/7"
