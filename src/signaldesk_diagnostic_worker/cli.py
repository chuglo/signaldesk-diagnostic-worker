from __future__ import annotations

import argparse
from collections.abc import Callable, Sequence
from signal import SIGINT, SIGTERM, getsignal, signal
from threading import Event
from types import FrameType
from typing import Any

import redis

from signaldesk_diagnostic_worker.consumer import DiagnosticConsumer
from signaldesk_diagnostic_worker.control_client import ControlApiClient
from signaldesk_diagnostic_worker.probe import DiagnosticRunner
from signaldesk_diagnostic_worker.settings import Settings


def make_stop_handler(stop_event: Event) -> Callable[[int, FrameType | None], None]:
    def stop(_signum: int, _frame: FrameType | None) -> None:
        stop_event.set()

    return stop


def create_consumer(settings: Settings, stop_event: Event) -> DiagnosticConsumer:
    redis_client = redis.Redis.from_url(
        settings.redis_url.get_secret_value(),
        decode_responses=False,
        socket_connect_timeout=settings.redis_connect_timeout_seconds,
        socket_timeout=settings.redis_socket_timeout_seconds,
        health_check_interval=30,
    )
    control = ControlApiClient(
        base_url=str(settings.control_api_base_url),
        credential=settings.diagnostic_worker_service_credential.get_secret_value(),
        timeout=settings.api_timeout_seconds,
        max_response_bytes=settings.api_max_response_bytes,
    )
    runner = DiagnosticRunner(
        dns_nameserver=str(settings.dns_nameserver),
        connect_timeout=settings.diagnostic_connect_timeout_seconds,
        read_timeout=settings.diagnostic_read_timeout_seconds,
        total_timeout=settings.diagnostic_total_timeout_seconds,
        max_header_bytes=settings.diagnostic_max_header_bytes,
    )
    return DiagnosticConsumer(
        settings=settings,
        redis_client=redis_client,
        control_client=control,
        runner=runner,
        stop_event=stop_event,
    )


def run_worker(
    settings: Settings,
    *,
    once: bool = False,
    stop_event: Event | None = None,
) -> None:
    stop = stop_event or Event()
    consumer = create_consumer(settings, stop)
    try:
        if once:
            consumer.setup()
            consumer.process_once()
        else:
            consumer.run()
    finally:
        control: Any = getattr(consumer, "control", None)
        broker: Any = getattr(consumer, "redis", None)
        if control is not None and hasattr(control, "close"):
            control.close()
        if broker is not None and hasattr(broker, "close"):
            broker.close()


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Run the SignalDesk diagnostic worker")
    parser.add_argument(
        "--once",
        action="store_true",
        help="process at most one bounded reclaimed/new batch and exit",
    )
    arguments = parser.parse_args(argv)
    stop_event = Event()
    handler = make_stop_handler(stop_event)
    previous = {SIGTERM: getsignal(SIGTERM), SIGINT: getsignal(SIGINT)}
    signal(SIGTERM, handler)
    signal(SIGINT, handler)
    try:
        run_worker(Settings(), once=arguments.once, stop_event=stop_event)  # type: ignore[call-arg]
    finally:
        signal(SIGTERM, previous[SIGTERM])
        signal(SIGINT, previous[SIGINT])


if __name__ == "__main__":
    main()
