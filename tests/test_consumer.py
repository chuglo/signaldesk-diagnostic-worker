from __future__ import annotations

from datetime import datetime, timezone
import json
from threading import Event
import time
from uuid import UUID, uuid4

import httpx
import pytest
import redis
from signaldesk_contracts import DiagnosticRequestedV1, EmailRequestedV1

from signaldesk_diagnostic_worker.consumer import DiagnosticConsumer, TopologyError
from signaldesk_diagnostic_worker.control_client import (
    ControlApiClient,
    FatalCredentialError,
)
from signaldesk_diagnostic_worker.settings import Settings


CREDENTIAL = "diagnostic-worker-secret-value-0001"


def make_settings(redis_url: str, consumer: str, **overrides: object) -> Settings:
    values: dict[str, object] = {
        "redis_url": redis_url,
        "control_api_base_url": "https://control.example.test",
        "diagnostic_worker_service_credential": CREDENTIAL,
        "consumer_name": consumer,
        "dns_nameserver": "1.1.1.1",
        "block_time_ms": 10,
        "stale_idle_ms": 1000,
        "api_timeout_seconds": 0.1,
        "diagnostic_total_timeout_seconds": 0.1,
        "max_deliveries": 3,
        "batch_size": 10,
    }
    values.update(overrides)
    return Settings(**values)


def requested_event(
    *,
    job_id: UUID | None = None,
    organization_id: UUID | None = None,
    correlation_id: UUID | None = None,
) -> DiagnosticRequestedV1:
    return DiagnosticRequestedV1(
        schema_version=1,
        event_id=uuid4(),
        event_type="diagnostic.requested.v1",
        occurred_at=datetime.now(timezone.utc),
        correlation_id=correlation_id or uuid4(),
        organization_id=organization_id or uuid4(),
        diagnostic_job_id=job_id or uuid4(),
    )


def add_event(
    client: redis.Redis,
    event: DiagnosticRequestedV1,
    *,
    fields: dict[str, str] | None = None,
) -> bytes:
    envelope = {"event": event.model_dump_json(), "event_id": str(event.event_id)}
    if fields:
        envelope.update(fields)
    return client.xadd("signaldesk:diagnostics", envelope)


def scope_json(event: DiagnosticRequestedV1, target: str, status: str = "claimed") -> dict[str, str]:
    return {
        "diagnostic_job_id": str(event.diagnostic_job_id),
        "organization_id": str(event.organization_id),
        "correlation_id": str(event.correlation_id),
        "target": target,
        "status": status,
    }


def api_client(handler: httpx.MockTransport) -> ControlApiClient:
    return ControlApiClient(
        base_url="https://control.example.test",
        credential=CREDENTIAL,
        timeout=1,
        transport=handler,
    )


class RecordingRunner:
    def __init__(self) -> None:
        self.targets: list[str] = []

    def run(self, target: str) -> dict[str, str | int]:
        self.targets.append(target)
        return {"outcome": "reachable", "protocol": "tcp"}


def test_same_operator_label_gets_distinct_process_ownership_identities(
    redis_client: redis.Redis, redis_url: str
) -> None:
    settings = make_settings(redis_url, "worker-restart")
    control = api_client(httpx.MockTransport(lambda _request: httpx.Response(500)))
    first = DiagnosticConsumer(
        settings=settings,
        redis_client=redis_client,
        control_client=control,
        runner=RecordingRunner(),
    )
    second = DiagnosticConsumer(
        settings=settings,
        redis_client=redis_client,
        control_client=control,
        runner=RecordingRunner(),
    )

    assert first.consumer_identity != second.consumer_identity
    assert first.consumer_identity.startswith("worker-restart:")
    assert second.consumer_identity.startswith("worker-restart:")


def test_group_creation_new_read_and_ack_only_after_completion_acceptance(
    redis_client: redis.Redis, redis_url: str
) -> None:
    event = requested_event()
    add_event(redis_client, event)
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path.endswith("/claim"):
            payload = scope_json(event, "tcp://api-authoritative.example:443")
            payload.pop("status")
            return httpx.Response(200, json=payload)
        return httpx.Response(
            200,
            json={"diagnostic_job_id": str(event.diagnostic_job_id), "status": "completed"},
        )

    runner = RecordingRunner()
    consumer = DiagnosticConsumer(
        settings=make_settings(redis_url, "worker-new"),
        redis_client=redis_client,
        control_client=api_client(httpx.MockTransport(handler)),
        runner=runner,
    )
    consumer.setup()
    assert redis_client.xinfo_groups("signaldesk:diagnostics")[0]["name"] == b"diagnostic-workers"

    assert consumer.process_once() == 1

    assert runner.targets == ["tcp://api-authoritative.example:443"]
    assert redis_client.xpending("signaldesk:diagnostics", "diagnostic-workers")["pending"] == 0
    assert [request.method for request in requests] == ["POST", "POST"]
    assert requests[0].content == b""
    assert json.loads(requests[1].content) == {
        "result": {"outcome": "reachable", "protocol": "tcp"}
    }


def test_worker_uses_only_api_target_and_rejects_forged_queue_scope(
    redis_client: redis.Redis, redis_url: str
) -> None:
    event = requested_event()
    forged = event.model_copy(update={"organization_id": uuid4()})
    add_event(redis_client, forged)
    runner = RecordingRunner()

    def handler(request: httpx.Request) -> httpx.Response:
        payload = scope_json(event, "tcp://api-only.example:443")
        payload.pop("status")
        return httpx.Response(200, json=payload)

    consumer = DiagnosticConsumer(
        settings=make_settings(redis_url, "worker-forged"),
        redis_client=redis_client,
        control_client=api_client(httpx.MockTransport(handler)),
        runner=runner,
    )
    consumer.setup()
    consumer.process_once()

    assert runner.targets == []
    assert redis_client.xlen("signaldesk:diagnostics:dlq") == 1
    dlq = redis_client.xrange("signaldesk:diagnostics:dlq")[0][1]
    assert dlq[b"failure_code"] == b"scope_mismatch"
    assert b"api-only" not in b"".join(dlq.values())


def test_extra_queue_fields_are_terminal_and_never_reach_api(
    redis_client: redis.Redis, redis_url: str
) -> None:
    event = requested_event()
    add_event(redis_client, event, fields={"target": "tcp://forged.example:443", "user": "forged"})
    calls: list[httpx.Request] = []
    consumer = DiagnosticConsumer(
        settings=make_settings(redis_url, "worker-extra"),
        redis_client=redis_client,
        control_client=api_client(httpx.MockTransport(lambda request: calls.append(request) or httpx.Response(500))),
        runner=RecordingRunner(),
    )
    consumer.setup()
    consumer.process_once()

    assert calls == []
    assert redis_client.xpending("signaldesk:diagnostics", "diagnostic-workers")["pending"] == 0
    dlq = redis_client.xrange("signaldesk:diagnostics:dlq")[0][1]
    assert dlq[b"failure_code"] == b"invalid_stream_fields"
    assert b"forged.example" not in b"".join(dlq.values())


@pytest.mark.parametrize("status", [500, 503])
def test_api_5xx_leaves_entry_pending(
    redis_client: redis.Redis, redis_url: str, status: int
) -> None:
    event = requested_event()
    add_event(redis_client, event)
    consumer = DiagnosticConsumer(
        settings=make_settings(redis_url, f"worker-{status}"),
        redis_client=redis_client,
        control_client=api_client(httpx.MockTransport(lambda _request: httpx.Response(status))),
        runner=RecordingRunner(),
    )
    consumer.setup()
    consumer.process_once()

    assert redis_client.xpending("signaldesk:diagnostics", "diagnostic-workers")["pending"] == 1
    assert redis_client.xlen("signaldesk:diagnostics:dlq") == 0


def test_remote_protocol_error_follows_transient_pending_path(
    redis_client: redis.Redis, redis_url: str
) -> None:
    event = requested_event()
    add_event(redis_client, event)

    def fail(_request: httpx.Request) -> httpx.Response:
        raise httpx.RemoteProtocolError("sensitive protocol detail")

    consumer = DiagnosticConsumer(
        settings=make_settings(redis_url, "worker-protocol-error"),
        redis_client=redis_client,
        control_client=api_client(httpx.MockTransport(fail)),
        runner=RecordingRunner(),
    )
    consumer.setup()

    assert consumer.process_once() == 1
    assert redis_client.xpending(
        "signaldesk:diagnostics", "diagnostic-workers"
    )["pending"] == 1
    assert redis_client.xlen("signaldesk:diagnostics:dlq") == 0


def test_fatal_credential_denial_is_neither_acked_nor_dead_lettered(
    redis_client: redis.Redis, redis_url: str
) -> None:
    event = requested_event()
    add_event(redis_client, event)
    consumer = DiagnosticConsumer(
        settings=make_settings(redis_url, "worker-fatal"),
        redis_client=redis_client,
        control_client=api_client(httpx.MockTransport(lambda _request: httpx.Response(401))),
        runner=RecordingRunner(),
    )
    consumer.setup()

    with pytest.raises(FatalCredentialError):
        consumer.process_once()
    assert redis_client.xpending("signaldesk:diagnostics", "diagnostic-workers")["pending"] == 1
    assert redis_client.xlen("signaldesk:diagnostics:dlq") == 0


def test_stale_xautoclaim_recovers_claimed_job_via_get_and_completes(
    redis_client: redis.Redis, redis_url: str
) -> None:
    event = requested_event()
    add_event(redis_client, event)
    state = {"completion_attempts": 0}

    def first_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/claim"):
            payload = scope_json(event, "tcp://authoritative.example:443")
            payload.pop("status")
            return httpx.Response(200, json=payload)
        state["completion_attempts"] += 1
        raise httpx.ReadTimeout("lost completion response")

    first = DiagnosticConsumer(
        settings=make_settings(redis_url, "worker-crashed"),
        redis_client=redis_client,
        control_client=api_client(httpx.MockTransport(first_handler)),
        runner=RecordingRunner(),
    )
    first.setup()
    first.process_once()
    assert redis_client.xpending("signaldesk:diagnostics", "diagnostic-workers")["pending"] == 1
    time.sleep(1.05)

    methods: list[str] = []

    def recovery_handler(request: httpx.Request) -> httpx.Response:
        methods.append(request.method)
        if request.url.path.endswith("/claim"):
            return httpx.Response(409)
        if request.method == "GET":
            return httpx.Response(200, json=scope_json(event, "tcp://authoritative.example:443"))
        return httpx.Response(200, json={"diagnostic_job_id": str(event.diagnostic_job_id), "status": "completed"})

    runner = RecordingRunner()
    recovered = DiagnosticConsumer(
        settings=make_settings(redis_url, "worker-recovery"),
        redis_client=redis_client,
        control_client=api_client(httpx.MockTransport(recovery_handler)),
        runner=runner,
    )
    recovered.setup()
    recovered.process_once()

    assert methods == ["POST", "GET", "POST"]
    assert runner.targets == ["tcp://authoritative.example:443"]
    assert redis_client.xpending("signaldesk:diagnostics", "diagnostic-workers")["pending"] == 0


def test_already_completed_stale_recovery_acks_without_execution(
    redis_client: redis.Redis, redis_url: str
) -> None:
    event = requested_event()
    add_event(redis_client, event)
    consumer_a = DiagnosticConsumer(
        settings=make_settings(redis_url, "worker-old"),
        redis_client=redis_client,
        control_client=api_client(httpx.MockTransport(lambda _request: httpx.Response(503))),
        runner=RecordingRunner(),
    )
    consumer_a.setup()
    consumer_a.process_once()
    time.sleep(1.05)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/claim"):
            return httpx.Response(409)
        return httpx.Response(200, json=scope_json(event, "tcp://done.example:443", "completed"))

    runner = RecordingRunner()
    consumer_b = DiagnosticConsumer(
        settings=make_settings(redis_url, "worker-new"),
        redis_client=redis_client,
        control_client=api_client(httpx.MockTransport(handler)),
        runner=runner,
    )
    consumer_b.setup()
    consumer_b.process_once()

    assert runner.targets == []
    assert redis_client.xpending("signaldesk:diagnostics", "diagnostic-workers")["pending"] == 0


@pytest.mark.parametrize("final_status", ["completed", "claimed"])
def test_completion_409_refetches_authority(
    redis_client: redis.Redis, redis_url: str, final_status: str
) -> None:
    event = requested_event()
    add_event(redis_client, event)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/claim"):
            payload = scope_json(event, "tcp://completion.example:443")
            payload.pop("status")
            return httpx.Response(200, json=payload)
        if request.method == "POST":
            return httpx.Response(409)
        return httpx.Response(200, json=scope_json(event, "tcp://completion.example:443", final_status))

    consumer = DiagnosticConsumer(
        settings=make_settings(redis_url, f"worker-completion-{final_status}"),
        redis_client=redis_client,
        control_client=api_client(httpx.MockTransport(handler)),
        runner=RecordingRunner(),
    )
    consumer.setup()
    consumer.process_once()

    pending = redis_client.xpending("signaldesk:diagnostics", "diagnostic-workers")["pending"]
    assert pending == (0 if final_status == "completed" else 1)


def test_max_delivery_moves_once_to_atomic_dlq_and_acks_source(
    redis_client: redis.Redis, redis_url: str
) -> None:
    event = requested_event()
    add_event(redis_client, event)
    failing = httpx.MockTransport(lambda _request: httpx.Response(503))
    first = DiagnosticConsumer(
        settings=make_settings(redis_url, "worker-attempt-1", max_deliveries=2),
        redis_client=redis_client,
        control_client=api_client(failing),
        runner=RecordingRunner(),
    )
    first.setup()
    first.process_once()
    time.sleep(1.05)
    second = DiagnosticConsumer(
        settings=make_settings(redis_url, "worker-attempt-2", max_deliveries=2),
        redis_client=redis_client,
        control_client=api_client(failing),
        runner=RecordingRunner(),
    )
    second.setup()
    second.process_once()
    second.process_once()

    assert redis_client.xpending("signaldesk:diagnostics", "diagnostic-workers")["pending"] == 0
    assert redis_client.xlen("signaldesk:diagnostics:dlq") == 1
    dlq = redis_client.xrange("signaldesk:diagnostics:dlq")[0][1]
    assert dlq[b"attempt_count"] == b"2"
    assert dlq[b"failure_code"] == b"control_transient"


def test_malformed_oversized_and_unsupported_events_dead_letter_safely(
    redis_client: redis.Redis, redis_url: str
) -> None:
    redis_client.xadd("signaldesk:diagnostics", {"event": '{"credential":"TOPSECRET"}', "event_id": str(uuid4())})
    redis_client.xadd("signaldesk:diagnostics", {"event": "X" * 9000, "event_id": str(uuid4())})
    email = EmailRequestedV1(
        schema_version=1,
        event_id=uuid4(),
        event_type="email.requested.v1",
        occurred_at=datetime.now(timezone.utc),
        correlation_id=uuid4(),
        organization_id=uuid4(),
        email_delivery_id=uuid4(),
    )
    redis_client.xadd("signaldesk:diagnostics", {"event": email.model_dump_json(), "event_id": str(email.event_id)})
    consumer = DiagnosticConsumer(
        settings=make_settings(redis_url, "worker-poison", event_max_bytes=8192),
        redis_client=redis_client,
        control_client=api_client(httpx.MockTransport(lambda _request: httpx.Response(500))),
        runner=RecordingRunner(),
    )
    consumer.setup()
    consumer.process_once()

    assert redis_client.xpending("signaldesk:diagnostics", "diagnostic-workers")["pending"] == 0
    records = redis_client.xrange("signaldesk:diagnostics:dlq")
    assert len(records) == 3
    combined = b"".join(value for _record_id, fields in records for value in fields.values())
    assert b"TOPSECRET" not in combined
    assert b"X" * 100 not in combined
    assert all(len(value) <= 8192 for _record_id, fields in records for value in fields.values())


def test_setup_rejects_non_standalone_topology_before_group_or_scripts(redis_url: str) -> None:
    class ClusterLike:
        def info(self, section: str) -> dict[str, int]:
            assert section == "cluster"
            return {"cluster_enabled": 1}

    consumer = DiagnosticConsumer(
        settings=make_settings(redis_url, "worker-cluster"),
        redis_client=ClusterLike(),  # type: ignore[arg-type]
        control_client=api_client(httpx.MockTransport(lambda _request: httpx.Response(500))),
        runner=RecordingRunner(),
    )

    with pytest.raises(TopologyError):
        consumer.setup()


def test_xautoclaim_cursor_advances_across_poll_calls() -> None:
    class CursorRedis:
        def __init__(self) -> None:
            self.starts: list[bytes | str] = []
            self.next_ids = iter([b"5-0", b"0-0"])

        def xautoclaim(self, *_args: object, start_id: bytes | str, **_kwargs: object):
            self.starts.append(start_id)
            return [next(self.next_ids), [], []]

        def xreadgroup(self, *_args: object, **_kwargs: object):
            return []

    broker = CursorRedis()
    consumer = DiagnosticConsumer(
        settings=make_settings("redis://redis.test:6379/0", "worker-cursor"),
        redis_client=broker,
        control_client=api_client(
            httpx.MockTransport(lambda _request: httpx.Response(500))
        ),
        runner=RecordingRunner(),
    )
    consumer._ready = True

    assert consumer.process_once() == 0
    assert consumer.process_once() == 0
    assert broker.starts == ["0-0", b"5-0"]


def test_ordinary_ack_requires_a_well_formed_atomic_script_result() -> None:
    class MissingAckRedis:
        def eval(self, *_args: object) -> list[object]:
            return [-1, b"ack_failed"]

    consumer = DiagnosticConsumer(
        settings=make_settings("redis://redis.test:6379/0", "worker-ack"),
        redis_client=MissingAckRedis(),
        control_client=api_client(
            httpx.MockTransport(lambda _request: httpx.Response(500))
        ),
        runner=RecordingRunner(),
    )

    with pytest.raises(RuntimeError, match="atomically acknowledge"):
        consumer._ack("1-0", 1)


def test_stop_signal_prevents_starting_another_probe_in_the_batch() -> None:
    class BatchRedis:
        def xautoclaim(self, *_args: object, **_kwargs: object):
            return [b"0-0", [(b"1-0", {}), (b"2-0", {})], []]

    stop = Event()
    consumer = DiagnosticConsumer(
        settings=make_settings("redis://redis.test:6379/0", "worker-stop"),
        redis_client=BatchRedis(),
        control_client=api_client(
            httpx.MockTransport(lambda _request: httpx.Response(500))
        ),
        runner=RecordingRunner(),
        stop_event=stop,
    )
    consumer._ready = True
    processed: list[bytes | str] = []

    def process(entry_id: bytes | str, _fields: object) -> None:
        processed.append(entry_id)
        stop.set()

    consumer._process_entry = process  # type: ignore[method-assign]

    assert consumer.process_once() == 1
    assert processed == [b"1-0"]


def test_dead_letter_lua_is_atomic_and_idempotent_without_marker_trust(
    redis_client: redis.Redis,
    redis_url: str,
) -> None:
    event = requested_event()
    add_event(redis_client, event)
    consumer = DiagnosticConsumer(
        settings=make_settings(redis_url, "worker-dlq-idempotent"),
        redis_client=redis_client,
        control_client=api_client(
            httpx.MockTransport(lambda _request: httpx.Response(500))
        ),
        runner=RecordingRunner(),
    )
    consumer.setup()
    entries = redis_client.xreadgroup(
        "diagnostic-workers",
        consumer.consumer_identity,
        {"signaldesk:diagnostics": ">"},
        count=1,
    )[0][1]
    entry_id = entries[0][0]
    raw_event = event.model_dump_json().encode()

    assert consumer._dead_letter(entry_id, raw_event, event, "invalid_event", 1)
    assert not consumer._dead_letter(entry_id, raw_event, event, "invalid_event", 1)

    assert redis_client.xlen("signaldesk:diagnostics:dlq") == 1
    assert redis_client.xpending(
        "signaldesk:diagnostics", "diagnostic-workers"
    )["pending"] == 0


@pytest.mark.parametrize("current_action", ["ack", "dlq"])
def test_stale_owner_cannot_ack_or_dead_letter_after_generation_changes(
    redis_client: redis.Redis,
    redis_url: str,
    current_action: str,
) -> None:
    event = requested_event()
    add_event(redis_client, event)
    stale = DiagnosticConsumer(
        settings=make_settings(redis_url, "worker-owner-a"),
        redis_client=redis_client,
        control_client=api_client(httpx.MockTransport(lambda _request: httpx.Response(500))),
        runner=RecordingRunner(),
    )
    stale.setup()
    entry_id = redis_client.xreadgroup(
        "diagnostic-workers",
        stale.consumer_identity,
        {"signaldesk:diagnostics": ">"},
        count=1,
    )[0][1][0][0]
    assert stale._delivery_count(entry_id) == 1

    current = DiagnosticConsumer(
        settings=make_settings(redis_url, "worker-owner-a"),
        redis_client=redis_client,
        control_client=api_client(httpx.MockTransport(lambda _request: httpx.Response(500))),
        runner=RecordingRunner(),
    )
    claimed = redis_client.xautoclaim(
        "signaldesk:diagnostics",
        "diagnostic-workers",
        current.consumer_identity,
        min_idle_time=0,
        start_id="0-0",
        count=1,
    )
    assert claimed[1][0][0] == entry_id

    raw_event = event.model_dump_json().encode()
    assert not stale._ack(entry_id, 1)
    assert not stale._dead_letter(
        entry_id, raw_event, event, "stale_terminal", 1
    )
    pending = redis_client.xpending_range(
        "signaldesk:diagnostics",
        "diagnostic-workers",
        min=entry_id,
        max=entry_id,
        count=1,
    )
    assert pending[0]["consumer"] == current.consumer_identity.encode()
    assert pending[0]["times_delivered"] == 2
    assert redis_client.xlen("signaldesk:diagnostics:dlq") == 0

    if current_action == "ack":
        assert current._ack(entry_id, 2)
        assert not current._ack(entry_id, 2)
        assert redis_client.xlen("signaldesk:diagnostics:dlq") == 0
    else:
        assert current._dead_letter(
            entry_id, raw_event, event, "current_terminal", 2
        )
        assert not current._dead_letter(
            entry_id, raw_event, event, "current_terminal", 2
        )
        assert redis_client.xlen("signaldesk:diagnostics:dlq") == 1
    assert redis_client.xpending(
        "signaldesk:diagnostics", "diagnostic-workers"
    )["pending"] == 0


def test_completion_ack_race_leaves_reclaimed_entry_for_current_owner(
    redis_client: redis.Redis,
    redis_url: str,
) -> None:
    event = requested_event()
    add_event(redis_client, event)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/claim"):
            payload = scope_json(event, "tcp://completion-race.example:443")
            payload.pop("status")
            return httpx.Response(200, json=payload)
        claimed = redis_client.xautoclaim(
            "signaldesk:diagnostics",
            "diagnostic-workers",
            "worker-completion-race-b",
            min_idle_time=0,
            start_id="0-0",
            count=1,
        )
        assert len(claimed[1]) == 1
        return httpx.Response(
            200,
            json={"diagnostic_job_id": str(event.diagnostic_job_id), "status": "completed"},
        )

    stale = DiagnosticConsumer(
        settings=make_settings(redis_url, "worker-completion-race-a"),
        redis_client=redis_client,
        control_client=api_client(httpx.MockTransport(handler)),
        runner=RecordingRunner(),
    )
    stale.setup()

    assert stale.process_once() == 1
    pending = redis_client.xpending_range(
        "signaldesk:diagnostics", "diagnostic-workers", min="-", max="+", count=1
    )
    assert pending[0]["consumer"] == b"worker-completion-race-b"
    assert pending[0]["times_delivered"] == 2
    assert redis_client.xlen("signaldesk:diagnostics:dlq") == 0
