from __future__ import annotations

import gzip
import traceback
from uuid import uuid4

import httpx
import pytest

from signaldesk_diagnostic_worker.control_client import (
    CompletionConflict,
    ControlApiClient,
    FatalCredentialError,
    NotFoundError,
    TransientControlError,
    WorkerScope,
)


CREDENTIAL = "diagnostic-worker-secret-value-0001"
JOB_ID = uuid4()
ORG_ID = uuid4()
CORRELATION_ID = uuid4()


class ExplodingStream(httpx.SyncByteStream):
    def __init__(self, payload: bytes = b"") -> None:
        self.payload = payload

    def __iter__(self):
        raise AssertionError("response body must not be read")


class ChunkedStream(httpx.SyncByteStream):
    def __init__(self, *chunks: bytes) -> None:
        self.chunks = chunks

    def __iter__(self):
        yield from self.chunks


def response_payload(status: str = "claimed") -> dict[str, str]:
    return {
        "diagnostic_job_id": str(JOB_ID),
        "organization_id": str(ORG_ID),
        "correlation_id": str(CORRELATION_ID),
        "target": "tcp://authoritative.example:443",
        "status": status,
    }


def test_claim_sends_only_path_job_id_and_worker_credential() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        payload = response_payload()
        payload.pop("status")
        return httpx.Response(200, json=payload)

    client = ControlApiClient(
        base_url="https://control.example.test",
        credential=CREDENTIAL,
        timeout=2.5,
        transport=httpx.MockTransport(handler),
    )

    scope = client.claim(JOB_ID)

    assert scope == WorkerScope(
        diagnostic_job_id=JOB_ID,
        organization_id=ORG_ID,
        correlation_id=CORRELATION_ID,
        target="tcp://authoritative.example:443",
        status="claimed",
    )
    request = requests[0]
    assert request.method == "POST"
    assert request.url == f"https://control.example.test/internal/diagnostics/{JOB_ID}/claim"
    assert request.headers["X-SignalDesk-Service-Credential"] == CREDENTIAL
    assert request.content == b""


def test_fetch_strictly_parses_authoritative_claimed_and_completed_scope() -> None:
    statuses = iter(["claimed", "completed"])

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=response_payload(next(statuses)))

    client = ControlApiClient(
        base_url="https://control.example.test",
        credential=CREDENTIAL,
        timeout=2,
        transport=httpx.MockTransport(handler),
    )

    assert client.fetch(JOB_ID).status == "claimed"
    assert client.fetch(JOB_ID).status == "completed"


@pytest.mark.parametrize(
    "mutation",
    [
        {"extra": "not-allowed"},
        {"status": "pending"},
        {"diagnostic_job_id": str(uuid4())},
        {"target": "x" * 2049},
    ],
)
def test_fetch_rejects_malformed_or_mismatched_scope(mutation: dict[str, str]) -> None:
    payload = response_payload() | mutation
    client = ControlApiClient(
        base_url="https://control.example.test",
        credential=CREDENTIAL,
        timeout=2,
        transport=httpx.MockTransport(lambda _request: httpx.Response(200, json=payload)),
    )

    with pytest.raises(TransientControlError):
        client.fetch(JOB_ID)


def test_complete_sends_only_bounded_result_and_strictly_parses_acceptance() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            json={"diagnostic_job_id": str(JOB_ID), "status": "completed"},
        )

    client = ControlApiClient(
        base_url="https://control.example.test",
        credential=CREDENTIAL,
        timeout=2,
        transport=httpx.MockTransport(handler),
    )

    client.complete(JOB_ID, {"outcome": "reachable", "http_status": 204})

    assert requests[0].url.path == f"/internal/diagnostics/{JOB_ID}/complete"
    assert requests[0].method == "POST"
    assert requests[0].headers["X-SignalDesk-Service-Credential"] == CREDENTIAL
    assert requests[0].read() == b'{"result":{"outcome":"reachable","http_status":204}}'


@pytest.mark.parametrize("status", [401, 403])
def test_credential_denial_is_fatal(status: int) -> None:
    client = ControlApiClient(
        base_url="https://control.example.test",
        credential=CREDENTIAL,
        timeout=2,
        transport=httpx.MockTransport(lambda _request: httpx.Response(status)),
    )

    with pytest.raises(FatalCredentialError):
        client.claim(JOB_ID)


@pytest.mark.parametrize("status", [500, 502, 503])
def test_server_failures_are_transient(status: int) -> None:
    client = ControlApiClient(
        base_url="https://control.example.test",
        credential=CREDENTIAL,
        timeout=2,
        transport=httpx.MockTransport(lambda _request: httpx.Response(status)),
    )

    with pytest.raises(TransientControlError):
        client.fetch(JOB_ID)


def test_network_timeout_is_transient_without_leaking_detail() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("secret internal endpoint detail")

    client = ControlApiClient(
        base_url="https://control.example.test",
        credential=CREDENTIAL,
        timeout=2,
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(TransientControlError) as caught:
        client.fetch(JOB_ID)
    assert "secret" not in str(caught.value)


def test_success_response_body_is_bounded_before_contract_parsing() -> None:
    client = ControlApiClient(
        base_url="https://control.example.test",
        credential=CREDENTIAL,
        timeout=2,
        max_response_bytes=256,
        transport=httpx.MockTransport(
            lambda _request: httpx.Response(200, content=b"x" * 257)
        ),
    )

    with pytest.raises(TransientControlError, match="response too large"):
        client.fetch(JOB_ID)


@pytest.mark.parametrize("encoding", ["gzip", "deflate"])
def test_success_response_rejects_compression_before_reading(
    encoding: str,
) -> None:
    requests: list[httpx.Request] = []
    compressed = gzip.compress(b"x" * 1_048_576)
    assert len(compressed) < 2_048

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            headers={"Content-Encoding": encoding},
            stream=ExplodingStream(compressed),
        )

    client = ControlApiClient(
        base_url="https://control.example.test",
        credential=CREDENTIAL,
        timeout=2,
        max_response_bytes=max(256, len(compressed)),
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(TransientControlError, match="unsupported content encoding"):
        client.fetch(JOB_ID)
    assert requests[0].headers["Accept-Encoding"] == "identity"


def test_success_response_rejects_declared_oversized_length_before_reading() -> None:
    client = ControlApiClient(
        base_url="https://control.example.test",
        credential=CREDENTIAL,
        timeout=2,
        max_response_bytes=256,
        transport=httpx.MockTransport(
            lambda _request: httpx.Response(
                200,
                headers={"Content-Length": "257"},
                stream=ExplodingStream(),
            )
        ),
    )

    with pytest.raises(TransientControlError, match="response too large"):
        client.fetch(JOB_ID)


def test_success_response_rejects_oversized_raw_chunked_body() -> None:
    client = ControlApiClient(
        base_url="https://control.example.test",
        credential=CREDENTIAL,
        timeout=2,
        max_response_bytes=256,
        transport=httpx.MockTransport(
            lambda _request: httpx.Response(
                200,
                stream=ChunkedStream(b"x" * 200, b"y" * 57),
            )
        ),
    )

    with pytest.raises(TransientControlError, match="response too large"):
        client.fetch(JOB_ID)


def test_success_response_accepts_identity_encoded_bounded_raw_body() -> None:
    payload = response_payload()
    client = ControlApiClient(
        base_url="https://control.example.test",
        credential=CREDENTIAL,
        timeout=2,
        transport=httpx.MockTransport(
            lambda _request: httpx.Response(
                200,
                headers={"Content-Encoding": "identity"},
                json=payload,
            )
        ),
    )

    assert client.fetch(JOB_ID).target == payload["target"]


def test_error_status_does_not_read_response_body() -> None:
    client = ControlApiClient(
        base_url="https://control.example.test",
        credential=CREDENTIAL,
        timeout=2,
        transport=httpx.MockTransport(
            lambda _request: httpx.Response(503, stream=ExplodingStream())
        ),
    )

    with pytest.raises(TransientControlError, match="request failed"):
        client.fetch(JOB_ID)


@pytest.mark.parametrize(
    "error",
    [
        httpx.RemoteProtocolError("sensitive protocol detail"),
        httpx.TransportError("sensitive transport detail"),
        httpx.DecodingError("sensitive decoding detail"),
    ],
)
def test_all_httpx_errors_are_transient_and_sanitized(error: httpx.HTTPError) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        raise error

    client = ControlApiClient(
        base_url="https://control.example.test",
        credential=CREDENTIAL,
        timeout=2,
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(TransientControlError) as caught:
        client.fetch(JOB_ID)
    assert str(caught.value) == "control API unavailable"
    assert "sensitive" not in str(caught.value)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    rendered_traceback = "".join(
        traceback.format_exception(
            type(caught.value), caught.value, caught.value.__traceback__
        )
    )
    assert "sensitive" not in rendered_traceback


def test_not_found_and_completion_conflict_are_typed() -> None:
    responses = iter([httpx.Response(404), httpx.Response(409)])
    client = ControlApiClient(
        base_url="https://control.example.test",
        credential=CREDENTIAL,
        timeout=2,
        transport=httpx.MockTransport(lambda _request: next(responses)),
    )

    with pytest.raises(NotFoundError):
        client.claim(JOB_ID)
    with pytest.raises(CompletionConflict):
        client.complete(JOB_ID, {"outcome": "blocked"})
