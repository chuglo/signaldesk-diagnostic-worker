from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Literal
from uuid import UUID

import httpx
from pydantic import BaseModel, ConfigDict, StringConstraints, ValidationError
from typing_extensions import Annotated


class ControlError(RuntimeError):
    pass


class FatalCredentialError(ControlError):
    pass


class NotFoundError(ControlError):
    pass


class ClaimConflict(ControlError):
    pass


class CompletionConflict(ControlError):
    pass


class ScopeConflict(ControlError):
    pass


class TransientControlError(ControlError):
    pass


@dataclass(frozen=True)
class _BoundedResponse:
    status_code: int
    content: bytes = b""


Target = Annotated[str, StringConstraints(min_length=1, max_length=2_048)]


class WorkerScope(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    diagnostic_job_id: UUID
    organization_id: UUID
    correlation_id: UUID
    target: Target
    status: Literal["claimed", "completed"]


class _ClaimResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    diagnostic_job_id: UUID
    organization_id: UUID
    correlation_id: UUID
    target: Target


class _CompleteResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    diagnostic_job_id: UUID
    status: Literal["completed"]


class ControlApiClient:
    """Narrow diagnostic-worker client with typed fail-closed outcomes."""

    def __init__(
        self,
        *,
        base_url: str,
        credential: str,
        timeout: float,
        max_response_bytes: int = 16_384,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if not 256 <= max_response_bytes <= 65_536:
            raise ValueError("max_response_bytes must be between 256 and 65536")
        self._max_response_bytes = max_response_bytes
        self._client = httpx.Client(
            base_url=base_url.rstrip("/"),
            timeout=httpx.Timeout(timeout),
            transport=transport,
            headers={
                "Accept-Encoding": "identity",
                "X-SignalDesk-Service-Credential": credential,
            },
            follow_redirects=False,
        )

    def close(self) -> None:
        self._client.close()

    def claim(self, job_id: UUID) -> WorkerScope:
        response = self._request("POST", f"/internal/diagnostics/{job_id}/claim")
        self._raise_status(response, conflict=ClaimConflict)
        try:
            parsed = _ClaimResponse.model_validate_json(response.content)
        except ValidationError as error:
            raise TransientControlError("invalid control API response") from error
        if parsed.diagnostic_job_id != job_id:
            raise TransientControlError("invalid control API response")
        return WorkerScope(
            diagnostic_job_id=parsed.diagnostic_job_id,
            organization_id=parsed.organization_id,
            correlation_id=parsed.correlation_id,
            target=parsed.target,
            status="claimed",
        )

    def fetch(self, job_id: UUID) -> WorkerScope:
        response = self._request("GET", f"/internal/diagnostics/{job_id}")
        self._raise_status(response, conflict=ScopeConflict)
        try:
            parsed = WorkerScope.model_validate_json(response.content)
        except ValidationError as error:
            raise TransientControlError("invalid control API response") from error
        if parsed.diagnostic_job_id != job_id:
            raise TransientControlError("invalid control API response")
        return parsed

    def complete(self, job_id: UUID, result: dict[str, str | int]) -> None:
        try:
            encoded = json.dumps(
                result,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
            ).encode("ascii")
        except (TypeError, ValueError) as error:
            raise ValueError("diagnostic result must be bounded JSON") from error
        if len(encoded) > 16_384:
            raise ValueError("diagnostic result must be bounded JSON")
        response = self._request(
            "POST",
            f"/internal/diagnostics/{job_id}/complete",
            json={"result": result},
        )
        self._raise_status(response, conflict=CompletionConflict)
        try:
            parsed = _CompleteResponse.model_validate_json(response.content)
        except ValidationError as error:
            raise TransientControlError("invalid control API response") from error
        if parsed.diagnostic_job_id != job_id:
            raise TransientControlError("invalid control API response")

    def _request(self, method: str, path: str, **kwargs: Any) -> _BoundedResponse:
        transport_failed = False
        try:
            with self._client.stream(method, path, **kwargs) as response:
                if response.status_code != 200:
                    return _BoundedResponse(response.status_code)
                content_encoding = response.headers.get("content-encoding", "").strip()
                if content_encoding and content_encoding.lower() != "identity":
                    raise TransientControlError(
                        "control API response has unsupported content encoding"
                    )
                declared_length = response.headers.get("content-length")
                if declared_length is not None:
                    try:
                        length = int(declared_length, 10)
                    except ValueError as error:
                        raise TransientControlError(
                            "invalid control API response"
                        ) from error
                    if length < 0:
                        raise TransientControlError("invalid control API response")
                    if length > self._max_response_bytes:
                        raise TransientControlError("control API response too large")
                content = bytearray()
                chunks = (
                    (response.content,)
                    if response.is_stream_consumed
                    else response.iter_raw()
                )
                for chunk in chunks:
                    if len(content) + len(chunk) > self._max_response_bytes:
                        raise TransientControlError("control API response too large")
                    content.extend(chunk)
                return _BoundedResponse(response.status_code, bytes(content))
        except TransientControlError:
            raise
        except httpx.HTTPError:
            transport_failed = True
        if transport_failed:
            raise TransientControlError("control API unavailable")
        raise RuntimeError("control API request ended without a response")

    @staticmethod
    def _raise_status(
        response: _BoundedResponse,
        *,
        conflict: type[ControlError],
    ) -> None:
        if response.status_code == 200:
            return
        if response.status_code in {401, 403}:
            raise FatalCredentialError("control API credential denied")
        if response.status_code == 404:
            raise NotFoundError("diagnostic job not found")
        if response.status_code == 409:
            raise conflict("diagnostic state conflict")
        raise TransientControlError("control API request failed")
