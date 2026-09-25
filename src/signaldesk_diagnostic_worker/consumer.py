from __future__ import annotations

import hashlib
from threading import Event
from typing import Any, Protocol
from uuid import UUID, uuid4

from pydantic import ValidationError
from redis.exceptions import ResponseError
from signaldesk_contracts import DiagnosticRequestedV1

from signaldesk_diagnostic_worker.control_client import (
    ClaimConflict,
    CompletionConflict,
    ControlApiClient,
    FatalCredentialError,
    NotFoundError,
    ScopeConflict,
    TransientControlError,
    WorkerScope,
)
from signaldesk_diagnostic_worker.settings import Settings


class TopologyError(RuntimeError):
    pass


class Runner(Protocol):
    def run(self, target: str) -> dict[str, str | int]: ...


_ACK_SCRIPT = """
local pending = redis.call('XPENDING', KEYS[1], ARGV[1], ARGV[2], ARGV[2], 1)
if #pending == 0 then
  return {0, 'ownership_lost'}
end
if pending[1][2] ~= ARGV[3] or tostring(pending[1][4]) ~= ARGV[4] then
  return {0, 'ownership_lost'}
end
local acknowledged = redis.call('XACK', KEYS[1], ARGV[1], ARGV[2])
if acknowledged ~= 1 then
  return {-1, 'ack_failed'}
end
return {1, 'acknowledged'}
"""

_DLQ_SCRIPT = """
local pending = redis.call('XPENDING', KEYS[1], ARGV[1], ARGV[2], ARGV[2], 1)
if #pending == 0 then
  return {0, 'ownership_lost'}
end
if pending[1][2] ~= ARGV[3] or tostring(pending[1][4]) ~= ARGV[4] then
  return {0, 'ownership_lost'}
end
local dlq_id = redis.call(
  'XADD', KEYS[2], '*',
  'event', ARGV[5],
  'event_id', ARGV[6],
  'failure_code', ARGV[7],
  'source_stream', ARGV[8],
  'source_id', ARGV[2],
  'attempt_count', ARGV[4]
)
local acknowledged = redis.call('XACK', KEYS[1], ARGV[1], ARGV[2])
if acknowledged ~= 1 then
  return {-1, 'ack_failed'}
end
return {1, 'dead_lettered'}
"""


class DiagnosticConsumer:
    """Bounded, authoritative Redis consumer with crash recovery."""

    def __init__(
        self,
        *,
        settings: Settings,
        redis_client: Any,
        control_client: ControlApiClient,
        runner: Runner,
        stop_event: Event | None = None,
    ) -> None:
        self.settings = settings
        self.redis = redis_client
        self.control = control_client
        self.runner = runner
        self.stop_event = stop_event or Event()
        # The configured value is an operator label, not a fencing identity.
        # A process-incarnation suffix prevents a restarted worker from
        # impersonating the prior pending owner.
        self.consumer_identity = f"{settings.consumer_name}:{uuid4().hex}"
        self._ready = False
        self._autoclaim_cursor: bytes | str = "0-0"

    def setup(self) -> None:
        cluster = self.redis.info("cluster")
        enabled = cluster.get("cluster_enabled", cluster.get(b"cluster_enabled"))
        if enabled not in {0, "0", b"0"}:
            raise TopologyError("diagnostic worker requires standalone Redis")
        role = self.redis.role()
        role_name = role[0] if role else None
        if role_name not in {"master", b"master"}:
            raise TopologyError("diagnostic worker requires standalone primary Redis")
        try:
            self.redis.xgroup_create(
                self.settings.stream_name,
                self.settings.consumer_group,
                id="0-0",
                mkstream=True,
            )
        except ResponseError as error:
            if "BUSYGROUP" not in str(error):
                raise
        self._ready = True

    def run(self) -> None:
        if not self._ready:
            self.setup()
        while not self.stop_event.is_set():
            self.process_once()

    def process_once(self) -> int:
        if not self._ready:
            raise RuntimeError("consumer setup is required")
        reclaimed = self.redis.xautoclaim(
            self.settings.stream_name,
            self.settings.consumer_group,
            self.consumer_identity,
            min_idle_time=self.settings.stale_idle_ms,
            start_id=self._autoclaim_cursor,
            count=self.settings.batch_size,
        )
        if reclaimed:
            self._autoclaim_cursor = reclaimed[0]
        entries = reclaimed[1] if reclaimed and len(reclaimed) > 1 else []
        if not entries:
            streams = self.redis.xreadgroup(
                self.settings.consumer_group,
                self.consumer_identity,
                {self.settings.stream_name: ">"},
                count=self.settings.batch_size,
                block=self.settings.block_time_ms,
            )
            entries = streams[0][1] if streams else []
        processed = 0
        for entry_id, fields in entries:
            if self.stop_event.is_set():
                break
            self._process_entry(entry_id, fields)
            processed += 1
        return processed

    def _process_entry(self, entry_id: bytes | str, fields: dict[Any, Any]) -> None:
        attempts = self._delivery_count(entry_id)
        if attempts is None:
            return
        raw_fields = {
            self._decode_field_name(key): self._field_bytes(value)
            for key, value in fields.items()
        }
        raw_event = raw_fields.get("event", b"")
        parsed: DiagnosticRequestedV1 | None = None
        failure: str | None = None
        if set(raw_fields) != {"event", "event_id"}:
            failure = "invalid_stream_fields"
        elif len(raw_event) > self.settings.event_max_bytes:
            failure = "oversized_event"
        elif len(raw_fields["event_id"]) > 64:
            failure = "invalid_event_id"
        else:
            try:
                parsed = DiagnosticRequestedV1.model_validate_json(raw_event)
            except (ValidationError, ValueError):
                failure = "invalid_event"
            if parsed is not None:
                try:
                    field_event_id = UUID(raw_fields["event_id"].decode("ascii"))
                except (UnicodeDecodeError, ValueError):
                    failure = "invalid_event_id"
                else:
                    if field_event_id != parsed.event_id:
                        failure = "event_id_mismatch"
        if failure is not None:
            self._dead_letter(entry_id, raw_event, parsed, failure, attempts)
            return
        assert parsed is not None

        try:
            scope = self.control.claim(parsed.diagnostic_job_id)
        except ClaimConflict:
            try:
                scope = self.control.fetch(parsed.diagnostic_job_id)
            except FatalCredentialError:
                raise
            except NotFoundError:
                self._dead_letter(
                    entry_id, raw_event, parsed, "job_not_found", attempts
                )
                return
            except (ScopeConflict, TransientControlError):
                self._retry_or_dead_letter(
                    entry_id, raw_event, parsed, "control_transient", attempts
                )
                return
        except FatalCredentialError:
            raise
        except NotFoundError:
            self._dead_letter(entry_id, raw_event, parsed, "job_not_found", attempts)
            return
        except TransientControlError:
            self._retry_or_dead_letter(
                entry_id, raw_event, parsed, "control_transient", attempts
            )
            return

        if not self._scope_matches(parsed, scope):
            self._dead_letter(entry_id, raw_event, parsed, "scope_mismatch", attempts)
            return
        if scope.status == "completed":
            self._ack(entry_id, attempts)
            return

        try:
            result = self.runner.run(scope.target)
        except Exception:
            self._retry_or_dead_letter(
                entry_id, raw_event, parsed, "runner_failed", attempts
            )
            return
        try:
            self.control.complete(parsed.diagnostic_job_id, result)
        except FatalCredentialError:
            raise
        except CompletionConflict:
            self._resolve_completion_conflict(
                entry_id, raw_event, parsed, attempts
            )
            return
        except NotFoundError:
            self._dead_letter(entry_id, raw_event, parsed, "job_not_found", attempts)
            return
        except TransientControlError:
            self._retry_or_dead_letter(
                entry_id, raw_event, parsed, "control_transient", attempts
            )
            return
        self._ack(entry_id, attempts)

    def _resolve_completion_conflict(
        self,
        entry_id: bytes | str,
        raw_event: bytes,
        event: DiagnosticRequestedV1,
        attempts: int,
    ) -> None:
        try:
            scope = self.control.fetch(event.diagnostic_job_id)
        except FatalCredentialError:
            raise
        except NotFoundError:
            self._dead_letter(entry_id, raw_event, event, "job_not_found", attempts)
            return
        except (ScopeConflict, TransientControlError):
            self._retry_or_dead_letter(
                entry_id, raw_event, event, "completion_conflict", attempts
            )
            return
        if not self._scope_matches(event, scope):
            self._dead_letter(entry_id, raw_event, event, "scope_mismatch", attempts)
        elif scope.status == "completed":
            self._ack(entry_id, attempts)
        else:
            self._retry_or_dead_letter(
                entry_id, raw_event, event, "completion_conflict", attempts
            )

    @staticmethod
    def _scope_matches(event: DiagnosticRequestedV1, scope: WorkerScope) -> bool:
        return (
            scope.diagnostic_job_id == event.diagnostic_job_id
            and scope.organization_id == event.organization_id
            and scope.correlation_id == event.correlation_id
        )

    def _delivery_count(self, entry_id: bytes | str) -> int | None:
        pending = self.redis.xpending_range(
            self.settings.stream_name,
            self.settings.consumer_group,
            min=entry_id,
            max=entry_id,
            count=1,
            consumername=self.consumer_identity,
        )
        if not pending:
            return None
        record = pending[0]
        value = record.get("times_delivered", record.get(b"times_delivered", 1))
        return max(1, int(value))

    def _retry_or_dead_letter(
        self,
        entry_id: bytes | str,
        raw_event: bytes,
        event: DiagnosticRequestedV1,
        failure_code: str,
        attempts: int,
    ) -> None:
        if attempts >= self.settings.max_deliveries:
            self._dead_letter(
                entry_id, raw_event, event, failure_code, attempts
            )

    def _ack(self, entry_id: bytes | str, attempts: int) -> bool:
        source_id = (
            entry_id.decode("ascii", "strict")
            if isinstance(entry_id, bytes)
            else entry_id
        )
        result = self.redis.eval(
            _ACK_SCRIPT,
            1,
            self.settings.stream_name,
            self.settings.consumer_group,
            source_id,
            self.consumer_identity,
            str(attempts),
        )
        return self._parse_atomic_result(
            result,
            success_token="acknowledged",
            operation="acknowledge",
        )

    def _dead_letter(
        self,
        entry_id: bytes | str,
        raw_event: bytes,
        event: DiagnosticRequestedV1 | None,
        failure_code: str,
        attempts: int,
    ) -> bool:
        source_id = (
            entry_id.decode("ascii", "strict")
            if isinstance(entry_id, bytes)
            else entry_id
        )
        if event is None:
            safe_event = "sha256:" + hashlib.sha256(raw_event).hexdigest()
            safe_event_id = "invalid"
        else:
            safe_event = event.model_dump_json()
            safe_event_id = str(event.event_id)
        result = self.redis.eval(
            _DLQ_SCRIPT,
            2,
            self.settings.stream_name,
            self.settings.dlq_stream_name,
            self.settings.consumer_group,
            source_id,
            self.consumer_identity,
            str(attempts),
            safe_event,
            safe_event_id,
            failure_code,
            self.settings.stream_name,
        )
        return self._parse_atomic_result(
            result,
            success_token="dead_lettered",
            operation="dead-letter",
        )

    @staticmethod
    def _parse_atomic_result(
        result: Any,
        *,
        success_token: str,
        operation: str,
    ) -> bool:
        message = f"Redis did not atomically {operation} the diagnostic event"
        if not isinstance(result, (list, tuple)) or len(result) != 2:
            raise RuntimeError(message)
        status, raw_token = result
        if type(status) is not int or not isinstance(raw_token, (bytes, str)):
            raise RuntimeError(message)
        try:
            token = raw_token.decode("ascii") if isinstance(raw_token, bytes) else raw_token
        except UnicodeDecodeError:
            raise RuntimeError(message) from None
        if status == 0 and token == "ownership_lost":
            return False
        if status == 1 and token == success_token:
            return True
        raise RuntimeError(message)

    @staticmethod
    def _decode_field_name(value: Any) -> str:
        if isinstance(value, bytes):
            try:
                return value.decode("ascii")
            except UnicodeDecodeError:
                return "<invalid>"
        return str(value)

    @staticmethod
    def _field_bytes(value: Any) -> bytes:
        if isinstance(value, bytes):
            return value
        return str(value).encode("utf-8", "replace")
