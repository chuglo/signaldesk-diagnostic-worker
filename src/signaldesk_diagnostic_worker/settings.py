from __future__ import annotations

from collections.abc import Mapping
import math
from typing import Annotated, Any, Literal, Self

from pydantic import (
    AnyHttpUrl,
    Field,
    IPvAnyAddress,
    RedisDsn,
    SecretStr,
    StringConstraints,
    TypeAdapter,
    ValidationError,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, SettingsConfigDict


ConsumerName = Annotated[
    str,
    StringConstraints(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$"),
]
_REDIS_DSN_ADAPTER = TypeAdapter(RedisDsn)


class Settings(BaseSettings):
    """Least-privilege, fail-closed runtime configuration for one worker."""

    model_config = SettingsConfigDict(
        env_prefix="SIGNALDESK_DIAGNOSTIC_WORKER_",
        extra="forbid",
        hide_input_in_errors=True,
        strict=True,
        validate_default=True,
    )

    redis_url: SecretStr
    control_api_base_url: AnyHttpUrl
    diagnostic_worker_service_credential: SecretStr
    consumer_name: ConsumerName
    dns_nameserver: IPvAnyAddress

    stream_name: Literal["signaldesk:diagnostics"] = "signaldesk:diagnostics"
    consumer_group: Literal["diagnostic-workers"] = "diagnostic-workers"
    dlq_stream_name: Literal["signaldesk:diagnostics:dlq"] = (
        "signaldesk:diagnostics:dlq"
    )

    block_time_ms: int = Field(default=1_000, ge=1, le=5_000)
    stale_idle_ms: int = Field(default=30_000, ge=1_000, le=300_000)
    max_deliveries: int = Field(default=5, ge=1, le=20)
    batch_size: int = Field(default=10, ge=1, le=100)
    api_timeout_seconds: float = Field(default=5.0, gt=0, le=30)
    api_max_response_bytes: int = Field(default=16_384, ge=256, le=65_536)
    redis_connect_timeout_seconds: float = Field(default=3.0, gt=0, le=10)
    redis_socket_timeout_seconds: float = Field(default=10.0, gt=0, le=30)
    diagnostic_connect_timeout_seconds: float = Field(default=3.0, gt=0, le=10)
    diagnostic_read_timeout_seconds: float = Field(default=3.0, gt=0, le=30)
    diagnostic_total_timeout_seconds: float = Field(default=10.0, gt=0, le=60)
    diagnostic_max_header_bytes: int = Field(default=16_384, ge=256, le=65_536)
    event_max_bytes: int = Field(default=8_192, ge=256, le=16_384)

    @model_validator(mode="before")
    @classmethod
    def mask_redis_url_before_validation(cls, value: Any) -> Any:
        if not isinstance(value, Mapping):
            return value
        masked = dict(value)
        redis_url = masked.get("redis_url")
        if isinstance(redis_url, str):
            masked["redis_url"] = SecretStr(redis_url)
        elif isinstance(redis_url, (bytes, bytearray, memoryview)):
            try:
                decoded = bytes(redis_url).decode("utf-8", "strict")
            except UnicodeDecodeError:
                decoded = "invalid://"
            masked["redis_url"] = SecretStr(decoded)
        return masked

    @model_validator(mode="after")
    def validate_stale_idle_window(self) -> Self:
        bounded_work_ms = math.ceil(
            (
                2 * self.api_timeout_seconds
                + self.diagnostic_total_timeout_seconds
            )
            * 1_000
        )
        safety_margin_ms = 100
        if self.stale_idle_ms <= bounded_work_ms + safety_margin_ms:
            raise ValueError(
                "stale_idle_ms must exceed two API timeouts plus the diagnostic "
                "total timeout and a 100ms safety margin"
            )
        return self

    @field_validator("diagnostic_worker_service_credential")
    @classmethod
    def validate_service_credential(cls, value: SecretStr) -> SecretStr:
        raw = value.get_secret_value()
        if (
            len(raw) < 32
            or raw != raw.strip()
            or not raw.isascii()
            or any(character.isspace() for character in raw)
        ):
            raise ValueError(
                "diagnostic worker credential must be at least 32 non-whitespace ASCII characters"
            )
        return value

    @field_validator("control_api_base_url")
    @classmethod
    def validate_control_api_base_url(cls, value: AnyHttpUrl) -> AnyHttpUrl:
        if value.username is not None or value.password is not None:
            raise ValueError("control API base URL must not contain credentials")
        if value.query is not None or value.fragment is not None:
            raise ValueError("control API base URL must not contain query or fragment")
        return value

    @field_validator("redis_url")
    @classmethod
    def validate_redis_url(cls, value: SecretStr) -> SecretStr:
        message = (
            "Redis URL must be a valid unauthenticated redis:// or rediss:// URL "
            "without query or fragment"
        )
        try:
            parsed = _REDIS_DSN_ADAPTER.validate_python(
                value.get_secret_value(), strict=True
            )
        except (ValidationError, TypeError, ValueError):
            raise ValueError(message) from None
        if (
            parsed.username is not None
            or parsed.password is not None
            or parsed.query is not None
            or parsed.fragment is not None
        ):
            raise ValueError(message) from None
        return value
