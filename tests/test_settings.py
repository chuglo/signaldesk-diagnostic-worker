from __future__ import annotations

import pytest
from pydantic import SecretStr, ValidationError

from signaldesk_diagnostic_worker.settings import Settings


VALID = {
    "redis_url": "redis://localhost:6379/0",
    "control_api_base_url": "https://control.example.test",
    "diagnostic_worker_service_credential": "d" * 32,
    "consumer_name": "diagnostic-worker-01",
    "dns_nameserver": "1.1.1.1",
}


def test_settings_require_only_worker_runtime_authority() -> None:
    settings = Settings(**VALID)

    assert settings.stream_name == "signaldesk:diagnostics"
    assert settings.consumer_group == "diagnostic-workers"
    assert settings.dlq_stream_name == "signaldesk:diagnostics:dlq"
    assert settings.diagnostic_worker_service_credential.get_secret_value() == "d" * 32
    assert settings.redis_connect_timeout_seconds == 3.0
    assert settings.redis_socket_timeout_seconds == 10.0
    assert settings.diagnostic_total_timeout_seconds == 10.0
    assert "d" * 32 not in repr(settings)
    assert "d" * 32 not in repr(settings.model_dump())
    fields = set(Settings.model_fields)
    assert not fields & {
        "web_bff_service_credential",
        "email_worker_service_credential",
        "export_worker_service_credential",
        "smtp_url",
        "minio_url",
    }


def test_settings_are_required_and_environment_prefixed(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValidationError):
        Settings()

    for key, value in VALID.items():
        monkeypatch.setenv(f"SIGNALDESK_DIAGNOSTIC_WORKER_{key.upper()}", value)
    assert Settings().consumer_name == VALID["consumer_name"]


@pytest.mark.parametrize("credential", ["x" * 31, "x" * 31 + " ", "é" * 32, "x\ny" + "x" * 30])
def test_settings_reject_weak_or_unsafe_worker_credentials(credential: str) -> None:
    with pytest.raises(ValidationError):
        Settings(**(VALID | {"diagnostic_worker_service_credential": credential}))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("block_time_ms", 0),
        ("block_time_ms", 5001),
        ("stale_idle_ms", 999),
        ("max_deliveries", 0),
        ("max_deliveries", 21),
        ("batch_size", 0),
        ("batch_size", 101),
        ("api_timeout_seconds", 0),
        ("redis_connect_timeout_seconds", 0),
        ("redis_socket_timeout_seconds", 31),
        ("diagnostic_connect_timeout_seconds", 0),
        ("diagnostic_read_timeout_seconds", 31),
        ("diagnostic_total_timeout_seconds", 0),
        ("diagnostic_total_timeout_seconds", 61),
        ("diagnostic_max_header_bytes", 255),
        ("diagnostic_max_header_bytes", 65537),
        ("event_max_bytes", 255),
        ("event_max_bytes", 16385),
    ],
)
def test_settings_reject_unsafe_operational_bounds(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        Settings(**(VALID | {field: value}))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("redis_url", "http://localhost:6379"),
        ("control_api_base_url", "ftp://control.example.test"),
        ("control_api_base_url", "https://user:pass@control.example.test"),
        ("dns_nameserver", "not-an-ip-address"),
        ("consumer_name", ""),
        ("consumer_name", "worker name"),
    ],
)
def test_settings_reject_invalid_endpoints_and_consumer_names(field: str, value: str) -> None:
    with pytest.raises(ValidationError):
        Settings(**(VALID | {field: value}))


@pytest.mark.parametrize(
    ("redis_url", "secret"),
    [
        ("redis://raw-user-secret:password@localhost:6379/0", "raw-user-secret"),
        ("redis://:raw-password-secret@localhost:6379/0", "raw-password-secret"),
        ("redis://localhost:6379/0?credential=raw-query-secret", "raw-query-secret"),
        ("redis://localhost:6379/0#raw-fragment-secret", "raw-fragment-secret"),
        ("redis://[raw-malformed-secret", "raw-malformed-secret"),
    ],
)
def test_redis_url_rejects_credentials_query_and_fragment_without_secret_exposure(
    redis_url: str,
    secret: str,
) -> None:
    with pytest.raises(ValidationError) as caught:
        Settings(**(VALID | {"redis_url": redis_url}))

    rendered = [
        str(caught.value),
        repr(caught.value),
        repr(caught.value.errors(include_input=True)),
        caught.value.json(include_input=True),
    ]
    assert all(secret not in value for value in rendered)


@pytest.mark.parametrize(
    ("redis_url", "secret"),
    [
        (b"redis://:raw-bytes-password@localhost:6379/0", "raw-bytes-password"),
        (b"redis://:\xffraw-undecodable-password@localhost:6379/0", "raw-undecodable-password"),
    ],
)
def test_bytes_redis_url_never_leaks_through_structured_validation_errors(
    redis_url: bytes,
    secret: str,
) -> None:
    with pytest.raises(ValidationError) as caught:
        Settings(**(VALID | {"redis_url": redis_url}))

    rendered = [
        str(caught.value),
        repr(caught.value),
        repr(caught.value.errors(include_input=True)),
        caught.value.json(include_input=True),
    ]
    assert all(secret not in value for value in rendered)


def test_valid_redis_url_is_strictly_parsed_but_stored_as_a_masked_secret() -> None:
    settings = Settings(**VALID)

    assert isinstance(settings.redis_url, SecretStr)
    assert settings.redis_url.get_secret_value() == VALID["redis_url"]
    assert VALID["redis_url"] not in repr(settings)
    assert VALID["redis_url"] not in repr(settings.model_dump())
    assert VALID["redis_url"] not in repr(settings.model_dump(mode="json"))
    assert VALID["redis_url"] not in settings.model_dump_json()


def test_stale_idle_must_exceed_bounded_work_window_plus_safety_margin() -> None:
    with pytest.raises(ValidationError, match="stale_idle_ms must exceed"):
        Settings(
            **(
                VALID
                | {
                    "api_timeout_seconds": 1.0,
                    "diagnostic_total_timeout_seconds": 2.0,
                    "stale_idle_ms": 4_100,
                }
            )
        )

    settings = Settings(
        **(
            VALID
            | {
                "api_timeout_seconds": 1.0,
                "diagnostic_total_timeout_seconds": 2.0,
                "stale_idle_ms": 4_101,
            }
        )
    )
    assert settings.stale_idle_ms == 4_101
