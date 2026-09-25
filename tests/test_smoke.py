import signaldesk_diagnostic_worker
from signaldesk_diagnostic_worker.settings import Settings


def test_package_imports() -> None:
    assert signaldesk_diagnostic_worker.__doc__
    assert "redis_url" in Settings.model_fields
