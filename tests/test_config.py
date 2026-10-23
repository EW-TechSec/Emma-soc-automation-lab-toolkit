import pytest

from soclab.config import load_settings


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for var in (
        "ABUSEIPDB_API_KEY",
        "VIRUSTOTAL_API_KEY",
        "OTX_API_KEY",
        "SOCLAB_OFFLINE",
        "SOCLAB_DRY_RUN",
        "SOCLAB_DATA_DIR",
    ):
        monkeypatch.delenv(var, raising=False)


def test_defaults_are_safe():
    s = load_settings(env_file=None)
    assert s.dry_run is True
    assert s.intel_mode("abuseipdb") == "mock"


def test_live_when_key_present(monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "abc123")
    s = load_settings(env_file=None)
    assert s.intel_mode("abuseipdb") == "live"
    assert s.intel_mode("virustotal") == "mock"


def test_offline_forces_mock_even_with_key(monkeypatch):
    monkeypatch.setenv("OTX_API_KEY", "abc123")
    monkeypatch.setenv("SOCLAB_OFFLINE", "1")
    assert load_settings(env_file=None).intel_mode("otx") == "mock"


def test_dry_run_can_be_disabled_explicitly(monkeypatch):
    monkeypatch.setenv("SOCLAB_DRY_RUN", "false")
    assert load_settings(env_file=None).dry_run is False


def test_unknown_provider_rejected():
    with pytest.raises(ValueError):
        load_settings(env_file=None).intel_mode("shodan")
