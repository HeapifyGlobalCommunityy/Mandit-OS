import pytest


@pytest.fixture(autouse=True)
def _no_real_lookups(monkeypatch):
    """Tests never call outside services or depend on the developer's API keys."""
    monkeypatch.setenv("MANDIT_LIVE_LOOKUPS", "off")
    for name in ("VIRUS_TOTAL_API_KEY", "VIRUSTOTAL_API_KEY", "GOOGLE_SAFE_BROWSING_API_KEY"):
        monkeypatch.delenv(name, raising=False)
