"""Operator switch that stops the admin panel contacting vendor hosts.

Two admin endpoints originate outbound requests without a user asking:
the dashboard polls ``/api/update-check`` hourly (GitHub Releases) and
``/api/presets/refresh`` proxies omlx.ai. Neither carries operator data,
but both reveal the server's address and uptime pattern to a third party.

These tests hold the switch to its contract: when OMLX_OFFLINE is set, no
request is attempted at all (a stub raises if one is), and the endpoints
still answer in the shape their callers already handle. When it is unset,
the calls go out as before — a switch that silently blocked traffic in
both directions would be just as wrong.
"""

import os

import pytest
from fastapi import HTTPException

from omlx.admin import routes


class _ExplodingGet:
    """Stands in for requests.get; fails the test if anything calls it."""

    def __init__(self):
        self.called = False

    def __call__(self, *args, **kwargs):
        self.called = True
        raise AssertionError(f"offline mode still issued a request: {args}")


@pytest.fixture(autouse=True)
def _clear_offline_env(monkeypatch):
    monkeypatch.delenv(routes.OFFLINE_MODE_ENV, raising=False)
    routes._update_cache = {}
    routes._update_cache_time = {}
    yield
    routes._update_cache = {}
    routes._update_cache_time = {}


class TestOfflineModeSwitch:
    def test_unset_is_online(self):
        assert routes.offline_mode() is False

    @pytest.mark.parametrize("value", ["1", "true", "TRUE", "yes", "on", "enabled"])
    def test_truthy_values_enable(self, monkeypatch, value):
        monkeypatch.setenv(routes.OFFLINE_MODE_ENV, value)
        assert routes.offline_mode() is True

    @pytest.mark.parametrize("value", ["", "0", "false", "no", "off", "  "])
    def test_falsy_values_stay_online(self, monkeypatch, value):
        monkeypatch.setenv(routes.OFFLINE_MODE_ENV, value)
        assert routes.offline_mode() is False

    def test_read_per_call_not_at_import(self, monkeypatch):
        # The value is read on each call so an operator can flip it without
        # restarting the server.
        assert routes.offline_mode() is False
        monkeypatch.setenv(routes.OFFLINE_MODE_ENV, "1")
        assert routes.offline_mode() is True


class TestUpdateCheckOffline:
    async def test_offline_makes_no_request(self, monkeypatch):
        monkeypatch.setenv(routes.OFFLINE_MODE_ENV, "1")
        exploding = _ExplodingGet()
        monkeypatch.setattr(routes.requests, "get", exploding)

        result = await routes.check_update(is_admin=True)

        assert exploding.called is False
        # The shape the dashboard already handles, so the UI reports
        # "no update" rather than an error banner.
        assert result["update_available"] is False
        assert result["latest_version"] is None
        assert result["release_url"] is None
        assert result["update_channel"] == "stable"

    async def test_offline_answer_is_not_cached(self, monkeypatch):
        # An offline reply must not become the cached reply for a later
        # online call, or turning the switch off would look like it did
        # nothing until the 24h TTL expired.
        monkeypatch.setenv(routes.OFFLINE_MODE_ENV, "1")
        monkeypatch.setattr(routes.requests, "get", _ExplodingGet())
        await routes.check_update(is_admin=True)

        assert routes._update_cache == {}
        assert routes._update_cache_time == {}

    async def test_online_still_checks(self, monkeypatch):
        # Guards against the switch inverting: with it unset the request
        # must still go out.
        calls = []

        class _Resp:
            status_code = 200

            @staticmethod
            def json():
                return []

        def _fake_get(url, **kwargs):
            calls.append(url)
            return _Resp()

        monkeypatch.setattr(routes.requests, "get", _fake_get)
        await routes.check_update(is_admin=True)

        assert len(calls) == 1
        assert "api.github.com" in calls[0]


class TestPresetRefreshOffline:
    async def test_offline_makes_no_request(self, monkeypatch):
        monkeypatch.setenv(routes.OFFLINE_MODE_ENV, "1")
        exploding = _ExplodingGet()
        monkeypatch.setattr(routes.requests, "get", exploding)

        with pytest.raises(HTTPException) as excinfo:
            await routes.refresh_presets(is_admin=True)

        assert exploding.called is False
        # 502 is what the client already treats as "fall back to the
        # bundled presets", so offline mode degrades quietly.
        assert excinfo.value.status_code == 502
        assert routes.OFFLINE_MODE_ENV in str(excinfo.value.detail)

    async def test_online_still_fetches(self, monkeypatch):
        calls = []

        class _Resp:
            status_code = 200

            @staticmethod
            def json():
                return {"presets": []}

        def _fake_get(url, **kwargs):
            calls.append(url)
            return _Resp()

        monkeypatch.setattr(routes.requests, "get", _fake_get)
        result = await routes.refresh_presets(is_admin=True)

        assert calls == [routes.PRESET_REMOTE_URL]
        assert result == {"presets": []}


class TestEnvNameStability:
    def test_switch_name(self):
        # The name is documented for operators; renaming it silently would
        # leave a deployment believing it is offline when it is not.
        assert routes.OFFLINE_MODE_ENV == "OMLX_OFFLINE"
        assert os.getenv("OMLX_OFFLINE") is None
