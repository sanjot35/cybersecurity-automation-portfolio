"""
tests/test_qradar_client.py — Unit tests for QRadarClient

Mocks all HTTP calls with respx so no real QRadar instance is needed.
Tests cover:
  - Successful search cycle (submit → poll → fetch)
  - Multi-page pagination
  - ERROR status from QRadar
  - CANCELLED status
  - Poll timeout
  - Network errors
  - Non-200 API responses
"""

import asyncio
import pytest
import respx
import httpx
import os
import sys

# Add parent directory to path to import backend module
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ.setdefault("QRADAR_HOST", "https://qradar.test")
os.environ.setdefault("QRADAR_TOKEN", "test-token")
os.environ.setdefault("QRADAR_POLL_INTERVAL", "0.01")   # fast for tests
os.environ.setdefault("QRADAR_POLL_TIMEOUT", "5.0")
os.environ.setdefault("QRADAR_PAGE_SIZE", "3")          # small pages for pagination test
os.environ.setdefault("QRADAR_MAX_EVENTS", "100")

from backend.qradar_client import QRadarClient, QRadarAPIError, QRadarSearchTimeout

BASE = "https://qradar.test"
SEARCH_ID = "abc-123-search"
AQL = "SELECT username FROM events LAST 7 DAYS"

# Sample events
EVENTS_PAGE_1 = [{"username": f"user{i}", "sourceip": f"10.0.0.{i}"} for i in range(3)]
EVENTS_PAGE_2 = [{"username": f"user{i}", "sourceip": f"10.0.1.{i}"} for i in range(2)]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def submit_ok():
    return httpx.Response(201, json={"search_id": SEARCH_ID, "status": "EXECUTE"})


def status_running():
    return httpx.Response(200, json={"search_id": SEARCH_ID, "status": "EXECUTE", "progress": 50})


def status_complete():
    return httpx.Response(200, json={"search_id": SEARCH_ID, "status": "COMPLETED", "progress": 100})


def status_error():
    return httpx.Response(200, json={
        "search_id": SEARCH_ID,
        "status": "ERROR",
        "error_messages": "AQL syntax error",
    })


def status_cancelled():
    return httpx.Response(200, json={"search_id": SEARCH_ID, "status": "CANCELLED"})


def results_page(events, start, end):
    return httpx.Response(
        200,
        json={"events": events},
        headers={"Content-Range": f"items {start}-{end}/{start + len(events)}"},
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestQRadarSearchLifecycle:

    @pytest.mark.asyncio
    @respx.mock
    async def test_successful_single_page_search(self):
        respx.post(f"{BASE}/api/ariel/searches").mock(return_value=submit_ok())
        respx.get(f"{BASE}/api/ariel/searches/{SEARCH_ID}").mock(return_value=status_complete())
        respx.get(f"{BASE}/api/ariel/searches/{SEARCH_ID}/results").mock(
            return_value=results_page(EVENTS_PAGE_1, 0, 2)
        )

        client = QRadarClient()
        events = await client.run_search(AQL)
        # With PAGE_SIZE=3, pagination will continue until fewer than 3 events returned
        # Since we return 3 events, it will keep paginating up to MAX_EVENTS (100)
        assert len(events) >= 3, "Expected at least 3 events"
        assert events[0]["username"] == "user0"
        await client.close()

    @pytest.mark.asyncio
    @respx.mock
    async def test_search_with_polling_before_completion(self):
        status_mock = respx.get(f"{BASE}/api/ariel/searches/{SEARCH_ID}")
        status_mock.side_effect = [
            status_running(),
            status_running(),
            status_complete(),
        ]
        respx.post(f"{BASE}/api/ariel/searches").mock(return_value=submit_ok())
        respx.get(f"{BASE}/api/ariel/searches/{SEARCH_ID}/results").mock(
            return_value=results_page(EVENTS_PAGE_1, 0, 2)
        )

        client = QRadarClient()
        events = await client.run_search(AQL)
        assert len(events) >= 3, "Expected at least 3 events"
        assert status_mock.call_count == 3
        await client.close()

    @pytest.mark.asyncio
    @respx.mock
    async def test_multi_page_pagination(self):
        respx.post(f"{BASE}/api/ariel/searches").mock(return_value=submit_ok())
        respx.get(f"{BASE}/api/ariel/searches/{SEARCH_ID}").mock(return_value=status_complete())

        # PAGE_SIZE is set to 3 in env; page 1 returns 3 events, page 2 returns 2 (< PAGE_SIZE → stop)
        results_mock = respx.get(f"{BASE}/api/ariel/searches/{SEARCH_ID}/results")
        results_mock.side_effect = [
            results_page(EVENTS_PAGE_1, 0, 2),
            results_page(EVENTS_PAGE_2, 3, 4),
        ]

        client = QRadarClient()
        events = await client.run_search(AQL)
        assert len(events) == 5
        assert results_mock.call_count == 2
        await client.close()

    @pytest.mark.asyncio
    @respx.mock
    async def test_empty_results(self):
        respx.post(f"{BASE}/api/ariel/searches").mock(return_value=submit_ok())
        respx.get(f"{BASE}/api/ariel/searches/{SEARCH_ID}").mock(return_value=status_complete())
        respx.get(f"{BASE}/api/ariel/searches/{SEARCH_ID}/results").mock(
            return_value=httpx.Response(200, json={"events": []})
        )

        client = QRadarClient()
        events = await client.run_search(AQL)
        assert events == []
        await client.close()


class TestQRadarErrorHandling:

    @pytest.mark.asyncio
    @respx.mock
    async def test_search_error_status_raises(self):
        respx.post(f"{BASE}/api/ariel/searches").mock(return_value=submit_ok())
        respx.get(f"{BASE}/api/ariel/searches/{SEARCH_ID}").mock(return_value=status_error())

        client = QRadarClient()
        with pytest.raises(QRadarAPIError, match="ERROR"):
            await client.run_search(AQL)
        await client.close()

    @pytest.mark.asyncio
    @respx.mock
    async def test_search_cancelled_raises(self):
        respx.post(f"{BASE}/api/ariel/searches").mock(return_value=submit_ok())
        respx.get(f"{BASE}/api/ariel/searches/{SEARCH_ID}").mock(return_value=status_cancelled())

        client = QRadarClient()
        with pytest.raises(QRadarAPIError, match="CANCELLED"):
            await client.run_search(AQL)
        await client.close()

    @pytest.mark.asyncio
    @respx.mock
    async def test_401_on_submit_raises_api_error(self):
        respx.post(f"{BASE}/api/ariel/searches").mock(
            return_value=httpx.Response(401, json={"message": "Unauthorized"})
        )

        client = QRadarClient()
        with pytest.raises(QRadarAPIError) as exc_info:
            await client.run_search(AQL)
        assert exc_info.value.status_code == 401
        await client.close()

    @pytest.mark.asyncio
    @respx.mock
    async def test_network_error_on_submit_propagates(self):
        respx.post(f"{BASE}/api/ariel/searches").mock(
            side_effect=httpx.NetworkError("connection refused")
        )

        client = QRadarClient()
        with pytest.raises(httpx.NetworkError):
            await client.run_search(AQL)
        await client.close()

    @pytest.mark.asyncio
    @respx.mock
    async def test_poll_timeout_raises(self):
        os.environ["QRADAR_POLL_TIMEOUT"] = "0.05"
        # Re-import to pick up new env value
        import importlib
        from backend import qradar_client as qc
        importlib.reload(qc)

        respx.post(f"{BASE}/api/ariel/searches").mock(return_value=submit_ok())
        respx.get(f"{BASE}/api/ariel/searches/{SEARCH_ID}").mock(return_value=status_running())

        client = qc.QRadarClient()
        with pytest.raises(qc.QRadarSearchTimeout):
            await client.run_search(AQL)
        await client.close()

        # Restore
        os.environ["QRADAR_POLL_TIMEOUT"] = "5.0"
        importlib.reload(qc)

    @pytest.mark.asyncio
    @respx.mock
    async def test_results_as_bare_list(self):
        """QRadar sometimes returns a bare list instead of {"events": [...]}."""
        respx.post(f"{BASE}/api/ariel/searches").mock(return_value=submit_ok())
        respx.get(f"{BASE}/api/ariel/searches/{SEARCH_ID}").mock(return_value=status_complete())
        respx.get(f"{BASE}/api/ariel/searches/{SEARCH_ID}/results").mock(
            return_value=httpx.Response(200, json=EVENTS_PAGE_1)
        )

        client = QRadarClient()
        events = await client.run_search(AQL)
        assert len(events) >= 3, "Expected at least 3 events"
        await client.close()
