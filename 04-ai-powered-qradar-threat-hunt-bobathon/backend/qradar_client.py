"""
qradar_client.py — Async IBM QRadar REST API wrapper

Implements the two-phase AQL search pattern:
  1. POST /api/ariel/searches          → submit query, get search_id
  2. GET  /api/ariel/searches/{id}     → poll until status == COMPLETED
  3. GET  /api/ariel/searches/{id}/results → fetch paginated events

All calls use a SEC token header (QRadar API token).
"""

import asyncio
import logging
import os
from typing import Any

import httpx
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("threat-hunt.qradar")

# ---------------------------------------------------------------------------
# Config (loaded from environment / .env)
# ---------------------------------------------------------------------------
QRADAR_HOST = os.getenv("QRADAR_HOST", "https://qradar.example.com")
QRADAR_TOKEN = os.getenv("QRADAR_TOKEN", "")
QRADAR_VERIFY_SSL = os.getenv("QRADAR_VERIFY_SSL", "true").lower() == "true"

# Tuning knobs
POLL_INTERVAL_SECONDS = float(os.getenv("QRADAR_POLL_INTERVAL", "2.0"))
POLL_TIMEOUT_SECONDS = float(os.getenv("QRADAR_POLL_TIMEOUT", "120.0"))
PAGE_SIZE = int(os.getenv("QRADAR_PAGE_SIZE", "1000"))
MAX_EVENTS = int(os.getenv("QRADAR_MAX_EVENTS", "10000"))


class QRadarAPIError(Exception):
    """Raised when QRadar returns a non-2xx response."""

    def __init__(self, status_code: int, detail: str):
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"QRadar API error {status_code}: {detail}")


class QRadarSearchTimeout(Exception):
    """Raised when a search does not complete within the timeout."""


class QRadarClient:
    """
    Async client for IBM QRadar Ariel REST API.

    Usage:
        client = QRadarClient()
        events = await client.run_search("SELECT * FROM events LAST 7 DAYS")
        await client.close()
    """

    def __init__(self):
        if not QRADAR_TOKEN:
            logger.warning(
                "QRADAR_TOKEN is not set — requests will fail against a real instance"
            )
        self._client = httpx.AsyncClient(
            base_url=QRADAR_HOST,
            headers={
                "SEC": QRADAR_TOKEN,
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Version": "20.0",
            },
            verify=QRADAR_VERIFY_SSL,
            timeout=httpx.Timeout(30.0),
        )

    async def close(self):
        await self._client.aclose()

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    async def run_search(self, aql: str) -> list[dict[str, Any]]:
        """
        Full search cycle: submit → poll → fetch all pages.

        Returns a flat list of event dicts.
        """
        search_id = await self._submit_search(aql)
        logger.info("Search submitted: %s", search_id)

        await self._wait_for_completion(search_id)
        logger.info("Search completed: %s", search_id)

        events = await self._fetch_all_results(search_id)
        logger.info("Fetched %d events for search %s", len(events), search_id)
        return events

    async def get_offense(self, offense_id: int) -> dict[str, Any]:
        """Fetch a single QRadar offense by ID."""
        resp = await self._get(f"/api/siem/offenses/{offense_id}")
        return resp

    async def list_offenses(
        self,
        status: str = "OPEN",
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """List QRadar offenses filtered by status."""
        resp = await self._get(
            "/api/siem/offenses",
            params={"filter": f"status={status}", "Range": f"items=0-{limit - 1}"},
        )
        return resp if isinstance(resp, list) else []

    # -----------------------------------------------------------------------
    # Internal helpers — search lifecycle
    # -----------------------------------------------------------------------

    async def _submit_search(self, aql: str) -> str:
        """POST the AQL query and return the search_id."""
        data = await self._post("/api/ariel/searches", json={"query_expression": aql})
        search_id = data.get("search_id")
        if not search_id:
            raise QRadarAPIError(0, f"No search_id in response: {data}")
        return search_id

    async def _wait_for_completion(self, search_id: str) -> None:
        """
        Poll GET /api/ariel/searches/{search_id} until status is COMPLETED or ERROR.
        Raises QRadarSearchTimeout if it takes too long.
        Raises QRadarAPIError if QRadar reports an error status.
        """
        deadline = asyncio.get_event_loop().time() + POLL_TIMEOUT_SECONDS
        while True:
            status_data = await self._get(f"/api/ariel/searches/{search_id}")
            status = status_data.get("status", "").upper()
            progress = status_data.get("progress", 0)

            logger.debug(
                "Search %s  status=%s  progress=%d%%", search_id, status, progress
            )

            if status == "COMPLETED":
                return
            if status in ("ERROR", "CANCELLED"):
                msg = status_data.get("error_messages", status)
                raise QRadarAPIError(0, f"Search {search_id} ended with status {status}: {msg}")

            if asyncio.get_event_loop().time() > deadline:
                raise QRadarSearchTimeout(
                    f"Search {search_id} did not complete within {POLL_TIMEOUT_SECONDS}s"
                )

            await asyncio.sleep(POLL_INTERVAL_SECONDS)

    async def _fetch_all_results(self, search_id: str) -> list[dict[str, Any]]:
        """
        Paginate through GET /api/ariel/searches/{search_id}/results
        until all events are retrieved or MAX_EVENTS is reached.
        """
        all_events: list[dict[str, Any]] = []
        start = 0

        while True:
            end = start + PAGE_SIZE - 1
            page = await self._get(
                f"/api/ariel/searches/{search_id}/results",
                headers={"Range": f"items={start}-{end}"},
            )

            # Results are wrapped: {"events": [...]} or just a list
            if isinstance(page, dict):
                batch = page.get("events", [])
            else:
                batch = page or []

            all_events.extend(batch)
            logger.debug(
                "Fetched page %d-%d (%d events, total so far %d)",
                start,
                end,
                len(batch),
                len(all_events),
            )

            # Stop if last page returned fewer items than PAGE_SIZE
            if len(batch) < PAGE_SIZE or len(all_events) >= MAX_EVENTS:
                break

            start += PAGE_SIZE

        return all_events[:MAX_EVENTS]

    # -----------------------------------------------------------------------
    # Low-level HTTP methods
    # -----------------------------------------------------------------------

    async def _get(
        self,
        path: str,
        params: dict | None = None,
        headers: dict | None = None,
    ) -> Any:
        resp = await self._client.get(path, params=params, headers=headers)
        return self._handle(resp)

    async def _post(self, path: str, json: dict | None = None) -> Any:
        resp = await self._client.post(path, json=json)
        return self._handle(resp)

    @staticmethod
    def _handle(resp: httpx.Response) -> Any:
        if resp.status_code >= 400:
            try:
                detail = resp.json().get("message", resp.text)
            except Exception:
                detail = resp.text
            raise QRadarAPIError(resp.status_code, detail)
        try:
            return resp.json()
        except Exception:
            return {}
