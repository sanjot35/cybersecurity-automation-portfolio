"""
anomaly.py — Behavioural anomaly detection for threat hunting events

Strategies:
  1. Z-score frequency analysis  — flags (user, process) pairs that are
     statistically rare compared to the baseline window
  2. Rare process detection       — processes seen fewer than N times total
  3. Off-hours activity           — events outside 07:00–19:00 local time
  4. High fan-out detection       — single source IP connecting to many destinations
"""

from __future__ import annotations

import logging
import math
import re
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any

from .models import Anomaly, Event

logger = logging.getLogger("threat-hunt.anomaly")

# Tuning thresholds
ZSCORE_THRESHOLD = 2.0          # flag events > 2 std devs above mean frequency
RARE_PROCESS_MAX_COUNT = 3      # flag processes seen ≤ N times in the result set
FAN_OUT_THRESHOLD = 5           # flag source IPs hitting ≥ N distinct destinations
BUSINESS_HOURS_START = 7        # 07:00
BUSINESS_HOURS_END = 19         # 19:00


class AnomalyDetector:
    """
    Stateless anomaly detector — all context is derived from the event batch
    passed to detect().

    In production, replace in-batch baselines with pre-computed rolling
    baselines stored in Redis or QRadar reference sets.
    """

    def detect(self, raw_events: list[dict[str, Any]]) -> list[Anomaly]:
        """
        Run all anomaly strategies over a batch of raw QRadar events.

        Returns a deduplicated list of Anomaly objects, sorted by severity.
        """
        if not raw_events:
            return []

        events = [self._to_event(e) for e in raw_events]

        anomalies: list[Anomaly] = []
        anomalies.extend(self._zscore_frequency(events))
        anomalies.extend(self._rare_process(events))
        anomalies.extend(self._off_hours(events))
        anomalies.extend(self._fan_out(events))

        # Deduplicate by (username, hostname, process_name, reason prefix)
        seen: set[str] = set()
        deduped: list[Anomaly] = []
        for a in anomalies:
            key = f"{a.event.username}|{a.event.hostname}|{a.event.process_name}|{a.reason[:40]}"
            if key not in seen:
                seen.add(key)
                deduped.append(a)

        deduped.sort(key=lambda a: self._severity_rank(a.severity), reverse=True)
        logger.info("Anomaly detection: %d flagged from %d events", len(deduped), len(events))
        return deduped

    # -----------------------------------------------------------------------
    # Strategy 1: Z-score frequency analysis
    # -----------------------------------------------------------------------

    def _zscore_frequency(self, events: list[Event]) -> list[Anomaly]:
        """
        Build a (username, process_name) frequency counter and flag events
        where the count is an outlier (z-score > threshold).
        """
        freq: Counter[tuple[str, str]] = Counter()
        for e in events:
            key = (e.username or "unknown", e.process_name or "unknown")
            freq[key] += 1

        if len(freq) < 3:
            return []

        counts = list(freq.values())
        mean = sum(counts) / len(counts)
        variance = sum((c - mean) ** 2 for c in counts) / len(counts)
        std = math.sqrt(variance) if variance else 0

        if std == 0:
            return []

        anomalies: list[Anomaly] = []
        for e in events:
            key = (e.username or "unknown", e.process_name or "unknown")
            count = freq[key]
            zscore = (count - mean) / std
            if zscore > ZSCORE_THRESHOLD:
                anomalies.append(
                    Anomaly(
                        event=e,
                        reason=(
                            f"High-frequency execution: {e.process_name!r} by {e.username!r} "
                            f"seen {count}x (z={zscore:.1f})"
                        ),
                        severity="high" if zscore > 4 else "medium",
                        zscore=round(zscore, 2),
                    )
                )
        return anomalies

    # -----------------------------------------------------------------------
    # Strategy 2: Rare process detection
    # -----------------------------------------------------------------------

    def _rare_process(self, events: list[Event]) -> list[Anomaly]:
        """
        Flag processes that appear very rarely — a hallmark of living-off-the-land
        or first-use-of-a-binary attacks.
        """
        process_count: Counter[str] = Counter(
            e.process_name for e in events if e.process_name
        )

        # Known-noisy processes to suppress
        ignore = {
            "svchost.exe", "explorer.exe", "chrome.exe", "firefox.exe",
            "outlook.exe", "Teams.exe", "Code.exe",
        }

        anomalies: list[Anomaly] = []
        for e in events:
            proc = e.process_name or ""
            if proc in ignore:
                continue
            if 0 < process_count[proc] <= RARE_PROCESS_MAX_COUNT:
                anomalies.append(
                    Anomaly(
                        event=e,
                        reason=(
                            f"Rare process execution: {proc!r} seen only "
                            f"{process_count[proc]}x in this hunt window"
                        ),
                        severity="medium",
                    )
                )
        return anomalies

    # -----------------------------------------------------------------------
    # Strategy 3: Off-hours activity
    # -----------------------------------------------------------------------

    def _off_hours(self, events: list[Event]) -> list[Anomaly]:
        """
        Flag events occurring outside normal business hours.
        PowerShell or lateral-movement patterns at 03:00 are far more suspicious.
        """
        anomalies: list[Anomaly] = []
        for e in events:
            if not e.devicetime:
                continue
            hour = self._parse_hour(e.devicetime)
            if hour is None:
                continue
            if not (BUSINESS_HOURS_START <= hour < BUSINESS_HOURS_END):
                anomalies.append(
                    Anomaly(
                        event=e,
                        reason=(
                            f"Off-hours activity at {hour:02d}:xx by {e.username!r} "
                            f"on {e.hostname!r}"
                        ),
                        severity="medium",
                    )
                )
        return anomalies

    # -----------------------------------------------------------------------
    # Strategy 4: Fan-out detection (one source → many destinations)
    # -----------------------------------------------------------------------

    def _fan_out(self, events: list[Event]) -> list[Anomaly]:
        """
        Detect a single source IP communicating with an unusually large number
        of distinct destination IPs — indicative of scanning or worm propagation.
        """
        src_to_dests: dict[str, set[str]] = defaultdict(set)
        src_to_events: dict[str, list[Event]] = defaultdict(list)

        for e in events:
            if e.sourceip and e.destinationip:
                src_to_dests[e.sourceip].add(e.destinationip)
                src_to_events[e.sourceip].append(e)

        anomalies: list[Anomaly] = []
        for src_ip, dests in src_to_dests.items():
            if len(dests) >= FAN_OUT_THRESHOLD:
                # Only flag first event per source IP
                rep_event = src_to_events[src_ip][0]
                anomalies.append(
                    Anomaly(
                        event=rep_event,
                        reason=(
                            f"High fan-out: {src_ip} communicated with "
                            f"{len(dests)} distinct destinations "
                            f"(threshold={FAN_OUT_THRESHOLD})"
                        ),
                        severity="high",
                    )
                )
        return anomalies

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    @staticmethod
    def _to_event(raw: dict[str, Any]) -> Event:
        """Normalise a raw QRadar event dict into an Event model."""
        return Event(
            event_name=raw.get("event_name") or raw.get("QIDNAME(qid)"),
            username=raw.get("username"),
            sourceip=raw.get("sourceip"),
            destinationip=raw.get("destinationip"),
            category=raw.get("category") or raw.get("CATEGORYNAME(category)"),
            devicetime=str(raw.get("devicetime", "")),
            command_line=raw.get("command_line") or raw.get("Command Line"),
            hostname=raw.get("hostname"),
            process_name=raw.get("process_name") or raw.get("Process Name"),
            raw=raw,
        )

    @staticmethod
    def _parse_hour(devicetime: str) -> int | None:
        """Extract the hour from various QRadar timestamp formats."""
        formats = [
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%d/%m/%Y %H:%M:%S",
        ]
        clean = re.sub(r"Z$|\+\d{2}:\d{2}$", "", devicetime.strip())
        for fmt in formats:
            try:
                return datetime.strptime(clean, fmt).hour
            except ValueError:
                continue
        return None

    @staticmethod
    def _severity_rank(severity: str) -> int:
        return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(severity, 0)
