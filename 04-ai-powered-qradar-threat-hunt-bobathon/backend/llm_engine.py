"""
llm_engine.py — Natural language → QRadar AQL via LLM

Uses the IBM watsonx.ai (or any OpenAI-compatible) API.
The system prompt was refined iteratively with Bob during development.
"""

import logging
import os
import re

import httpx
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("threat-hunt.llm")

LLM_API_URL = os.getenv("LLM_API_URL", "https://eu-de.ml.cloud.ibm.com/ml/v1/text/generation")
LLM_API_KEY = os.getenv("LLM_API_KEY", "")
LLM_MODEL = os.getenv("LLM_MODEL", "ibm/granite-13b-instruct-v2")
LLM_MAX_TOKENS = int(os.getenv("LLM_MAX_TOKENS", "512"))

# ---------------------------------------------------------------------------
# Bob-refined system prompt (iterated over 4 sessions with Bob)
# ---------------------------------------------------------------------------
AQL_SYSTEM_PROMPT = """\
You are an expert IBM QRadar AQL query writer for a threat hunting platform.

RULES:
1. Return ONLY the AQL query — no explanation, no markdown fences, no comments.
2. Always use the correct time filter: LAST {days} DAYS
3. Target table: events (never flows unless specifically asked)
4. Always SELECT: QIDNAME(qid) as event_name, username, sourceip, destinationip,
   CATEGORYNAME(category) as category, devicetime, "Command Line" as command_line,
   hostname, "Process Name" as process_name
5. Use WHERE to filter. Always include: devicetime > NOW() - {days} DAYS
6. For PowerShell hunting: filter on LOWER("Process Name") LIKE '%powershell%'
   OR LOWER("Command Line") LIKE '%invoke%'
   OR LOWER("Command Line") LIKE '%-encodedcommand%'
7. For lateral movement: look for net use, psexec, wmiexec, winrm, smbexec patterns
   in Command Line, plus logon type 3 (network logon) events
8. For privilege escalation: look for token impersonation, runas, scheduled task creation
9. ORDER BY devicetime DESC
10. Never use subqueries; use JOINs or REFERENCEVALUE() only when essential

EXAMPLE:
Hypothesis: "Find suspicious PowerShell lateral movement in last 7 days"
AQL:
SELECT QIDNAME(qid) as event_name, username, sourceip, destinationip,
       CATEGORYNAME(category) as category, devicetime,
       "Command Line" as command_line, hostname, "Process Name" as process_name
FROM events
WHERE devicetime > NOW() - 7 DAYS
  AND (
    LOWER("Process Name") LIKE '%powershell%'
    OR LOWER("Command Line") LIKE '%-encodedcommand%'
    OR LOWER("Command Line") LIKE '%invoke-command%'
    OR LOWER("Command Line") LIKE '%new-pssession%'
  )
  AND (
    logontype = '3'
    OR LOWER("Command Line") LIKE '%net use%'
    OR LOWER("Command Line") LIKE '%psexec%'
  )
ORDER BY devicetime DESC
"""

FALLBACK_AQL_TEMPLATE = """\
SELECT QIDNAME(qid) as event_name, username, sourceip, destinationip,
       CATEGORYNAME(category) as category, devicetime,
       "Command Line" as command_line, hostname, "Process Name" as process_name
FROM events
WHERE devicetime > NOW() - {days} DAYS
ORDER BY devicetime DESC
"""


class LLMEngine:
    """
    Translates natural-language threat hypotheses into QRadar AQL queries.

    Falls back to a generic SELECT if the LLM API is unavailable.
    """

    def __init__(self):
        if not LLM_API_KEY:
            logger.warning("LLM_API_KEY not set — will use fallback AQL templates")
        self._client = httpx.AsyncClient(
            headers={
                "Authorization": f"Bearer {LLM_API_KEY}",
                "Content-Type": "application/json",
            },
            timeout=httpx.Timeout(30.0),
        )

    async def generate_aql(self, query_text: str, days: int = 7) -> str:
        """
        Convert a natural-language hunting hypothesis into AQL.

        Args:
            query_text: Plain English hypothesis from the analyst
            days:       Look-back window in days

        Returns:
            A valid QRadar AQL query string
        """
        if not LLM_API_KEY:
            logger.info("No LLM key — returning keyword-matched AQL template")
            return self._keyword_fallback(query_text, days)

        prompt = self._build_prompt(query_text, days)
        try:
            aql = await self._call_llm(prompt)
            aql = self._sanitise(aql, days)
            logger.info("LLM generated AQL (%d chars)", len(aql))
            return aql
        except Exception as exc:
            logger.warning("LLM call failed (%s) — using keyword fallback", exc)
            return self._keyword_fallback(query_text, days)

    async def close(self):
        await self._client.aclose()

    # -----------------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------------

    def _build_prompt(self, query_text: str, days: int) -> str:
        system = AQL_SYSTEM_PROMPT.format(days=days)
        return (
            f"{system}\n\n"
            f"Now convert this hypothesis:\n"
            f'Hypothesis: "{query_text}"\n'
            f"Time window: {days} days\n"
            f"AQL:"
        )

    async def _call_llm(self, prompt: str) -> str:
        """Call the configured LLM endpoint and return the generated text."""
        payload = {
            "model_id": LLM_MODEL,
            "input": prompt,
            "parameters": {
                "decoding_method": "greedy",
                "max_new_tokens": LLM_MAX_TOKENS,
                "stop_sequences": ["\n\n", "Hypothesis:"],
            },
        }
        resp = await self._client.post(LLM_API_URL, json=payload)
        resp.raise_for_status()
        data = resp.json()
        # watsonx.ai response schema
        results = data.get("results", [])
        if results:
            return results[0].get("generated_text", "").strip()
        # OpenAI-compatible fallback
        choices = data.get("choices", [])
        if choices:
            return choices[0].get("message", {}).get("content", "").strip()
        raise ValueError(f"Unexpected LLM response schema: {list(data.keys())}")

    def _sanitise(self, aql: str, days: int) -> str:
        """
        Strip markdown fences and ensure the query has the mandatory time filter.
        """
        # Strip ```sql ... ``` or ``` ... ``` fences
        aql = re.sub(r"```[a-z]*\n?", "", aql).strip()

        # Ensure it starts with SELECT
        if not aql.upper().startswith("SELECT"):
            # Try to extract a SELECT block
            match = re.search(r"(SELECT\b.+)", aql, re.IGNORECASE | re.DOTALL)
            if match:
                aql = match.group(1).strip()
            else:
                logger.warning("LLM output did not contain SELECT — using fallback")
                return FALLBACK_AQL_TEMPLATE.format(days=days)

        # Ensure time filter present
        if "NOW()" not in aql.upper() and "LAST" not in aql.upper():
            # Inject before ORDER BY or at end
            time_clause = f"  AND devicetime > NOW() - {days} DAYS\n"
            if "ORDER BY" in aql.upper():
                aql = re.sub(
                    r"(ORDER BY)", time_clause + r"\1", aql, flags=re.IGNORECASE
                )
            else:
                aql += f"\n{time_clause}"

        return aql

    def _keyword_fallback(self, query_text: str, days: int) -> str:
        """
        Simple keyword-matched AQL builder used when LLM is unavailable.
        Covers the most common threat hunting patterns.
        """
        lower = query_text.lower()
        filters: list[str] = [f"devicetime > NOW() - {days} DAYS"]

        # PowerShell indicators
        if "powershell" in lower:
            filters.append(
                "(LOWER(\"Process Name\") LIKE '%powershell%' "
                "OR LOWER(\"Command Line\") LIKE '%-encodedcommand%' "
                "OR LOWER(\"Command Line\") LIKE '%invoke-%')"
            )

        # Lateral movement indicators
        if any(k in lower for k in ["lateral", "movement", "psexec", "wmi", "smb"]):
            filters.append(
                "(LOWER(\"Command Line\") LIKE '%psexec%' "
                "OR LOWER(\"Command Line\") LIKE '%wmiexec%' "
                "OR LOWER(\"Command Line\") LIKE '%net use%' "
                "OR logontype = '3')"
            )

        # Privilege escalation
        if any(k in lower for k in ["privilege", "escalation", "token", "runas"]):
            filters.append(
                "(LOWER(\"Command Line\") LIKE '%runas%' "
                "OR LOWER(\"Command Line\") LIKE '%seimpersonateprivilege%')"
            )

        # Ransomware / encryption
        if any(k in lower for k in ["ransom", "encrypt", "shadow copy"]):
            filters.append(
                "(LOWER(\"Command Line\") LIKE '%vssadmin%' "
                "OR LOWER(\"Command Line\") LIKE '%wbadmin%' "
                "OR LOWER(\"Command Line\") LIKE '%bcdedit%')"
            )

        where_clause = " AND\n  ".join(filters)

        return (
            "SELECT QIDNAME(qid) as event_name, username, sourceip, destinationip,\n"
            "       CATEGORYNAME(category) as category, devicetime,\n"
            "       \"Command Line\" as command_line, hostname, \"Process Name\" as process_name\n"
            "FROM events\n"
            f"WHERE {where_clause}\n"
            "ORDER BY devicetime DESC"
        )
