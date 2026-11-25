"""
tests/test_query_builder.py — Unit tests for LLMEngine AQL generation

Uses pytest-asyncio + respx (httpx mock) to test all code paths
without a real LLM or QRadar instance.

Run with:
    pytest tests/ -v
"""

import pytest
import pytest_asyncio
import respx
import httpx

import sys
import os

# Add parent directory to path to import backend module
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from backend.llm_engine import LLMEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine():
    """LLMEngine instance with a dummy API key so it tries the LLM path."""
    os.environ["LLM_API_KEY"] = "test-key"
    os.environ["LLM_API_URL"] = "https://mock-llm.example.com/generate"
    os.environ["LLM_MODEL"] = "test-model"
    eng = LLMEngine()
    yield eng


# ---------------------------------------------------------------------------
# Keyword fallback tests (no LLM involved)
# ---------------------------------------------------------------------------

class TestKeywordFallback:

    def setup_method(self):
        os.environ.pop("LLM_API_KEY", None)
        self.engine = LLMEngine()

    @pytest.mark.asyncio
    async def test_powershell_keywords_produce_aql(self):
        aql = await self.engine.generate_aql("Find PowerShell abuse", days=7)
        assert "FROM events" in aql
        assert "powershell" in aql.lower()
        assert "7 DAYS" in aql

    @pytest.mark.asyncio
    async def test_lateral_movement_keywords(self):
        aql = await self.engine.generate_aql("Detect lateral movement via psexec", days=14)
        assert "psexec" in aql.lower()
        assert "14 DAYS" in aql

    @pytest.mark.asyncio
    async def test_privilege_escalation_keywords(self):
        aql = await self.engine.generate_aql("Find privilege escalation attempts", days=3)
        assert "runas" in aql.lower() or "seimpersonate" in aql.lower()

    @pytest.mark.asyncio
    async def test_ransomware_keywords(self):
        aql = await self.engine.generate_aql("Hunt for ransomware encryption activity", days=1)
        assert "vssadmin" in aql.lower() or "bcdedit" in aql.lower()

    @pytest.mark.asyncio
    async def test_generic_query_still_valid_aql(self):
        aql = await self.engine.generate_aql("Look for anything suspicious", days=7)
        assert aql.strip().upper().startswith("SELECT")
        assert "FROM events" in aql
        assert "ORDER BY devicetime DESC" in aql

    @pytest.mark.asyncio
    async def test_days_parameter_respected(self):
        for days in [1, 30, 90]:
            aql = await self.engine.generate_aql("PowerShell hunt", days=days)
            assert f"{days} DAYS" in aql


# ---------------------------------------------------------------------------
# LLM path tests (mocked HTTP)
# ---------------------------------------------------------------------------

class TestLLMPath:

    MOCK_AQL = (
        "SELECT QIDNAME(qid) as event_name, username, sourceip\n"
        "FROM events\n"
        "WHERE devicetime > NOW() - 7 DAYS\n"
        "  AND LOWER(\"Process Name\") LIKE '%powershell%'\n"
        "ORDER BY devicetime DESC"
    )

    @pytest.mark.asyncio
    @respx.mock
    async def test_successful_llm_response(self, engine):
        respx.post("https://mock-llm.example.com/generate").mock(
            return_value=httpx.Response(
                200,
                json={"results": [{"generated_text": self.MOCK_AQL}]},
            )
        )
        aql = await engine.generate_aql("Find PowerShell lateral movement", days=7)
        assert "FROM events" in aql
        assert "powershell" in aql.lower()

    @pytest.mark.asyncio
    @respx.mock
    async def test_llm_strips_markdown_fences(self, engine):
        fenced = f"```sql\n{self.MOCK_AQL}\n```"
        respx.post("https://mock-llm.example.com/generate").mock(
            return_value=httpx.Response(
                200,
                json={"results": [{"generated_text": fenced}]},
            )
        )
        aql = await engine.generate_aql("PowerShell hunt", days=7)
        assert "```" not in aql
        assert aql.strip().upper().startswith("SELECT")

    @pytest.mark.asyncio
    @respx.mock
    async def test_llm_injects_time_filter_if_missing(self, engine):
        no_time = (
            "SELECT username FROM events\n"
            "WHERE LOWER(\"Process Name\") LIKE '%powershell%'\n"
            "ORDER BY devicetime DESC"
        )
        respx.post("https://mock-llm.example.com/generate").mock(
            return_value=httpx.Response(
                200,
                json={"results": [{"generated_text": no_time}]},
            )
        )
        aql = await engine.generate_aql("PowerShell hunt", days=14)
        assert "NOW()" in aql or "LAST" in aql.upper()

    @pytest.mark.asyncio
    @respx.mock
    async def test_api_timeout_falls_back_to_keyword(self, engine):
        respx.post("https://mock-llm.example.com/generate").mock(
            side_effect=httpx.TimeoutException("timed out")
        )
        aql = await engine.generate_aql("PowerShell hunt", days=7)
        # Should fall back to keyword-based template
        assert "FROM events" in aql
        assert "7 DAYS" in aql

    @pytest.mark.asyncio
    @respx.mock
    async def test_api_500_falls_back_to_keyword(self, engine):
        respx.post("https://mock-llm.example.com/generate").mock(
            return_value=httpx.Response(500, text="Internal Server Error")
        )
        aql = await engine.generate_aql("PowerShell hunt", days=7)
        assert "FROM events" in aql

    @pytest.mark.asyncio
    @respx.mock
    async def test_empty_llm_response_falls_back(self, engine):
        respx.post("https://mock-llm.example.com/generate").mock(
            return_value=httpx.Response(200, json={"results": [{"generated_text": ""}]})
        )
        aql = await engine.generate_aql("PowerShell hunt", days=7)
        assert "FROM events" in aql

    @pytest.mark.asyncio
    @respx.mock
    async def test_openai_compatible_response_schema(self, engine):
        """Test that OpenAI-style response schema is also handled."""
        respx.post("https://mock-llm.example.com/generate").mock(
            return_value=httpx.Response(
                200,
                json={
                    "choices": [
                        {"message": {"content": self.MOCK_AQL}}
                    ]
                },
            )
        )
        aql = await engine.generate_aql("Find lateral movement", days=7)
        assert "FROM events" in aql
