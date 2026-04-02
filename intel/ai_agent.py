#!/usr/bin/env python3
"""
The Daily Brief - AI Agent Module
Provides executive-level summarization of threat intelligence feeds.

Primary provider: Anthropic Claude (claude-sonnet-4-6)
Fallback provider: Ollama (local, http://localhost:11434)
Graceful degradation: returns None if both providers fail.
"""

import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Anthropic SDK - optional import (same pattern as OTX/VT in aggregator)
try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False
    logger.debug("anthropic package not installed; Claude provider unavailable")

# requests is already a hard dependency of the main aggregator
try:
    import requests as _requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class AIAgent:
    """
    AI agent that generates executive threat intelligence summaries.

    Key behaviours:
    - Resolves the Anthropic API key from env var ANTHROPIC_API_KEY first,
      then falls back to api_keys.json anthropic.api_key.
    - Tries Claude first, then Ollama, then returns None.
    - Caches the last generated summary with a configurable TTL so repeated
      calls within the same aggregation window are cheap.
    - Never raises: all errors are caught and logged; callers always receive
      a result dict (with None values on failure).
    """

    DEFAULT_CLAUDE_MODEL = "claude-sonnet-4-6"
    DEFAULT_OLLAMA_MODEL = "llama3"
    DEFAULT_OLLAMA_BASE_URL = "http://localhost:11434"
    DEFAULT_MAX_ARTICLES = 20
    DEFAULT_CACHE_TTL_MINUTES = 25
    SUMMARY_CACHE_FILENAME = "ai_summary_cache.json"

    def __init__(self, project_dir: Path, ai_config: Dict):
        """
        Parameters
        ----------
        project_dir : Path
            Root directory of the project (where api_keys.json lives).
        ai_config : Dict
            The 'ai' section from platform_config.json.
        """
        self.project_dir = project_dir
        self.config = ai_config
        self.enabled = ai_config.get("enabled", True)
        self.cache_dir = project_dir / "data" / "ai_cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._cache_file = self.cache_dir / self.SUMMARY_CACHE_FILENAME

        # Provider settings
        self._primary = ai_config.get("primary_provider", "claude")
        self._fallback = ai_config.get("fallback_provider", "ollama")

        claude_cfg = ai_config.get("claude", {})
        self._claude_model = claude_cfg.get("model", self.DEFAULT_CLAUDE_MODEL)
        self._claude_max_tokens = int(claude_cfg.get("max_tokens", 1024))

        ollama_cfg = ai_config.get("ollama", {})
        self._ollama_base_url = ollama_cfg.get("base_url", self.DEFAULT_OLLAMA_BASE_URL).rstrip("/")
        self._ollama_model = ollama_cfg.get("model", self.DEFAULT_OLLAMA_MODEL)

        summ_cfg = ai_config.get("summarization", {})
        self._max_articles = int(summ_cfg.get("max_articles", self.DEFAULT_MAX_ARTICLES))
        self._summarization_enabled = summ_cfg.get("enabled", True)

        self._cache_ttl_minutes = int(
            ai_config.get("cache_ttl_minutes", self.DEFAULT_CACHE_TTL_MINUTES)
        )

        self._api_key: Optional[str] = self._resolve_anthropic_key()

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def summarize_feeds(self, articles: List[Dict], metadata: Dict) -> Dict:
        """
        Generate an executive daily brief from the supplied articles.

        Returns a dict with keys:
            ai_summary              : str or None
            ai_summary_generated_at : ISO timestamp str or None
            ai_provider_used        : 'claude' | 'ollama' | 'none'

        Never raises.
        """
        empty_result = {
            "ai_summary": None,
            "ai_summary_generated_at": None,
            "ai_provider_used": "none",
        }

        if not self.enabled or not self._summarization_enabled:
            logger.info("  AI summarization disabled by config")
            return empty_result

        try:
            # Check cache before doing expensive API calls
            cached = self._load_cache(len(articles))
            if cached:
                logger.info("  AI summary loaded from cache (TTL valid)")
                return cached

            prompt = self._build_prompt(articles, metadata)
            summary, provider = self._call_provider(prompt)

            if summary is None:
                logger.warning("  AI summarization: both providers failed or unavailable")
                return empty_result

            result = {
                "ai_summary": summary,
                "ai_summary_generated_at": datetime.utcnow().isoformat() + "Z",
                "ai_provider_used": provider,
            }
            self._save_cache(result, len(articles))
            logger.info(f"  AI summary generated via {provider} ({len(summary)} chars)")
            return result

        except Exception as exc:
            logger.error(f"  AI agent unexpected error: {exc}", exc_info=True)
            return empty_result

    # ------------------------------------------------------------------
    # Provider calls
    # ------------------------------------------------------------------

    def _call_provider(self, prompt: str) -> Tuple[Optional[str], str]:
        """Try primary provider then fallback. Returns (text, provider) or (None, 'none')."""
        provider_order = []
        if self._primary:
            provider_order.append(self._primary)
        if self._fallback and self._fallback != self._primary:
            provider_order.append(self._fallback)

        for provider in provider_order:
            if provider == "claude":
                result = self._call_claude(prompt)
                if result is not None:
                    return result, "claude"
            elif provider == "ollama":
                result = self._call_ollama(prompt)
                if result is not None:
                    return result, "ollama"

        return None, "none"

    def _call_claude(self, prompt: str) -> Optional[str]:
        """Call the Anthropic Claude API. Returns text or None on any failure."""
        if not ANTHROPIC_AVAILABLE:
            logger.debug("  Claude: anthropic package not available")
            return None
        if not self._api_key:
            logger.debug("  Claude: no API key configured")
            return None

        try:
            client = anthropic.Anthropic(api_key=self._api_key)
            message = client.messages.create(
                model=self._claude_model,
                max_tokens=self._claude_max_tokens,
                messages=[{"role": "user", "content": prompt}],
            )
            if message.content and len(message.content) > 0:
                block = message.content[0]
                if hasattr(block, "text"):
                    return block.text.strip()
            logger.warning("  Claude: unexpected empty response content")
            return None
        except Exception as exc:
            logger.warning(f"  Claude API error: {exc}")
            return None

    def _call_ollama(self, prompt: str) -> Optional[str]:
        """Call local Ollama API. Returns text or None on any failure."""
        if not REQUESTS_AVAILABLE:
            logger.debug("  Ollama: requests not available")
            return None

        endpoint = f"{self._ollama_base_url}/api/generate"
        payload = {"model": self._ollama_model, "prompt": prompt, "stream": False}
        try:
            response = _requests.post(endpoint, json=payload, timeout=60)
            response.raise_for_status()
            text = response.json().get("response", "").strip()
            if text:
                return text
            logger.warning("  Ollama: empty response body")
            return None
        except Exception as exc:
            logger.warning(f"  Ollama API error: {exc}")
            return None

    # ------------------------------------------------------------------
    # Prompt construction
    # ------------------------------------------------------------------

    def _build_prompt(self, articles: List[Dict], metadata: Dict) -> str:
        """Build the summarization prompt from the top-N articles by priority and recency."""
        defcon_level = metadata.get("defcon_level", "?")
        defcon_details = metadata.get("defcon_details", {})
        defcon_name = defcon_details.get("name", "UNKNOWN") if isinstance(defcon_details, dict) else "UNKNOWN"
        generated_at = metadata.get("generated_at", datetime.utcnow().isoformat())
        total_articles = metadata.get("total_articles", len(articles))

        # Sort: priority ascending (1=critical first), then recency descending
        sorted_articles = sorted(
            articles,
            key=lambda a: (a.get("priority", 99), -(self._iso_to_ts(a.get("published", "")))),
        )
        top_articles = sorted_articles[: self._max_articles]

        article_lines = []
        for i, art in enumerate(top_articles, start=1):
            title = art.get("title", "Untitled")
            source = art.get("source", "Unknown")
            category = art.get("category", "")
            summary = art.get("summary", "")
            cves = art.get("iocs", {}).get("cves", []) if isinstance(art.get("iocs"), dict) else []
            cve_str = f" CVEs: {', '.join(cves[:3])}." if cves else ""
            summary_snippet = f"\n   Summary: {summary[:200]}" if summary else ""
            article_lines.append(
                f"{i}. [{category}] {title} (Source: {source}){cve_str}{summary_snippet}"
            )

        articles_block = "\n".join(article_lines)

        prompt = f"""You are a senior threat intelligence analyst writing an executive daily brief.

Current threat landscape data:
- Report date: {generated_at[:10]}
- Current DEFCON level: {defcon_level} ({defcon_name})
- Total intelligence items processed: {total_articles}
- Top {len(top_articles)} items by priority and recency shown below:

{articles_block}

Write a concise 3-4 paragraph executive brief that:
1. Opens with the overall threat environment and DEFCON {defcon_level} context
2. Highlights the most significant active threats and campaigns
3. Calls out any critical vulnerabilities or active exploitation
4. Closes with a short recommended focus for security teams today

Write in plain prose. No bullet points. No markdown headers. No preamble. Start directly with the first paragraph.
Keep the total response under 500 words."""

        return prompt

    # ------------------------------------------------------------------
    # Caching
    # ------------------------------------------------------------------

    def _load_cache(self, current_article_count: int) -> Optional[Dict]:
        """Return cached result if within TTL and article count has not changed significantly."""
        if not self._cache_file.exists():
            return None
        try:
            with open(self._cache_file, encoding="utf-8") as f:
                cached = json.load(f)

            cached_at_str = cached.get("_cached_at")
            cached_count = cached.get("_article_count", 0)
            if not cached_at_str:
                return None

            cached_at = datetime.fromisoformat(cached_at_str.replace("Z", ""))
            age_minutes = (datetime.utcnow() - cached_at).total_seconds() / 60

            if age_minutes > self._cache_ttl_minutes:
                logger.debug(f"  AI cache expired ({age_minutes:.1f} min > {self._cache_ttl_minutes} min TTL)")
                return None

            # Significant change = more than 10% difference in article count
            if cached_count > 0:
                delta_pct = abs(current_article_count - cached_count) / cached_count
                if delta_pct > 0.10:
                    logger.debug(f"  AI cache invalidated: article count changed {cached_count} -> {current_article_count}")
                    return None

            return {
                "ai_summary": cached.get("ai_summary"),
                "ai_summary_generated_at": cached.get("ai_summary_generated_at"),
                "ai_provider_used": cached.get("ai_provider_used", "none"),
            }
        except Exception as exc:
            logger.debug(f"  AI cache read error: {exc}")
            return None

    def _save_cache(self, result: Dict, article_count: int) -> None:
        """Persist result to cache file with metadata."""
        try:
            payload = dict(result)
            payload["_cached_at"] = datetime.utcnow().isoformat() + "Z"
            payload["_article_count"] = article_count
            with open(self._cache_file, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
        except Exception as exc:
            logger.debug(f"  AI cache write error: {exc}")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _resolve_anthropic_key(self) -> Optional[str]:
        """
        Resolve Anthropic API key.
        Priority: env var ANTHROPIC_API_KEY > api_keys.json anthropic.api_key
        """
        env_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
        if env_key:
            return env_key

        api_keys_path = self.project_dir / "api_keys.json"
        if api_keys_path.exists():
            try:
                with open(api_keys_path, encoding="utf-8") as f:
                    keys = json.load(f)
                key = keys.get("anthropic", {}).get("api_key", "").strip()
                if key and not key.startswith("YOUR_"):
                    return key
            except (json.JSONDecodeError, IOError) as exc:
                logger.debug(f"  Could not read api_keys.json for Anthropic key: {exc}")

        return None

    @staticmethod
    def _iso_to_ts(iso_str: str) -> float:
        """Convert ISO datetime string to Unix timestamp float, 0.0 on failure."""
        if not iso_str:
            return 0.0
        try:
            dt = datetime.fromisoformat(iso_str.replace("Z", "").replace("+00:00", ""))
            return dt.timestamp()
        except (ValueError, AttributeError):
            return 0.0
