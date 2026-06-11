"""Central configuration for CVEzD3FEND, loaded from environment / .env.

See contracts/BUNDLE_CONTRACT.md and docs/OPERATIONS.md for the meaning of
each setting.
"""

from __future__ import annotations

import datetime as _dt
from pathlib import Path

from dotenv import load_dotenv
from pydantic_settings import BaseSettings, SettingsConfigDict

# Provider API keys (ANTHROPIC_API_KEY, OPENAI_API_KEY, GEMINI_API_KEY,
# LOCAL_OPENAI_*) are read directly from os.environ by intelligence/providers/*
# (unprefixed, per AI_ASSISTANCE_CONTRACT). pydantic-settings only loads
# CVEZD3FEND_*-prefixed values from .env into Settings, so load .env into the
# process environment too -- without this, keys placed in .env are inert.
load_dotenv()


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="CVEZD3FEND_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Paths ---
    data_dir: Path = Path("data")

    # --- Build window ---
    reference_date: str | None = None
    max_cves_per_year: int = 200
    top_routes_per_cve: int = 3
    max_gaps_per_reason: int = 50
    max_framework_routes: int = 1000

    # --- HTTP ---
    http_timeout_seconds: float = 30.0
    http_max_bytes: int = 25 * 1024 * 1024

    # --- Optional collectors ---
    enable_kev: bool = False
    enable_epss: bool = False
    enable_live_enrichment: bool = False
    enrichment_cache_limit: int = 20
    nvd_api_key: str | None = None
    github_token: str | None = None

    # --- AI / intelligence ---
    ai_enabled: bool = False
    ai_provider: str = "mock"
    ai_model: str | None = None
    rag_vector_store: bool = False

    # --- Optional API sidecar ---
    api_host: str = "127.0.0.1"
    api_port: int = 8000

    # --- Static serve ---
    serve_port: int = 8787

    @property
    def raw_dir(self) -> Path:
        return self.data_dir / "raw"

    @property
    def sources_dir(self) -> Path:
        return self.raw_dir / "sources"

    @property
    def reference_dir(self) -> Path:
        return self.raw_dir / "reference"

    @property
    def cache_dir(self) -> Path:
        return self.data_dir / "cache"

    @property
    def dist_dir(self) -> Path:
        return self.data_dir / "dist"

    @property
    def review_dir(self) -> Path:
        return self.data_dir / "review"

    @property
    def bundle_path(self) -> Path:
        return self.dist_dir / "knowledge-bundle.json"

    @property
    def quality_report_path(self) -> Path:
        return self.dist_dir / "quality-report.json"

    @property
    def promoted_edges_path(self) -> Path:
        return self.dist_dir / "promoted-edges.json"

    @property
    def ai_candidates_path(self) -> Path:
        return self.review_dir / "ai-candidates.jsonl"

    def reference_datetime(self) -> _dt.datetime:
        if self.reference_date:
            return _dt.datetime.fromisoformat(self.reference_date).replace(
                tzinfo=_dt.timezone.utc
            )
        return _dt.datetime.now(tz=_dt.timezone.utc)

    def ensure_dirs(self) -> None:
        for d in (
            self.sources_dir,
            self.reference_dir,
            self.cache_dir,
            self.dist_dir,
            self.review_dir,
            self.data_dir / "examples",
        ):
            d.mkdir(parents=True, exist_ok=True)


def get_settings() -> Settings:
    return Settings()
