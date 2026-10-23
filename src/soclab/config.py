"""Central configuration.

Every module reads settings from here instead of calling os.environ itself, so
there is one place that decides:

* whether threat-intel lookups hit the real APIs ("live") or recorded fixtures ("mock")
* whether response actions are executed or only logged (dry-run, the default)
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from dotenv import load_dotenv

IntelMode = Literal["live", "mock"]

PROVIDER_KEY_VARS = {
    "abuseipdb": "ABUSEIPDB_API_KEY",
    "virustotal": "VIRUSTOTAL_API_KEY",
    "otx": "OTX_API_KEY",
}

_TRUE = {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    api_keys: dict[str, str]
    offline: bool
    dry_run: bool
    data_dir: Path

    def intel_mode(self, provider: str) -> IntelMode:
        """Live only if we are online AND have a key for this provider."""
        if provider not in PROVIDER_KEY_VARS:
            raise ValueError(f"Unknown threat-intel provider: {provider!r}")
        if self.offline or not self.api_keys.get(provider):
            return "mock"
        return "live"


def load_settings(env_file: str | Path | None = ".env") -> Settings:
    if env_file:
        load_dotenv(env_file, override=False)

    keys = {p: os.getenv(var, "").strip() for p, var in PROVIDER_KEY_VARS.items()}
    return Settings(
        api_keys={p: k for p, k in keys.items() if k},
        offline=os.getenv("SOCLAB_OFFLINE", "").lower() in _TRUE,
        # Safe by default: destructive actions need an explicit opt-out.
        dry_run=os.getenv("SOCLAB_DRY_RUN", "true").lower() in _TRUE,
        data_dir=Path(os.getenv("SOCLAB_DATA_DIR", "data")),
    )
