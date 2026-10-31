"""
config.py - Environment settings and per-repo policy parsing (.diffshield.yml).

Trust boundary: per-repo policy is always read from the repository's BASE commit,
never the PR head. A pull request must never relax the policy that judges it.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

import yaml

logger = logging.getLogger("diffshield.config")


@dataclass
class Settings:
    """Application runtime settings from environment."""
    github_app_id: str = ""
    github_private_key_path: str = ""
    github_private_key: str = ""
    github_webhook_secret: str = ""
    dry_run: bool = False
    db_path: str = "diffshield.db"
    default_hold_hours: int = 12
    host: str = "0.0.0.0"
    port: int = 8000

    @classmethod
    def from_env(cls) -> Settings:
        app_id = os.getenv("GITHUB_APP_ID", "")
        key_path = os.getenv("GITHUB_PRIVATE_KEY_PATH", "")
        raw_key = os.getenv("GITHUB_PRIVATE_KEY", "")
        if key_path and Path(key_path).exists() and not raw_key:
            raw_key = Path(key_path).read_text(encoding="utf-8")

        return cls(
            github_app_id=app_id,
            github_private_key_path=key_path,
            github_private_key=raw_key,
            github_webhook_secret=os.getenv("GITHUB_WEBHOOK_SECRET", ""),
            dry_run=os.getenv("DIFFSHIELD_DRY_RUN", "0") in ("1", "true", "True"),
            db_path=os.getenv("DIFFSHIELD_DB_PATH", "diffshield.db"),
            default_hold_hours=int(os.getenv("DIFFSHIELD_HOLD_HOURS", "12")),
            host=os.getenv("DIFFSHIELD_HOST", "0.0.0.0"),
            port=int(os.getenv("PORT", os.getenv("DIFFSHIELD_PORT", "8000")))
        )


@dataclass
class RepoPolicy:
    """
    Per-repository policy parsed from base commit .diffshield.yml.
    Safe defaults applied on missing or broken configurations.
    """
    enforcement: str = "hold"  # 'hold', 'block', 'close', 'comment'
    hold_hours: int = 12
    ignore_paths: List[str] = field(default_factory=lambda: [
        "dist/**",
        "*/dist/**",
        "*.min.js",
        "*.min.css",
        "node_modules/**",
        "*/node_modules/**"
    ])

    @classmethod
    def from_yaml(cls, yaml_content: Optional[str]) -> RepoPolicy:
        """
        Parse policy with safe defaults.
        Broken or invalid YAML falls back safely to 'hold' with 12h.
        """
        if not yaml_content or not yaml_content.strip():
            return cls()

        try:
            data = yaml.safe_load(yaml_content)
            if not isinstance(data, dict):
                logger.warning("Invalid .diffshield.yml structure, falling back to safe defaults.")
                return cls()

            enforcement = str(data.get("enforcement", "hold")).lower()
            if enforcement not in ("hold", "block", "close", "comment"):
                enforcement = "hold"

            hold_hours = int(data.get("hold_hours", 12))
            ignore_paths = data.get("ignore_paths", [
                "dist/**", "*/dist/**", "*.min.js", "*.min.css", "node_modules/**"
            ])

            return cls(
                enforcement=enforcement,
                hold_hours=hold_hours,
                ignore_paths=ignore_paths
            )
        except Exception as err:
            logger.warning(f"Error parsing .diffshield.yml ({err}); using safe defaults.")
            return cls()

